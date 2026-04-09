//! Nostr-signaled UDP hole-punch transport.
//!
//! This transport integrates the Nostr/STUN/punch library code into the FIPS
//! transport system. It provides:
//!
//! - config and startup wiring
//! - background relay discovery workers
//! - latest-advertisement merge logic per responder pubkey
//! - synthetic `TransportAddr` handles for discovered advertisements
//! - per-peer connection objects that own their own UDP sockets
//! - outbound connect via STUN/signaling/punch on a fresh per-peer socket
//! - inbound responder path: publish advertisement, accept offers, punch
//! - per-peer receive loops that feed packets upstream via `packet_tx`

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportCongestion, TransportError, TransportId, TransportState, TransportType,
};
use crate::config::UdpHolePunchConfig;
use crate::holepunch::orchestrator::{
    HolePunchConfig, PunchedPath, accept_offer, initiate_from_advertisement,
    subscribe_signals_all, wait_for_first_offer,
};
use crate::holepunch::signaling::{
    SERVICE_AD_CLEANUP_REASON, ServiceAdvertisement, advertisement_is_newer,
    delete_service_advertisement, parse_service_advertisement,
    publish_service_advertisement_with_ttl, service_advertisement_filter,
};
use crate::nostr_relay::RelayClient;
use nostr::prelude::*;
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

const DISCOVERY_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);
const DISCOVERY_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const DISCOVERY_DELETION_REPLAY_SKEW_SECS: u64 = 60;
const TRANSPORT_SERVICE_AD_KIND: u16 = 30078;
const TRANSPORT_SERVICE_TAG: &str = "udp-service-v1/fips";

enum DiscoverySessionOutcome {
    ConnectedThenClosed,
    Failed(String),
}

/// Transport-local stats for the initial udp_holepunch integration.
#[derive(Debug, Default, Serialize)]
pub struct UdpHolePunchStatsSnapshot {
    pub relays_connected: u64,
    pub advertisements_seen: u64,
    pub advertisements_deduped: u64,
    pub advertisements_updated: u64,
}

#[derive(Debug, Default)]
struct UdpHolePunchStats {
    relays_connected: AtomicU64,
    advertisements_seen: AtomicU64,
    advertisements_deduped: AtomicU64,
    advertisements_updated: AtomicU64,
}

impl UdpHolePunchStats {
    fn snapshot(&self) -> UdpHolePunchStatsSnapshot {
        UdpHolePunchStatsSnapshot {
            relays_connected: self.relays_connected.load(Ordering::Relaxed),
            advertisements_seen: self.advertisements_seen.load(Ordering::Relaxed),
            advertisements_deduped: self.advertisements_deduped.load(Ordering::Relaxed),
            advertisements_updated: self.advertisements_updated.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct CachedAdvertisement {
    handle: TransportAddr,
    advertisement: ServiceAdvertisement,
}

struct SharedState {
    seen_event_ids: StdMutex<HashSet<String>>,
    latest_by_pubkey: StdMutex<HashMap<String, CachedAdvertisement>>,
    latest_deletion_by_pubkey: StdMutex<HashMap<String, Event>>,
    handles: StdMutex<HashMap<TransportAddr, ServiceAdvertisement>>,
    discoveries: StdMutex<Vec<DiscoveredPeer>>,
    connect_states: StdMutex<HashMap<TransportAddr, ConnectionState>>,
    connections: StdMutex<HashMap<TransportAddr, Arc<UdpHolePunchConnection>>>,
    next_handle: AtomicU64,
}

impl SharedState {
    fn new() -> Self {
        Self {
            seen_event_ids: StdMutex::new(HashSet::new()),
            latest_by_pubkey: StdMutex::new(HashMap::new()),
            latest_deletion_by_pubkey: StdMutex::new(HashMap::new()),
            handles: StdMutex::new(HashMap::new()),
            discoveries: StdMutex::new(Vec::new()),
            connect_states: StdMutex::new(HashMap::new()),
            connections: StdMutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn allocate_handle(&self, prefix: &str) -> TransportAddr {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        TransportAddr::from_string(&format!("{prefix}:{id:016x}"))
    }

    fn record_advertisement(
        &self,
        transport_id: TransportId,
        advertisement: ServiceAdvertisement,
        stats: &UdpHolePunchStats,
    ) {
        stats.advertisements_seen.fetch_add(1, Ordering::Relaxed);

        let event_id = advertisement.event_id.to_hex();
        {
            let mut seen = self.seen_event_ids.lock().unwrap();
            if !seen.insert(event_id.clone()) {
                stats.advertisements_deduped.fetch_add(1, Ordering::Relaxed);
                debug!(event_id = %event_id, "ignoring duplicate advertisement event");
                return;
            }
        }

        let pubkey = advertisement.peer_pubkey.to_hex();
        let latest_deletions = self.latest_deletion_by_pubkey.lock().unwrap();
        let deletion_is_newer = latest_deletions
            .get(&pubkey)
            .is_some_and(|deletion| !event_is_newer_than_event(&advertisement, deletion));
        if deletion_is_newer {
            debug!(
                peer_pubkey = %pubkey,
                event_id = %advertisement.event_id,
                "ignoring advertisement superseded by a newer deletion"
            );
            return;
        }

        let mut latest = self.latest_by_pubkey.lock().unwrap();
        if latest_deletions
            .get(&pubkey)
            .is_some_and(|deletion| !event_is_newer_than_event(&advertisement, deletion))
        {
            debug!(
                peer_pubkey = %pubkey,
                event_id = %advertisement.event_id,
                "ignoring advertisement superseded by a newer deletion"
            );
            return;
        }

        match latest.get_mut(&pubkey) {
            Some(existing) => {
                if advertisement_is_newer(&advertisement, &existing.advertisement) {
                    debug!(
                        peer_pubkey = %pubkey,
                        old_event = %existing.advertisement.event_id,
                        new_event = %advertisement.event_id,
                        "updating effective advertisement for peer"
                    );
                    let handle = existing.handle.clone();
                    existing.advertisement = advertisement.clone();
                    self.handles.lock().unwrap().insert(handle.clone(), advertisement.clone());
                    self.connect_states.lock().unwrap().entry(handle.clone()).or_insert(ConnectionState::None);
                    self.enqueue_discovery(transport_id, handle, advertisement.peer_pubkey);
                    stats.advertisements_updated.fetch_add(1, Ordering::Relaxed);
                } else {
                    debug!(peer_pubkey = %pubkey, event_id = %advertisement.event_id, "ignoring stale advertisement");
                }
            }
            None => {
                let handle = self.allocate_handle("ad");
                debug!(peer_pubkey = %pubkey, handle = %handle, event_id = %advertisement.event_id, "registered new responder advertisement");
                self.handles.lock().unwrap().insert(handle.clone(), advertisement.clone());
                self.connect_states.lock().unwrap().insert(handle.clone(), ConnectionState::None);
                latest.insert(
                    pubkey,
                    CachedAdvertisement {
                        handle: handle.clone(),
                        advertisement: advertisement.clone(),
                    },
                );
                self.enqueue_discovery(transport_id, handle, advertisement.peer_pubkey);
                stats.advertisements_updated.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn record_advertisement_deletion(&self, event: Event) {
        let event_id = event.id.to_hex();
        {
            let mut seen = self.seen_event_ids.lock().unwrap();
            if !seen.insert(event_id.clone()) {
                debug!(event_id = %event_id, "ignoring duplicate advertisement deletion event");
                return;
            }
        }

        let coordinates: Vec<_> = event
            .tags
            .coordinates()
            .filter(|coordinate| {
                coordinate.kind.as_u16() == TRANSPORT_SERVICE_AD_KIND
                    && coordinate.identifier == TRANSPORT_SERVICE_TAG
                    && coordinate.public_key == event.pubkey
            })
            .cloned()
            .collect();
        if coordinates.is_empty() {
            return;
        }

        for coordinate in coordinates {
            let pubkey = coordinate.public_key.to_hex();

            let mut latest_deletions = self.latest_deletion_by_pubkey.lock().unwrap();
            let should_replace = latest_deletions
                .get(&pubkey)
                .is_none_or(|existing| discovery_event_is_newer(&event, existing));
            if !should_replace {
                continue;
            }

            latest_deletions.insert(pubkey.clone(), event.clone());
            let mut latest = self.latest_by_pubkey.lock().unwrap();
            let evicted = match latest.get(&pubkey) {
                Some(cached) if !event_is_newer_than_event(&cached.advertisement, &event) => {
                    let cached = cached.clone();
                    latest.remove(&pubkey);
                    Some(cached)
                }
                _ => None,
            };
            drop(latest);
            drop(latest_deletions);

            if let Some(cached) = evicted {
                debug!(
                    peer_pubkey = %pubkey,
                    event_id = %event.id,
                    deleted_event = %cached.advertisement.event_id,
                    "evicting advertisement after newer deletion"
                );
                self.handles.lock().unwrap().remove(&cached.handle);
                self.discoveries.lock().unwrap().retain(|peer| peer.addr != cached.handle);

                let has_connection = self.connections.lock().unwrap().contains_key(&cached.handle);
                if !has_connection {
                    self.connect_states.lock().unwrap().remove(&cached.handle);
                }
            }
        }
    }

    fn enqueue_discovery(&self, transport_id: TransportId, handle: TransportAddr, pubkey: PublicKey) {
        let hint = XOnlyPublicKey::from_slice(pubkey.as_bytes()).ok();
        let mut discoveries = self.discoveries.lock().unwrap();
        discoveries.retain(|peer| peer.addr != handle);
        let peer = match hint {
            Some(pubkey_hint) => DiscoveredPeer::with_hint(transport_id, handle, pubkey_hint),
            None => DiscoveredPeer::new(transport_id, handle),
        };
        discoveries.push(peer);
    }

    fn take_discoveries(&self) -> Vec<DiscoveredPeer> {
        let mut discoveries = self.discoveries.lock().unwrap();
        std::mem::take(&mut *discoveries)
    }
}

/// One live per-peer hole-punched UDP connection.
struct UdpHolePunchConnection {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    recv_task: StdMutex<Option<JoinHandle<()>>>,
}

impl UdpHolePunchConnection {
    async fn stop(&self) {
        if let Some(task) = self.recv_task.lock().unwrap().take() {
            task.abort();
            let _ = task.await;
        }
    }
}

/// UDP hole-punch transport.
pub struct UdpHolePunchTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: UdpHolePunchConfig,
    state: TransportState,
    packet_tx: PacketTx,
    keys: Option<Keys>,
    relay_tasks: Vec<JoinHandle<()>>,
    responder_task: Option<JoinHandle<()>>,
    responder_shutdown: Option<oneshot::Sender<()>>,
    shared: Arc<SharedState>,
    stats: Arc<UdpHolePunchStats>,
}

impl UdpHolePunchTransport {
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: UdpHolePunchConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            packet_tx,
            keys: None,
            relay_tasks: Vec::new(),
            responder_task: None,
            responder_shutdown: None,
            shared: Arc::new(SharedState::new()),
            stats: Arc::new(UdpHolePunchStats::default()),
        }
    }

    /// Set the Nostr keys used for signaling and authentication.
    ///
    /// Must be called before `start_async()` for the connect and responder
    /// paths to work. Discovery-only operation does not require keys.
    pub fn set_keys(&mut self, keys: Keys) {
        self.keys = Some(keys);
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    pub fn stats(&self) -> UdpHolePunchStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn congestion(&self) -> TransportCongestion {
        TransportCongestion::default()
    }

    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;
        self.state = TransportState::Up;

        info!(
            transport_id = %self.transport_id,
            bind_ip = %self.config.bind_ip(),
            auto_connect = self.config.auto_connect(),
            accept_connections = self.config.accept_connections(),
            relays = self.config.relays.len(),
            stun_servers = self.config.stun_servers.len(),
            has_keys = self.keys.is_some(),
            "udp_holepunch transport started"
        );

        if self.config.accept_connections() {
            if self.keys.is_some() {
                self.spawn_responder_worker();
            } else {
                warn!(
                    transport_id = %self.transport_id,
                    "udp_holepunch accept_connections enabled but no keys set; responder will not start"
                );
            }
        }

        if self.config.auto_connect() {
            self.spawn_discovery_workers();
        }

        Ok(())
    }

    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if let Some(shutdown_tx) = self.responder_shutdown.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(task) = self.responder_task.take() {
            let _ = task.await;
        }

        for task in self.relay_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }

        let connections: Vec<_> = {
            let mut guard = self.shared.connections.lock().unwrap();
            guard.drain().map(|(_, connection)| connection).collect()
        };
        for connection in connections {
            connection.stop().await;
        }
        self.state = TransportState::Down;

        info!(transport_id = %self.transport_id, "udp_holepunch transport stopped");
        Ok(())
    }

    pub async fn send_async(&self, addr: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let connection = {
            let connections = self.shared.connections.lock().unwrap();
            connections
                .get(addr)
                .cloned()
                .ok_or_else(|| TransportError::InvalidAddress(format!("udp_holepunch address {} is not connected", addr)))?
        };

        let bytes = connection.socket.send_to(data, connection.remote_addr).await?;
        Ok(bytes)
    }

    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let keys = self.keys.clone().ok_or_else(|| {
            TransportError::NotSupported("udp_holepunch keys not configured".into())
        })?;

        let advertisement = {
            let handles = self.shared.handles.lock().unwrap();
            handles.get(addr).cloned().ok_or_else(|| {
                TransportError::InvalidAddress(format!(
                    "unknown udp_holepunch discovery handle: {}",
                    addr
                ))
            })?
        };

        // Already connecting or connected -- return immediately.
        {
            let states = self.shared.connect_states.lock().unwrap();
            match states.get(addr) {
                Some(ConnectionState::Connecting) | Some(ConnectionState::Connected) => {
                    return Ok(());
                }
                _ => {}
            }
        }
        {
            let connections = self.shared.connections.lock().unwrap();
            if connections.contains_key(addr) {
                return Ok(());
            }
        }

        // Mark as connecting before spawning the background task.
        self.shared
            .connect_states
            .lock()
            .unwrap()
            .insert(addr.clone(), ConnectionState::Connecting);

        let shared = self.shared.clone();
        let transport_id = self.transport_id;
        let addr = addr.clone();
        let bind_ip = self.config.bind_ip().to_string();
        let relay_urls = relay_urls_for_outbound(&self.config.relays, &advertisement.relays);
        let hp_config = self.hole_punch_config();
        let packet_tx = self.packet_tx.clone();

        tokio::spawn(async move {
            let result =
                run_outbound_punch(&bind_ip, &relay_urls, &keys, &advertisement, &hp_config).await;

            match result {
                Ok((socket, punched_path)) => {
                    let socket = Arc::new(socket);
                    let recv_task = tokio::spawn(udp_holepunch_receive_loop(
                        socket.clone(),
                        transport_id,
                        addr.clone(),
                        packet_tx,
                    ));
                    let connection = Arc::new(UdpHolePunchConnection {
                        socket,
                        remote_addr: punched_path.peer_addr,
                        recv_task: StdMutex::new(Some(recv_task)),
                    });
                    shared
                        .connections
                        .lock()
                        .unwrap()
                        .insert(addr.clone(), connection);
                    shared
                        .connect_states
                        .lock()
                        .unwrap()
                        .insert(addr, ConnectionState::Connected);
                    info!(
                        transport_id = %transport_id,
                        peer = %punched_path.peer_pubkey,
                        remote = %punched_path.peer_addr,
                        session = %punched_path.session_id,
                        "udp_holepunch outbound connection established"
                    );
                }
                Err(reason) => {
                    warn!(
                        transport_id = %transport_id,
                        error = %reason,
                        "udp_holepunch outbound punch failed"
                    );
                    shared
                        .connect_states
                        .lock()
                        .unwrap()
                        .insert(addr, ConnectionState::Failed(reason));
                }
            }
        });

        Ok(())
    }

    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        self.shared
            .connect_states
            .lock()
            .unwrap()
            .get(addr)
            .cloned()
            .unwrap_or(ConnectionState::None)
    }

    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        self.shared.connect_states.lock().unwrap().remove(addr);
        let connection = self.shared.connections.lock().unwrap().remove(addr);
        if let Some(connection) = connection {
            connection.stop().await;
        }
    }

    fn hole_punch_config(&self) -> HolePunchConfig {
        HolePunchConfig {
            signal_timeout: Duration::from_secs(self.config.timeout_secs()),
            stun_attempt_timeout: Duration::from_secs(2),
            probe_interval: Duration::from_millis(self.config.probe_ms()),
            punch_timeout: Duration::from_secs(self.config.timeout_secs()),
            ..HolePunchConfig::default()
        }
    }

    fn spawn_discovery_workers(&mut self) {
        let deletion_replay_window_secs = self
            .config
            .ad_expiration_secs()
            .saturating_add(DISCOVERY_DELETION_REPLAY_SKEW_SECS);
        for relay_url in self.config.relays.clone() {
            let shared = self.shared.clone();
            let stats = self.stats.clone();
            let transport_id = self.transport_id;
            let task = tokio::spawn(async move {
                run_discovery_worker(
                    transport_id,
                    relay_url,
                    shared,
                    stats,
                    deletion_replay_window_secs,
                )
                .await;
            });
            self.relay_tasks.push(task);
        }
    }

    fn spawn_responder_worker(&mut self) {
        let keys = match self.keys.clone() {
            Some(keys) => keys,
            None => return,
        };
        let shared = self.shared.clone();
        let transport_id = self.transport_id;
        let config = self.config.clone();
        let packet_tx = self.packet_tx.clone();
        let hp_config = self.hole_punch_config();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            run_responder_worker(transport_id, config, keys, hp_config, shared, packet_tx, shutdown_rx)
                .await;
        });
        self.responder_shutdown = Some(shutdown_tx);
        self.responder_task = Some(task);
    }
}

impl Transport for UdpHolePunchTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP_HOLEPUNCH
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        1280
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported("use start_async() for udp_holepunch transport".into()))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported("use stop_async() for udp_holepunch transport".into()))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported("use send_async() for udp_holepunch transport".into()))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(self.shared.take_discoveries())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}

// ---------------------------------------------------------------------------
// Background workers
// ---------------------------------------------------------------------------

async fn run_discovery_worker(
    transport_id: TransportId,
    relay_url: String,
    shared: Arc<SharedState>,
    stats: Arc<UdpHolePunchStats>,
    deletion_replay_window_secs: u64,
) {
    let mut reconnect_delay = DISCOVERY_RECONNECT_BASE_DELAY;

    loop {
        match run_discovery_session(
            transport_id,
            &relay_url,
            shared.clone(),
            stats.clone(),
            deletion_replay_window_secs,
        )
        .await
        {
            DiscoverySessionOutcome::ConnectedThenClosed => {
                reconnect_delay = next_discovery_reconnect_delay(reconnect_delay, true);
                warn!(
                    transport_id = %transport_id,
                    relay = %relay_url,
                    retry_in = ?reconnect_delay,
                    "udp_holepunch discovery subscription closed; reconnecting"
                );
                tokio::time::sleep(reconnect_delay).await;
            }
            DiscoverySessionOutcome::Failed(err) => {
                warn!(
                    transport_id = %transport_id,
                    relay = %relay_url,
                    error = %err,
                    retry_in = ?reconnect_delay,
                    "udp_holepunch discovery worker failed; reconnecting"
                );
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = next_discovery_reconnect_delay(reconnect_delay, false);
            }
        }
    }
}

async fn run_discovery_session(
    transport_id: TransportId,
    relay_url: &str,
    shared: Arc<SharedState>,
    stats: Arc<UdpHolePunchStats>,
    deletion_replay_window_secs: u64,
) -> DiscoverySessionOutcome {
    let client = match RelayClient::connect(&relay_url).await {
        Ok(client) => {
            stats.relays_connected.fetch_add(1, Ordering::Relaxed);
            info!(transport_id = %transport_id, relay = %relay_url, "udp_holepunch relay connected for discovery");
            client
        }
        Err(err) => {
            return DiscoverySessionOutcome::Failed(format!("relay connect failed: {err}"));
        }
    };

    let advertisement_filter = service_advertisement_filter();
    let deletion_since = Timestamp::from(
        Timestamp::now()
            .as_secs()
            .saturating_sub(deletion_replay_window_secs),
    );
    let deletion_filter = Filter::new()
        .kind(Kind::EventDeletion)
        .since(deletion_since);
    let mut sub = match client.subscribe(vec![advertisement_filter, deletion_filter]).await {
        Ok(sub) => sub,
        Err(err) => {
            client.disconnect().await;
            return DiscoverySessionOutcome::Failed(format!("advertisement subscription failed: {err}"));
        }
    };

    if let Err(err) = sub.wait_for_eose().await {
        let _ = sub.close().await;
        client.disconnect().await;
        return DiscoverySessionOutcome::Failed(format!("advertisement subscription failed before EOSE: {err}"));
    }

    debug!(transport_id = %transport_id, relay = %relay_url, "udp_holepunch discovery subscription live");

    while let Some(event) = sub.next().await {
        match event.kind.as_u16() {
            TRANSPORT_SERVICE_AD_KIND => {
                if event.is_expired() {
                    debug!(
                        transport_id = %transport_id,
                        relay = %relay_url,
                        event_id = %event.id,
                        "ignoring expired udp_holepunch advertisement"
                    );
                    continue;
                }

                match parse_service_advertisement(&event) {
                    Ok(advertisement) => {
                        shared.record_advertisement(transport_id, advertisement, &stats);
                    }
                    Err(err) => {
                        debug!(transport_id = %transport_id, relay = %relay_url, event_id = %event.id, error = %err, "ignoring non-advertisement event in udp_holepunch discovery worker");
                    }
                }
            }
            value if value == Kind::EventDeletion.as_u16() => {
                shared.record_advertisement_deletion(event);
            }
            _ => {
                debug!(transport_id = %transport_id, relay = %relay_url, event_id = %event.id, "ignoring unrelated event in udp_holepunch discovery worker");
            }
        }
    }

    let _ = sub.close().await;
    client.disconnect().await;
    DiscoverySessionOutcome::ConnectedThenClosed
}

fn event_is_newer_than_event(advertisement: &ServiceAdvertisement, event: &Event) -> bool {
    let advertisement_secs = advertisement.created_at.as_secs();
    let event_secs = event.created_at.as_secs();
    if advertisement_secs != event_secs {
        return advertisement_secs > event_secs;
    }

    advertisement.event_id.to_hex() < event.id.to_hex()
}

fn discovery_event_is_newer(new: &Event, existing: &Event) -> bool {
    let new_secs = new.created_at.as_secs();
    let existing_secs = existing.created_at.as_secs();
    if new_secs != existing_secs {
        return new_secs > existing_secs;
    }

    new.id.to_hex() < existing.id.to_hex()
}

fn next_discovery_reconnect_delay(current: Duration, reset: bool) -> Duration {
    if reset {
        DISCOVERY_RECONNECT_BASE_DELAY
    } else {
        current
            .saturating_mul(2)
            .min(DISCOVERY_RECONNECT_MAX_DELAY)
    }
}

// ---------------------------------------------------------------------------
// Relay URL selection for outbound punches
// ---------------------------------------------------------------------------

/// Choose relay URLs for an outbound punch.
///
/// Prefers the relays advertised by the responder (from the service
/// advertisement's `relays` tag). Falls back to the local config relays
/// only if the advertisement doesn't specify any.
fn relay_urls_for_outbound(config_relays: &[String], ad_relays: &[String]) -> Vec<String> {
    if !ad_relays.is_empty() {
        ad_relays.to_vec()
    } else {
        config_relays.to_vec()
    }
}

// ---------------------------------------------------------------------------
// Outbound punch (runs in a background task spawned by connect_async)
// ---------------------------------------------------------------------------

async fn run_outbound_punch(
    bind_ip: &str,
    relay_urls: &[String],
    keys: &Keys,
    advertisement: &ServiceAdvertisement,
    config: &HolePunchConfig,
) -> Result<(UdpSocket, PunchedPath), String> {
    let bind_addr = format!("{bind_ip}:0");
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .map_err(|e| format!("socket bind {bind_addr}: {e}"))?;

    let mut relays = Vec::new();
    for url in relay_urls {
        match RelayClient::connect(url).await {
            Ok(client) => relays.push(client),
            Err(err) => warn!(relay = %url, error = %err, "relay connect failed during outbound punch"),
        }
    }
    if relays.is_empty() {
        return Err("no relays connected for outbound punch".into());
    }

    let relay_refs: Vec<&RelayClient> = relays.iter().collect();
    let result = initiate_from_advertisement(&socket, &relay_refs, keys, advertisement, config)
        .await
        .map(|path| (socket, path))
        .map_err(|e| format!("punch failed: {e}"));

    for relay in relays {
        relay.disconnect().await;
    }

    result
}

// ---------------------------------------------------------------------------
// Per-peer receive loop
// ---------------------------------------------------------------------------

async fn udp_holepunch_receive_loop(
    socket: Arc<UdpSocket>,
    transport_id: TransportId,
    transport_addr: TransportAddr,
    packet_tx: PacketTx,
) {
    let mut buf = vec![0u8; 1380]; // 1280 MTU + headroom
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _remote_addr)) => {
                let data = buf[..len].to_vec();
                let packet = ReceivedPacket::new(transport_id, transport_addr.clone(), data);
                if packet_tx.send(packet).await.is_err() {
                    debug!(
                        transport_id = %transport_id,
                        addr = %transport_addr,
                        "udp_holepunch receive loop: packet channel closed"
                    );
                    break;
                }
            }
            Err(err) => {
                debug!(
                    transport_id = %transport_id,
                    addr = %transport_addr,
                    error = %err,
                    "udp_holepunch receive loop error"
                );
                break;
            }
        }
    }
}

#[derive(Default)]
struct RecentOfferDedup {
    event_ids: HashMap<String, Instant>,
    sessions: HashMap<(String, String), Instant>,
}

impl RecentOfferDedup {
    fn should_skip(&mut self, offer: &crate::holepunch::signaling::IncomingOffer, ttl: Duration) -> bool {
        let now = Instant::now();
        self.prune(now, ttl);

        let event_id = offer.event_id.to_hex();
        if self.event_ids.contains_key(&event_id) {
            return true;
        }

        let session_key = (offer.sender_pubkey.to_hex(), offer.offer.session_id.clone());
        if self.sessions.contains_key(&session_key) {
            return true;
        }

        self.event_ids.insert(event_id, now);
        self.sessions.insert(session_key, now);
        false
    }

    fn prune(&mut self, now: Instant, ttl: Duration) {
        self.event_ids.retain(|_, seen_at| now.duration_since(*seen_at) <= ttl);
        self.sessions.retain(|_, seen_at| now.duration_since(*seen_at) <= ttl);
    }
}

// ---------------------------------------------------------------------------
// Inbound responder worker
// ---------------------------------------------------------------------------

async fn run_responder_worker(
    transport_id: TransportId,
    config: UdpHolePunchConfig,
    keys: Keys,
    hp_config: HolePunchConfig,
    shared: Arc<SharedState>,
    packet_tx: PacketTx,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    // Connect to relays.
    let mut relays = Vec::new();
    for url in &config.relays {
        match RelayClient::connect(url).await {
            Ok(client) => {
                info!(transport_id = %transport_id, relay = %url, "udp_holepunch responder relay connected");
                relays.push(client);
            }
            Err(err) => {
                warn!(transport_id = %transport_id, relay = %url, error = %err, "udp_holepunch responder relay connect failed");
            }
        }
    }
    if relays.is_empty() {
        error!(transport_id = %transport_id, "udp_holepunch responder: no relays connected; cannot accept offers");
        return;
    }

    let relay_refs: Vec<&RelayClient> = relays.iter().collect();

    // Subscribe for incoming signals (offers).
    let mut subscriptions = match subscribe_signals_all(&relay_refs, keys.public_key()).await {
        Ok(subs) => subs,
        Err(err) => {
            error!(transport_id = %transport_id, error = %err, "udp_holepunch responder: failed to subscribe for signals");
            for relay in relays {
                relay.disconnect().await;
            }
            return;
        }
    };
    info!(
        transport_id = %transport_id,
        subs = subscriptions.len(),
        "udp_holepunch responder: listening for offers"
    );
    let mut recent_offers = RecentOfferDedup::default();
    let offer_dedup_ttl = hp_config.signal_timeout + hp_config.punch_timeout;
    let ad_ttl = Duration::from_secs(config.ad_expiration_secs());
    let refresh_interval = Duration::from_secs((config.ad_expiration_secs() / 2).max(1));
    let mut next_refresh = Instant::now();
    let refresh_poll_cap = Duration::from_secs(1);
    let stun_refs: Vec<&str> = config.stun_servers.iter().map(|s| s.as_str()).collect();
    let relay_url_refs: Vec<&str> = config.relays.iter().map(|s| s.as_str()).collect();
    let mut advertisement_live = false;

    // Accept loop -- handle offers one at a time.
    loop {
        if Instant::now() >= next_refresh {
            match publish_service_advertisement_with_ttl(
                &relay_refs,
                &keys,
                &stun_refs,
                &relay_url_refs,
                ad_ttl,
            )
            .await
            {
                Ok(_) => {
                    advertisement_live = true;
                    next_refresh = Instant::now() + refresh_interval;
                    info!(transport_id = %transport_id, expires_in_secs = ad_ttl.as_secs(), "udp_holepunch responder: advertisement published");
                }
                Err(err) => {
                    warn!(transport_id = %transport_id, error = %err, "udp_holepunch responder: failed to refresh advertisement");
                    next_refresh = Instant::now() + refresh_interval;
                }
            }
        }

        let wait_timeout = refresh_poll_cap.min(next_refresh.saturating_duration_since(Instant::now()));
        let offer = tokio::select! {
            _ = &mut shutdown_rx => break,
            result = wait_for_first_offer(&mut subscriptions, &keys, Some(wait_timeout)) => {
                match result {
                    Ok(offer) => offer,
                    Err(crate::holepunch::HolePunchError::Timeout(_)) => continue,
                    Err(err) => {
                        warn!(transport_id = %transport_id, error = %err, "udp_holepunch responder: offer wait failed; exiting");
                        break;
                    }
                }
            }
        };

        let offer = offer;

        if recent_offers.should_skip(&offer, offer_dedup_ttl) {
            debug!(
                transport_id = %transport_id,
                sender = %offer.sender_pubkey,
                session_id = %offer.offer.session_id,
                event_id = %offer.event_id,
                "udp_holepunch responder: ignoring duplicate offer"
            );
            continue;
        }

        info!(
            transport_id = %transport_id,
            sender = %offer.sender_pubkey,
            event_id = %offer.event_id,
            session_id = %offer.offer.session_id,
            "udp_holepunch responder: received offer, starting punch"
        );

        let bind_addr = format!("{}:0", config.bind_ip());
        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => s,
            Err(err) => {
                warn!(transport_id = %transport_id, error = %err, "udp_holepunch responder: socket bind failed");
                continue;
            }
        };

        let result = accept_offer(
            &socket,
            &relay_refs,
            &keys,
            &offer,
            &config.stun_servers,
            &hp_config,
        )
        .await;

        match result {
            Ok(punched_path) => {
                let handle = shared.allocate_handle("hp");

                info!(
                    transport_id = %transport_id,
                    handle = %handle,
                    peer = %punched_path.peer_pubkey,
                    remote = %punched_path.peer_addr,
                    session = %punched_path.session_id,
                    "udp_holepunch responder: inbound connection established"
                );

                let socket = Arc::new(socket);
                let recv_task = tokio::spawn(udp_holepunch_receive_loop(
                    socket.clone(),
                    transport_id,
                    handle.clone(),
                    packet_tx.clone(),
                ));
                let connection = Arc::new(UdpHolePunchConnection {
                    socket,
                    remote_addr: punched_path.peer_addr,
                    recv_task: StdMutex::new(Some(recv_task)),
                });
                shared
                    .connections
                    .lock()
                    .unwrap()
                    .insert(handle.clone(), connection);
                shared
                    .connect_states
                    .lock()
                    .unwrap()
                    .insert(handle, ConnectionState::Connected);
            }
            Err(err) => {
                warn!(
                    transport_id = %transport_id,
                    sender = %offer.sender_pubkey,
                    error = %err,
                    "udp_holepunch responder: punch failed"
                );
            }
        }
    }

    for sub in subscriptions {
        let _ = sub.close().await;
    }
    if advertisement_live {
        match delete_service_advertisement(&relay_refs, &keys, SERVICE_AD_CLEANUP_REASON).await {
            Ok(_) => {
                info!(transport_id = %transport_id, "udp_holepunch responder: advertisement deleted");
            }
            Err(err) => {
                warn!(transport_id = %transport_id, error = %err, "udp_holepunch responder: failed to delete advertisement");
            }
        }
    }
    for relay in relays {
        relay.disconnect().await;
    }
    warn!(transport_id = %transport_id, "udp_holepunch responder worker exited");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holepunch::signaling::{
        SERVICE_AD_CLEANUP_REASON, publish_service_advertisement, service_advertisement_coordinate,
    };
    use crate::nostr_relay::init_test_logging;
    use crate::nostr_relay::test_relay::TestRelay;
    use crate::stun::StunServer;
    use tokio::time::{Duration, sleep, timeout};

    async fn publish_test_service_advertisement(
        client: &RelayClient,
        keys: &Keys,
        created_at: Timestamp,
        expiration: Option<Timestamp>,
    ) -> Event {
        let event = EventBuilder::new(Kind::Custom(30078), "")
            .tag(Tag::identifier("udp-service-v1/fips"))
            .tag(Tag::custom(
                TagKind::custom("stun"),
                ["stun.example.com:3478"],
            ))
            .custom_created_at(created_at);
        let event = match expiration {
            Some(expiration) => event.tag(Tag::expiration(expiration)),
            None => event,
        }
        .sign_with_keys(keys)
        .unwrap();
        client.publish(event.clone()).await.unwrap();
        event
    }

    async fn publish_expired_service_advertisement(client: &RelayClient, keys: &Keys) {
        let now = Timestamp::now();
        let _ = publish_test_service_advertisement(
            client,
            keys,
            now,
            Some(Timestamp::from(now.as_secs().saturating_sub(1))),
        )
        .await;
    }

    async fn publish_test_service_advertisement_deletion(
        client: &RelayClient,
        keys: &Keys,
        created_at: Timestamp,
    ) -> Event {
        publish_test_service_advertisement_deletion_for_pubkey(
            client,
            keys,
            keys.public_key(),
            created_at,
        )
        .await
    }

    async fn publish_test_service_advertisement_deletion_for_pubkey(
        client: &RelayClient,
        signer_keys: &Keys,
        advertised_pubkey: PublicKey,
        created_at: Timestamp,
    ) -> Event {
        let event = EventBuilder::delete(
            EventDeletionRequest::new()
                .coordinate(service_advertisement_coordinate(advertised_pubkey))
                .reason(SERVICE_AD_CLEANUP_REASON),
        )
        .custom_created_at(created_at)
        .sign_with_keys(signer_keys)
        .unwrap();
        client.publish(event.clone()).await.unwrap();
        event
    }

    #[test]
    fn latest_advertisement_wins_by_created_at() {
        let newer = ServiceAdvertisement {
            peer_pubkey: PublicKey::parse("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            stun_servers: vec!["stun.new:3478".to_string()],
            relays: vec![],
            created_at: Timestamp::from(20),
            event_id: EventId::parse("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
        };
        let older = ServiceAdvertisement {
            peer_pubkey: newer.peer_pubkey,
            stun_servers: vec!["stun.old:3478".to_string()],
            relays: vec![],
            created_at: Timestamp::from(10),
            event_id: EventId::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
        };

        assert!(advertisement_is_newer(&newer, &older));
        assert!(!advertisement_is_newer(&older, &newer));
    }

    #[tokio::test]
    async fn discover_drains_latest_advertisement() {
        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(42), None, config, packet_tx);
        transport.start_async().await.unwrap();

        publish_service_advertisement(&[&publisher], &keys, &["stun.example.com:3478"], &[], None)
            .await
            .unwrap();

        sleep(Duration::from_millis(200)).await;

        let discovered = transport.discover().unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].transport_id, TransportId::new(42));
        assert_eq!(discovered[0].pubkey_hint, XOnlyPublicKey::from_slice(keys.public_key().as_bytes()).ok());

        let discovered_again = transport.discover().unwrap();
        assert!(discovered_again.is_empty());

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discover_ignores_expired_advertisement() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        publish_expired_service_advertisement(&publisher, &keys).await;

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(43), None, config, packet_tx);
        transport.start_async().await.unwrap();

        sleep(Duration::from_millis(200)).await;

        let discovered = transport.discover().unwrap();
        assert!(discovered.is_empty(), "expired advertisement should be ignored");

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discovery_worker_reconnects_after_relay_connection_drop() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let relay_url = relay.url().to_string();
        let responder_keys = Keys::generate();
        let initial_publisher = RelayClient::connect(&relay_url).await.unwrap();

        let config = UdpHolePunchConfig {
            relays: vec![relay_url.clone()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(44), None, config, packet_tx);
        transport.start_async().await.unwrap();

        let initial_event = publish_test_service_advertisement(
            &initial_publisher,
            &responder_keys,
            Timestamp::from(10),
            None,
        )
        .await;

        let discovered_handle = timeout(Duration::from_secs(5), async {
            loop {
                let discovered = transport.discover().unwrap();
                if let Some(peer) = discovered.into_iter().next() {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for initial discovery");

        let cached_initial_event_id = {
            let handles = transport.shared.handles.lock().unwrap();
            handles
                .get(&discovered_handle)
                .expect("missing cached advertisement")
                .event_id
        };
        assert_eq!(cached_initial_event_id, initial_event.id);

        relay.drop_connections().await;
        initial_publisher.disconnect().await;

        let publisher_after_drop = RelayClient::connect(&relay_url).await.unwrap();
        let newer_event = publish_test_service_advertisement(
            &publisher_after_drop,
            &responder_keys,
            Timestamp::from(20),
            None,
        )
        .await;

        timeout(Duration::from_secs(5), async {
            loop {
                if transport.stats().relays_connected >= 2 {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for relay reconnect");

        let rediscovered_handle = timeout(Duration::from_secs(5), async {
            loop {
                let discovered = transport.discover().unwrap();
                if let Some(peer) = discovered.into_iter().find(|peer| peer.addr == discovered_handle) {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for refreshed discovery");
        assert_eq!(rediscovered_handle, discovered_handle);

        let cached_new_event_id = {
            let handles = transport.shared.handles.lock().unwrap();
            handles
                .get(&discovered_handle)
                .expect("missing refreshed advertisement")
                .event_id
        };
        assert_eq!(cached_new_event_id, newer_event.id);
        assert_ne!(cached_new_event_id, cached_initial_event_id);

        publisher_after_drop.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discover_replay_ignores_advertisement_deleted_before_startup() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();
        let now = Timestamp::now();

        publish_test_service_advertisement(&publisher, &keys, now, None).await;
        publish_test_service_advertisement_deletion(
            &publisher,
            &keys,
            Timestamp::from(now.as_secs().saturating_add(1)),
        )
        .await;

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(45), None, config, packet_tx);
        transport.start_async().await.unwrap();

        sleep(Duration::from_millis(200)).await;

        assert!(transport.discover().unwrap().is_empty());
        assert!(transport.shared.latest_by_pubkey.lock().unwrap().is_empty());
        assert!(transport.shared.handles.lock().unwrap().is_empty());

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discover_evicts_cached_advertisement_after_newer_deletion() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();
        let now = Timestamp::now();

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(46), None, config, packet_tx);
        transport.start_async().await.unwrap();

        publish_test_service_advertisement(&publisher, &keys, now, None).await;

        let handle = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(peer) = transport.discover().unwrap().into_iter().next() {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for discovery");

        publish_test_service_advertisement_deletion(
            &publisher,
            &keys,
            Timestamp::from(now.as_secs().saturating_add(1)),
        )
        .await;

        timeout(Duration::from_secs(5), async {
            loop {
                if !transport.shared.handles.lock().unwrap().contains_key(&handle) {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for advertisement eviction");

        assert!(transport.discover().unwrap().is_empty());
        assert!(transport.shared.latest_by_pubkey.lock().unwrap().is_empty());

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discover_ignores_deletion_from_wrong_pubkey() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let responder_keys = Keys::generate();
        let attacker_keys = Keys::generate();
        let now = Timestamp::now();

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(48), None, config, packet_tx);
        transport.start_async().await.unwrap();

        let initial_event =
            publish_test_service_advertisement(&publisher, &responder_keys, now, None).await;
        let handle = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(peer) = transport.discover().unwrap().into_iter().next() {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for initial discovery");

        publish_test_service_advertisement_deletion_for_pubkey(
            &publisher,
            &attacker_keys,
            responder_keys.public_key(),
            Timestamp::from(now.as_secs().saturating_add(1)),
        )
        .await;

        sleep(Duration::from_millis(200)).await;

        let cached = transport
            .shared
            .handles
            .lock()
            .unwrap()
            .get(&handle)
            .cloned()
            .expect("advertisement should not be evicted by foreign deletion");
        assert_eq!(cached.event_id, initial_event.id);

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn discover_accepts_newer_advertisement_after_deletion() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let publisher = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();
        let now = Timestamp::now();

        let config = UdpHolePunchConfig {
            relays: vec![relay.url().to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            auto_connect: Some(true),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(47), None, config, packet_tx);
        transport.start_async().await.unwrap();

        let initial_event = publish_test_service_advertisement(&publisher, &keys, now, None).await;
        let initial_handle = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(peer) = transport.discover().unwrap().into_iter().next() {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for initial discovery");

        publish_test_service_advertisement_deletion(
            &publisher,
            &keys,
            Timestamp::from(now.as_secs().saturating_add(1)),
        )
        .await;
        timeout(Duration::from_secs(5), async {
            loop {
                if !transport.shared.handles.lock().unwrap().contains_key(&initial_handle) {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for deletion eviction");

        let refreshed_event = publish_test_service_advertisement(
            &publisher,
            &keys,
            Timestamp::from(now.as_secs().saturating_add(2)),
            None,
        )
        .await;

        let refreshed_handle = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(peer) = transport.discover().unwrap().into_iter().next() {
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for refreshed discovery");

        assert_ne!(refreshed_handle, initial_handle);

        let refreshed_ad = transport
            .shared
            .handles
            .lock()
            .unwrap()
            .get(&refreshed_handle)
            .cloned()
            .expect("missing refreshed advertisement");
        assert_eq!(refreshed_ad.event_id, refreshed_event.id);
        assert_ne!(refreshed_ad.event_id, initial_event.id);

        publisher.disconnect().await;
        relay.shutdown().await;
        transport.stop_async().await.unwrap();
    }

    #[test]
    fn discovery_reconnect_delay_resets_after_healthy_session() {
        let capped = next_discovery_reconnect_delay(Duration::from_secs(16), false);
        assert_eq!(capped, DISCOVERY_RECONNECT_MAX_DELAY);

        let reset = next_discovery_reconnect_delay(capped, true);
        assert_eq!(reset, DISCOVERY_RECONNECT_BASE_DELAY);
    }

    #[tokio::test]
    async fn connect_async_requires_keys() {
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let config = UdpHolePunchConfig {
            relays: vec!["ws://localhost:1".to_string()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            ..Default::default()
        };
        let mut transport = UdpHolePunchTransport::new(TransportId::new(1), None, config, packet_tx);
        transport.start_async().await.unwrap();

        // Manually insert a fake handle so the address is known.
        let handle = transport.shared.allocate_handle("ad");
        let fake_ad = ServiceAdvertisement {
            peer_pubkey: PublicKey::parse("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            stun_servers: vec!["stun.example.com:3478".to_string()],
            relays: vec![],
            created_at: Timestamp::now(),
            event_id: EventId::parse("0000000000000000000000000000000000000000000000000000000000000099").unwrap(),
        };
        transport.shared.handles.lock().unwrap().insert(handle.clone(), fake_ad);

        let err = transport.connect_async(&handle).await.unwrap_err();
        assert!(
            err.to_string().contains("keys not configured"),
            "expected keys error, got: {}",
            err
        );

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn connect_async_rejects_unknown_handle() {
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let config = UdpHolePunchConfig::default();
        let mut transport = UdpHolePunchTransport::new(TransportId::new(1), None, config, packet_tx);
        transport.set_keys(Keys::generate());
        transport.start_async().await.unwrap();

        let bogus = TransportAddr::from_string("ad:bogus");
        let err = transport.connect_async(&bogus).await.unwrap_err();
        assert!(
            err.to_string().contains("unknown"),
            "expected unknown handle error, got: {}",
            err
        );

        transport.stop_async().await.unwrap();
    }

    #[tokio::test]
    async fn stop_async_deletes_responder_advertisement() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let relay_url = relay.url().to_string();
        let responder_keys = Keys::generate();
        let config = UdpHolePunchConfig {
            bind_ip: Some("127.0.0.1".to_string()),
            relays: vec![relay_url.clone()],
            stun_servers: vec!["stun.example.com:3478".to_string()],
            accept_connections: Some(true),
            auto_connect: Some(false),
            ad_expiration_secs: Some(60),
            ..Default::default()
        };

        let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
        let mut transport = UdpHolePunchTransport::new(TransportId::new(7), None, config, packet_tx);
        transport.set_keys(responder_keys.clone());
        transport.start_async().await.unwrap();

        sleep(Duration::from_millis(300)).await;
        transport.stop_async().await.unwrap();

        let observer = RelayClient::connect(&relay_url).await.unwrap();
        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .author(responder_keys.public_key());
        let mut sub = observer.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        let deletion = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out waiting for advertisement deletion")
            .expect("deletion subscription closed");
        assert_eq!(deletion.content, SERVICE_AD_CLEANUP_REASON);
        assert_eq!(deletion.tags.iter().filter(|tag| tag.kind() == TagKind::a()).count(), 1);

        let coordinate = deletion
            .tags
            .coordinates()
            .next()
            .expect("missing advertisement coordinate");
        assert_eq!(coordinate.kind, Kind::Custom(30078));
        assert_eq!(coordinate.public_key, responder_keys.public_key());
        assert_eq!(coordinate.identifier, "udp-service-v1/fips");

        sub.close().await.unwrap();
        observer.disconnect().await;
        relay.shutdown().await;
    }

    #[test]
    fn recent_offer_dedup_filters_duplicate_event_and_session() {
        let mut dedup = RecentOfferDedup::default();
        let ttl = Duration::from_secs(30);
        let sender = PublicKey::parse(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let reply_pubkey = PublicKey::parse(
            "0000000000000000000000000000000000000000000000000000000000000004",
        )
        .unwrap();

        let offer = crate::holepunch::signaling::IncomingOffer {
            sender_pubkey: sender,
            event_id: EventId::parse(
                "0000000000000000000000000000000000000000000000000000000000000101",
            )
            .unwrap(),
            offer: crate::holepunch::signaling::Offer {
                session_id: "session-1".into(),
                reflexive_addr: "1.2.3.4:1111".parse().unwrap(),
                local_addr: "10.0.0.2:1111".parse().unwrap(),
                stun_server: "stun.example.com:3478".into(),
                reply_pubkey,
                timestamp: 1,
            },
        };
        assert!(!dedup.should_skip(&offer, ttl));
        assert!(dedup.should_skip(&offer, ttl));

        let same_session_new_event = crate::holepunch::signaling::IncomingOffer {
            event_id: EventId::parse(
                "0000000000000000000000000000000000000000000000000000000000000102",
            )
            .unwrap(),
            ..offer.clone()
        };
        assert!(dedup.should_skip(&same_session_new_event, ttl));

        let different_session = crate::holepunch::signaling::IncomingOffer {
            event_id: EventId::parse(
                "0000000000000000000000000000000000000000000000000000000000000103",
            )
            .unwrap(),
            offer: crate::holepunch::signaling::Offer {
                session_id: "session-2".into(),
                ..offer.offer.clone()
            },
            ..offer
        };
        assert!(!dedup.should_skip(&different_session, ttl));
    }

    #[test]
    fn relay_urls_for_outbound_prefers_advertisement() {
        let config = vec!["ws://config-relay:1".to_string()];
        let ad = vec![
            "ws://ad-relay:1".to_string(),
            "ws://ad-relay:2".to_string(),
        ];
        assert_eq!(relay_urls_for_outbound(&config, &ad), ad);
    }

    #[test]
    fn relay_urls_for_outbound_falls_back_to_config() {
        let config = vec!["ws://config-relay:1".to_string()];
        let ad: Vec<String> = vec![];
        assert_eq!(relay_urls_for_outbound(&config, &ad), config);
    }

    /// End-to-end transport integration test.
    ///
    /// Two `UdpHolePunchTransport` instances (initiator + responder) on
    /// localhost with a local STUN server and in-process Nostr relay.
    /// Verifies: advertisement discovery → connect → bidirectional data.
    #[tokio::test]
    async fn transport_connect_and_send() {
        init_test_logging();

        // --- Infrastructure ---
        let stun_server = StunServer::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_server.local_addr().to_string();
        let relay = TestRelay::start().await;
        let relay_url = relay.url().to_string();

        let responder_keys = Keys::generate();
        let initiator_keys = Keys::generate();

        // --- Responder transport ---
        // accept_connections=true so it publishes an advertisement and
        // listens for offers. auto_connect=false since it doesn't initiate.
        let responder_config = UdpHolePunchConfig {
            bind_ip: Some("127.0.0.1".to_string()),
            relays: vec![relay_url.clone()],
            stun_servers: vec![stun_addr.clone()],
            accept_connections: Some(true),
            auto_connect: Some(false),
            timeout_secs: Some(5),
            probe_ms: Some(50),
            ad_expiration_secs: None,
        };
        let (responder_packet_tx, mut responder_packet_rx) =
            crate::transport::packet_channel(64);
        let mut responder = UdpHolePunchTransport::new(
            TransportId::new(1),
            None,
            responder_config,
            responder_packet_tx,
        );
        responder.set_keys(responder_keys.clone());
        responder.start_async().await.unwrap();

        // Give the responder worker time to connect to the relay and
        // publish its advertisement before the initiator subscribes.
        sleep(Duration::from_millis(300)).await;

        // --- Initiator transport ---
        // auto_connect=true so it runs a discovery worker that will pick
        // up the responder's advertisement. accept_connections=false.
        let initiator_config = UdpHolePunchConfig {
            bind_ip: Some("127.0.0.1".to_string()),
            relays: vec![relay_url.clone()],
            stun_servers: vec![stun_addr.clone()],
            auto_connect: Some(true),
            accept_connections: Some(false),
            timeout_secs: Some(5),
            probe_ms: Some(50),
            ad_expiration_secs: None,
        };
        let (initiator_packet_tx, mut initiator_packet_rx) =
            crate::transport::packet_channel(64);
        let mut initiator = UdpHolePunchTransport::new(
            TransportId::new(2),
            None,
            initiator_config,
            initiator_packet_tx,
        );
        initiator.set_keys(initiator_keys.clone());
        initiator.start_async().await.unwrap();

        // --- Wait for the initiator to discover the responder ---
        let discovered_handle = timeout(Duration::from_secs(5), async {
            loop {
                let discovered = initiator.discover().unwrap();
                if let Some(peer) = discovered.into_iter().next() {
                    assert_eq!(
                        peer.pubkey_hint,
                        XOnlyPublicKey::from_slice(
                            responder_keys.public_key().as_bytes()
                        )
                        .ok()
                    );
                    break peer.addr;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for initiator to discover responder");

        // --- Initiator connects (STUN + signaling + punch) ---
        initiator.connect_async(&discovered_handle).await.unwrap();

        timeout(Duration::from_secs(10), async {
            loop {
                match initiator.connection_state_sync(&discovered_handle) {
                    ConnectionState::Connected => break,
                    ConnectionState::Failed(reason) => {
                        panic!("initiator connect failed: {reason}");
                    }
                    _ => sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .expect("timed out waiting for initiator connection");

        // --- Send data: initiator → responder ---
        let payload_a = b"hello from initiator";
        initiator
            .send_async(&discovered_handle, payload_a)
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(2), responder_packet_rx.recv())
            .await
            .expect("timed out waiting for responder to receive packet")
            .expect("responder packet channel closed");
        assert_eq!(received.data, payload_a);
        assert_eq!(received.transport_id, TransportId::new(1));

        // --- Send data: responder → initiator ---
        // Find the responder's inbound connection handle (hp:...).
        let responder_handle = {
            let connections = responder.shared.connections.lock().unwrap();
            assert_eq!(
                connections.len(),
                1,
                "responder should have exactly one inbound connection"
            );
            connections.keys().next().unwrap().clone()
        };

        let payload_b = b"hello from responder";
        responder
            .send_async(&responder_handle, payload_b)
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(2), initiator_packet_rx.recv())
            .await
            .expect("timed out waiting for initiator to receive packet")
            .expect("initiator packet channel closed");
        assert_eq!(received.data, payload_b);
        assert_eq!(received.transport_id, TransportId::new(2));

        // --- Cleanup ---
        initiator.stop_async().await.unwrap();
        responder.stop_async().await.unwrap();
        relay.shutdown().await;
        stun_server.shutdown().await;
    }
}
