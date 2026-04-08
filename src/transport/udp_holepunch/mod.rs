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
    ServiceAdvertisement, parse_service_advertisement, publish_service_advertisement,
    service_advertisement_filter,
};
use crate::nostr_relay::RelayClient;
use nostr::prelude::*;
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

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
        let mut latest = self.latest_by_pubkey.lock().unwrap();
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

fn advertisement_is_newer(new: &ServiceAdvertisement, existing: &ServiceAdvertisement) -> bool {
    let new_secs = new.created_at.as_secs();
    let existing_secs = existing.created_at.as_secs();
    if new_secs != existing_secs {
        return new_secs > existing_secs;
    }

    new.event_id.to_hex() < existing.event_id.to_hex()
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
        let relay_urls = self.config.relays.clone();
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
        }
    }

    fn spawn_discovery_workers(&mut self) {
        for relay_url in self.config.relays.clone() {
            let shared = self.shared.clone();
            let stats = self.stats.clone();
            let transport_id = self.transport_id;
            let task = tokio::spawn(async move {
                run_discovery_worker(transport_id, relay_url, shared, stats).await;
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

        let task = tokio::spawn(async move {
            run_responder_worker(transport_id, config, keys, hp_config, shared, packet_tx).await;
        });
        self.relay_tasks.push(task);
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
) {
    let client = match RelayClient::connect(&relay_url).await {
        Ok(client) => {
            stats.relays_connected.fetch_add(1, Ordering::Relaxed);
            info!(transport_id = %transport_id, relay = %relay_url, "udp_holepunch relay connected for discovery");
            client
        }
        Err(err) => {
            warn!(transport_id = %transport_id, relay = %relay_url, error = %err, "udp_holepunch relay connect failed");
            return;
        }
    };

    let filter = service_advertisement_filter();
    let mut sub = match client.subscribe(vec![filter]).await {
        Ok(sub) => sub,
        Err(err) => {
            warn!(transport_id = %transport_id, relay = %relay_url, error = %err, "udp_holepunch advertisement subscription failed");
            client.disconnect().await;
            return;
        }
    };

    if let Err(err) = sub.wait_for_eose().await {
        warn!(transport_id = %transport_id, relay = %relay_url, error = %err, "udp_holepunch advertisement subscription failed before EOSE");
        let _ = sub.close().await;
        client.disconnect().await;
        return;
    }

    debug!(transport_id = %transport_id, relay = %relay_url, "udp_holepunch discovery subscription live");

    while let Some(event) = sub.next().await {
        match parse_service_advertisement(&event) {
            Ok(advertisement) => {
                shared.record_advertisement(transport_id, advertisement, &stats);
            }
            Err(err) => {
                debug!(transport_id = %transport_id, relay = %relay_url, event_id = %event.id, error = %err, "ignoring non-advertisement event in udp_holepunch discovery worker");
            }
        }
    }

    warn!(transport_id = %transport_id, relay = %relay_url, "udp_holepunch discovery worker exited; reconnect loop not implemented yet");
    let _ = sub.close().await;
    client.disconnect().await;
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

    // Publish service advertisement so initiators can discover us.
    let stun_refs: Vec<&str> = config.stun_servers.iter().map(|s| s.as_str()).collect();
    if let Err(err) = publish_service_advertisement(&relay_refs, &keys, &stun_refs).await {
        error!(transport_id = %transport_id, error = %err, "udp_holepunch responder: failed to publish advertisement");
        for relay in relays {
            relay.disconnect().await;
        }
        return;
    }
    info!(transport_id = %transport_id, "udp_holepunch responder: advertisement published");

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

    // Accept loop -- handle offers one at a time.
    loop {
        let offer = match wait_for_first_offer(&mut subscriptions, None).await {
            Ok(offer) => offer,
            Err(err) => {
                warn!(transport_id = %transport_id, error = %err, "udp_holepunch responder: offer wait failed; exiting");
                break;
            }
        };

        info!(
            transport_id = %transport_id,
            sender = %offer.sender_pubkey,
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
    use crate::holepunch::signaling::publish_service_advertisement;
    use crate::nostr_relay::test_relay::TestRelay;
    use tokio::time::{Duration, sleep};

    #[test]
    fn latest_advertisement_wins_by_created_at() {
        let newer = ServiceAdvertisement {
            peer_pubkey: PublicKey::parse("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            stun_servers: vec!["stun.new:3478".to_string()],
            created_at: Timestamp::from(20),
            event_id: EventId::parse("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
        };
        let older = ServiceAdvertisement {
            peer_pubkey: newer.peer_pubkey,
            stun_servers: vec!["stun.old:3478".to_string()],
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

        publish_service_advertisement(&[&publisher], &keys, &["stun.example.com:3478"])
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
}
