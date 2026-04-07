//! Nostr-signaled UDP hole-punch transport.
//!
//! This transport is the beginning of the FIPS integration for the existing
//! Nostr/STUN/punch library code. In this first slice it provides:
//!
//! - config and startup wiring
//! - a bound UDP socket owned by the transport
//! - background relay discovery workers
//! - latest-advertisement merge logic per responder pubkey
//! - synthetic `TransportAddr` handles for discovered advertisements
//!
//! The actual connect/bootstrap path and inbound responder path are still to be
//! integrated. For now those codepaths log clearly and return `NotSupported`.

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, Transport, TransportAddr, TransportCongestion,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::UdpHolePunchConfig;
use crate::holepunch::signaling::{ServiceAdvertisement, parse_service_advertisement, service_advertisement_filter};
use crate::nostr_relay::RelayClient;
use nostr::prelude::*;
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

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
    punched_addrs: StdMutex<HashMap<TransportAddr, SocketAddr>>,
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
            punched_addrs: StdMutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn allocate_handle(&self) -> TransportAddr {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        TransportAddr::from_string(&format!("ad:{id:016x}"))
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
                let handle = self.allocate_handle();
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
    socket: Option<Arc<UdpSocket>>,
    _packet_tx: PacketTx,
    relay_tasks: Vec<JoinHandle<()>>,
    local_addr: Option<SocketAddr>,
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
            socket: None,
            _packet_tx: packet_tx,
            relay_tasks: Vec::new(),
            local_addr: None,
            shared: Arc::new(SharedState::new()),
            stats: Arc::new(UdpHolePunchStats::default()),
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
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

        let socket = UdpSocket::bind(self.config.bind_addr()).await?;
        self.local_addr = Some(socket.local_addr()?);
        self.socket = Some(Arc::new(socket));
        self.state = TransportState::Up;

        info!(
            transport_id = %self.transport_id,
            local_addr = %self.local_addr.expect("local addr set after bind"),
            auto_connect = self.config.auto_connect(),
            accept_connections = self.config.accept_connections(),
            relays = self.config.relays.len(),
            stun_servers = self.config.stun_servers.len(),
            "udp_holepunch transport started"
        );

        if self.config.accept_connections() {
            warn!(
                transport_id = %self.transport_id,
                "udp_holepunch inbound responder path is not integrated yet; advertisements will not be published"
            );
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

        self.socket.take();
        self.local_addr = None;
        self.state = TransportState::Down;

        info!(transport_id = %self.transport_id, "udp_holepunch transport stopped");
        Ok(())
    }

    pub async fn send_async(&self, addr: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let socket = self.socket.as_ref().ok_or(TransportError::NotStarted)?;
        let remote_addr = {
            let punched = self.shared.punched_addrs.lock().unwrap();
            punched
                .get(addr)
                .copied()
                .ok_or_else(|| TransportError::InvalidAddress(format!("udp_holepunch address {} is not connected", addr)))?
        };

        let bytes = socket.send_to(data, remote_addr).await?;
        Ok(bytes)
    }

    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let known = self.shared.handles.lock().unwrap().contains_key(addr);
        if !known {
            return Err(TransportError::InvalidAddress(format!("unknown udp_holepunch discovery handle: {}", addr)));
        }

        warn!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            "udp_holepunch connect path is not integrated yet"
        );
        Err(TransportError::NotSupported(
            "udp_holepunch connect path not yet integrated".into(),
        ))
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
        self.shared.punched_addrs.lock().unwrap().remove(addr);
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
}
