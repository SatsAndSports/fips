//! Nostr Transport Implementation
//!
//! Provides transport for FIPS peer communication via ephemeral Nostr
//! events relayed through WebSocket relays. Packets are Base64-encoded
//! in event content, addressed using `["p", "<hex_pubkey>"]` tags.
//!
//! Architecture: Each relay connection is managed by its own async task.
//! Outbound messages are distributed via a `broadcast` channel — `send_async`
//! publishes to the channel and each relay task forwards to its own WebSocket.
//! This avoids shared mutable state for write halves entirely.

pub mod event;

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::NostrConfig;
use event::{build_close, build_event, build_publish, build_subscription, RelayMessage};
use futures::{SinkExt, StreamExt};
use secp256k1::Keypair;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, trace, warn};

// ============================================================================
// Stats
// ============================================================================

/// Atomic counters for Nostr transport statistics.
#[derive(Debug, Default)]
pub struct NostrStats {
    pub events_published: AtomicU64,
    pub events_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub publish_errors: AtomicU64,
    pub decode_errors: AtomicU64,
    pub relay_connects: AtomicU64,
    pub relay_disconnects: AtomicU64,
}

/// Snapshot of Nostr transport stats (for serialization).
#[derive(Debug, serde::Serialize)]
pub struct NostrStatsSnapshot {
    pub events_published: u64,
    pub events_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub publish_errors: u64,
    pub decode_errors: u64,
    pub relay_connects: u64,
    pub relay_disconnects: u64,
}

impl NostrStats {
    pub fn snapshot(&self) -> NostrStatsSnapshot {
        NostrStatsSnapshot {
            events_published: self.events_published.load(Ordering::Relaxed),
            events_received: self.events_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            publish_errors: self.publish_errors.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            relay_connects: self.relay_connects.load(Ordering::Relaxed),
            relay_disconnects: self.relay_disconnects.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// Transport
// ============================================================================

/// Nostr transport for FIPS.
///
/// Provides packet delivery via ephemeral Nostr events through WebSocket
/// relays. A single transport instance manages connections to all configured
/// relays. Links are virtual, addressed by the remote peer's hex pubkey.
pub struct NostrTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: NostrConfig,
    /// Current state.
    state: TransportState,
    /// Node's signing keypair (set via set_keypair before start).
    keypair: Option<Keypair>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Relay connection task handles.
    relay_tasks: Vec<JoinHandle<()>>,
    /// Broadcast channel for distributing outbound messages to relay tasks.
    broadcast_tx: broadcast::Sender<String>,
    /// Shutdown signal.
    shutdown_tx: watch::Sender<bool>,
    /// Transport statistics.
    stats: Arc<NostrStats>,
}

impl NostrTransport {
    /// Create a new Nostr transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: NostrConfig,
        packet_tx: PacketTx,
    ) -> Self {
        let (broadcast_tx, _) = broadcast::channel(256);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            keypair: None,
            packet_tx,
            relay_tasks: Vec::new(),
            broadcast_tx,
            shutdown_tx,
            stats: Arc::new(NostrStats::default()),
        }
    }

    /// Set the node's signing keypair.
    ///
    /// Must be called before `start_async()`. The keypair is used to sign
    /// outgoing Nostr events and to derive the subscription pubkey filter.
    pub fn set_keypair(&mut self, keypair: Keypair) {
        self.keypair = Some(keypair);
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the link MTU for a specific address (always returns transport MTU).
    pub fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        self.config.mtu()
    }

    /// Close a connection (no-op for connectionless Nostr transport).
    pub fn close_connection(&self, _addr: &TransportAddr) {}

    /// Whether to auto-connect to discovered peers.
    pub fn auto_connect(&self) -> bool {
        false
    }

    /// Whether to accept inbound connections.
    pub fn accept_connections(&self) -> bool {
        true
    }

    /// Get transport stats.
    pub fn stats(&self) -> &Arc<NostrStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// Connects to all configured relays and subscribes for incoming events.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        let keypair = self.keypair.ok_or_else(|| {
            TransportError::StartFailed("keypair not set — call set_keypair() first".into())
        })?;

        if self.config.relays.is_empty() {
            return Err(TransportError::StartFailed("no relays configured".into()));
        }

        self.state = TransportState::Starting;

        let (our_pubkey, _) = keypair.x_only_public_key();
        let kind = self.config.kind();

        for relay_url in &self.config.relays {
            let relay_url = relay_url.clone();
            let transport_id = self.transport_id;
            let packet_tx = self.packet_tx.clone();
            let sub_msg = build_subscription(&our_pubkey, kind);
            let broadcast_rx = self.broadcast_tx.subscribe();
            let shutdown_rx = self.shutdown_tx.subscribe();
            let stats = self.stats.clone();

            let task = tokio::spawn(relay_loop(
                relay_url,
                transport_id,
                packet_tx,
                broadcast_rx,
                shutdown_rx,
                sub_msg,
                stats,
            ));

            self.relay_tasks.push(task);
        }

        self.state = TransportState::Up;

        info!(
            transport_id = %self.transport_id,
            name = ?self.name,
            relays = self.config.relays.len(),
            kind = kind,
            pubkey = %hex::encode(our_pubkey.serialize()),
            "Nostr transport started"
        );

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Signal all relay tasks to shut down gracefully
        let _ = self.shutdown_tx.send(true);

        // Wait for all relay tasks to finish (they will send CLOSE and
        // close their WebSockets before returning)
        for task in self.relay_tasks.drain(..) {
            let _ = task.await;
        }

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            "Nostr transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// The `addr` should be the recipient's hex-encoded x-only public key.
    /// The packet is Base64-encoded, wrapped in a signed Nostr event, and
    /// broadcast to all connected relay tasks for publishing.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if data.len() > self.config.mtu() as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }

        let keypair = self.keypair.ok_or(TransportError::NotStarted)?;
        let recipient_hex = addr
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress("non-string transport address".into()))?;

        let event_json = build_event(&keypair, recipient_hex, data, self.config.kind());
        let publish_msg = build_publish(&event_json);

        // Broadcast to all relay tasks (non-blocking)
        match self.broadcast_tx.send(publish_msg) {
            Ok(_) => {
                self.stats
                    .events_published
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(data.len() as u64, Ordering::Relaxed);

                trace!(
                    transport_id = %self.transport_id,
                    recipient = %recipient_hex,
                    bytes = data.len(),
                    "Nostr packet sent"
                );

                Ok(data.len())
            }
            Err(_) => {
                self.stats.publish_errors.fetch_add(1, Ordering::Relaxed);
                Err(TransportError::SendFailed(
                    "no relay connections available".into(),
                ))
            }
        }
    }
}

impl Transport for NostrTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::NOSTR
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for Nostr transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for Nostr transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for Nostr transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }
}

// ============================================================================
// Relay Loop
// ============================================================================

/// Relay connection loop with reconnection.
///
/// Owns both read and write halves of the WebSocket. Reads incoming events
/// and dispatches to `packet_tx`. Receives outbound messages from the
/// broadcast channel and forwards to the relay. Reconnects with exponential
/// backoff on disconnect.
async fn relay_loop(
    relay_url: String,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mut broadcast_rx: broadcast::Receiver<String>,
    mut shutdown_rx: watch::Receiver<bool>,
    subscription_msg: String,
    stats: Arc<NostrStats>,
) {
    let mut backoff = tokio::time::Duration::from_secs(1);
    let max_backoff = tokio::time::Duration::from_secs(60);

    loop {
        // Check for shutdown before attempting connection
        if *shutdown_rx.borrow() {
            return;
        }

        debug!(relay = %relay_url, "Connecting to Nostr relay");

        match connect_async(&relay_url).await {
            Ok((ws_stream, _)) => {
                info!(relay = %relay_url, "Connected to Nostr relay");
                stats.relay_connects.fetch_add(1, Ordering::Relaxed);
                backoff = tokio::time::Duration::from_secs(1);

                let (mut write, mut read) = ws_stream.split();

                // Send subscription
                if let Err(e) = write
                    .send(Message::Text(subscription_msg.clone().into()))
                    .await
                {
                    warn!(relay = %relay_url, error = %e, "Failed to send subscription");
                    stats.relay_disconnects.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                debug!(relay = %relay_url, "Subscription sent");

                // Main select loop: read from WebSocket, write from broadcast, watch for shutdown
                let disconnected = loop {
                    tokio::select! {
                        // Incoming message from relay
                        msg = read.next() => {
                            match msg {
                                Some(Ok(Message::Text(text))) => {
                                    handle_relay_text(&text, transport_id, &packet_tx, &stats, &relay_url).await;
                                }
                                Some(Ok(Message::Close(_))) => {
                                    info!(relay = %relay_url, "Relay sent close frame");
                                    break false;
                                }
                                Some(Err(e)) => {
                                    warn!(relay = %relay_url, error = %e, "WebSocket error");
                                    break false;
                                }
                                None => {
                                    // Stream ended
                                    break false;
                                }
                                _ => {} // Ignore ping/pong/binary
                            }
                        }
                        // Outbound message from send_async
                        msg = broadcast_rx.recv() => {
                            match msg {
                                Ok(publish_msg) => {
                                    if let Err(e) = write.send(Message::Text(publish_msg.into())).await {
                                        warn!(relay = %relay_url, error = %e, "Failed to publish event");
                                        break false;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    warn!(relay = %relay_url, dropped = n, "Broadcast channel lagged, dropped messages");
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    // Transport is being dropped
                                    break true;
                                }
                            }
                        }
                        // Shutdown signal
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break true;
                            }
                        }
                    }
                };

                // Graceful cleanup: unsubscribe and close WebSocket
                let _ = write.send(Message::Text(build_close().into())).await;
                let _ = write.close().await;
                stats.relay_disconnects.fetch_add(1, Ordering::Relaxed);

                if disconnected {
                    debug!(relay = %relay_url, "Relay loop shut down gracefully");
                    return;
                }

                warn!(relay = %relay_url, "Disconnected from relay, reconnecting...");
            }
            Err(e) => {
                warn!(
                    relay = %relay_url,
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "Failed to connect to relay"
                );
            }
        }

        // Backoff before reconnecting, but check for shutdown
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}

/// Handle a text message received from a relay.
async fn handle_relay_text(
    text: &str,
    transport_id: TransportId,
    packet_tx: &PacketTx,
    stats: &Arc<NostrStats>,
    relay_url: &str,
) {
    match event::parse_relay_message(text) {
        Some(RelayMessage::Event(parsed)) => {
            let data_len = parsed.content_bytes.len();
            let addr = TransportAddr::from_string(&parsed.sender_pubkey_hex);
            let packet = ReceivedPacket::new(transport_id, addr, parsed.content_bytes);

            trace!(
                transport_id = %transport_id,
                sender = %parsed.sender_pubkey_hex,
                bytes = data_len,
                "Nostr packet received"
            );

            stats.events_received.fetch_add(1, Ordering::Relaxed);
            stats
                .bytes_received
                .fetch_add(data_len as u64, Ordering::Relaxed);

            if packet_tx.send(packet).await.is_err() {
                debug!(
                    relay = %relay_url,
                    "Packet channel closed"
                );
            }
        }
        Some(RelayMessage::Notice(message)) => {
            warn!(relay = %relay_url, message = %message, "Relay NOTICE");
        }
        Some(RelayMessage::Ok {
            accepted: false,
            event_id,
            message,
        }) => {
            warn!(
                relay = %relay_url,
                event_id = %event_id,
                reason = %message,
                "Relay rejected event"
            );
            stats.publish_errors.fetch_add(1, Ordering::Relaxed);
        }
        Some(RelayMessage::Ok { accepted: true, .. }) => {
            // Event accepted, nothing to do
        }
        Some(RelayMessage::Eose(_)) => {
            debug!(relay = %relay_url, "Received EOSE");
        }
        Some(RelayMessage::Other(msg_type)) => {
            debug!(relay = %relay_url, msg_type = %msg_type, "Unhandled relay message type");
        }
        None => {
            stats.decode_errors.fetch_add(1, Ordering::Relaxed);
            trace!(relay = %relay_url, "Failed to parse relay message");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_channel;
    use secp256k1::{Secp256k1, SecretKey};
    use tokio::time::{timeout, Duration};

    fn make_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        secret[0] = 0x01; // ensure valid key
        let sk = SecretKey::from_slice(&secret).unwrap();
        Keypair::from_secret_key(&secp, &sk)
    }

    fn make_config() -> NostrConfig {
        NostrConfig {
            relays: vec!["ws://127.0.0.1:7777".to_string()],
            kind: Some(21210),
            mtu: Some(1280),
        }
    }

    #[test]
    fn test_transport_type() {
        let (tx, _rx) = packet_channel(100);
        let transport = NostrTransport::new(TransportId::new(1), None, make_config(), tx);
        assert_eq!(transport.transport_type().name, "nostr");
        assert!(!transport.transport_type().connection_oriented);
        assert!(!transport.transport_type().reliable);
    }

    #[test]
    fn test_sync_methods_return_not_supported() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = NostrTransport::new(TransportId::new(1), None, make_config(), tx);
        assert!(matches!(
            transport.start(),
            Err(TransportError::NotSupported(_))
        ));
        assert!(matches!(
            transport.stop(),
            Err(TransportError::NotSupported(_))
        ));
        assert!(matches!(
            transport.send(&TransportAddr::from_string("test"), b"data"),
            Err(TransportError::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn test_start_without_keypair_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut transport = NostrTransport::new(TransportId::new(1), None, make_config(), tx);
        let result = transport.start_async().await;
        assert!(matches!(result, Err(TransportError::StartFailed(_))));
    }

    #[tokio::test]
    async fn test_start_without_relays_fails() {
        let (tx, _rx) = packet_channel(100);
        let mut config = make_config();
        config.relays.clear();
        let mut transport = NostrTransport::new(TransportId::new(1), None, config, tx);
        transport.set_keypair(make_keypair(1));
        let result = transport.start_async().await;
        assert!(matches!(result, Err(TransportError::StartFailed(_))));
    }

    #[tokio::test]
    #[ignore] // requires local relay at ws://127.0.0.1:7777
    async fn test_send_recv_via_relay() {
        let kp_a = make_keypair(1);
        let kp_b = make_keypair(2);

        let (xonly_a, _) = kp_a.x_only_public_key();
        let (xonly_b, _) = kp_b.x_only_public_key();
        let hex_a = hex::encode(xonly_a.serialize());
        let hex_b = hex::encode(xonly_b.serialize());

        let (tx_a, _rx_a) = packet_channel(100);
        let (tx_b, mut rx_b) = packet_channel(100);

        let mut transport_a =
            NostrTransport::new(TransportId::new(1), None, make_config(), tx_a);
        let mut transport_b =
            NostrTransport::new(TransportId::new(2), None, make_config(), tx_b);

        transport_a.set_keypair(kp_a);
        transport_b.set_keypair(kp_b);

        // Start both transports
        transport_b.start_async().await.unwrap();
        transport_a.start_async().await.unwrap();

        // Wait for subscriptions to be established on the relay
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Send from A to B
        let payload = b"hello from A to B via nostr";
        let addr_b = TransportAddr::from_string(&hex_b);
        let bytes_sent = transport_a.send_async(&addr_b, payload).await.unwrap();
        assert_eq!(bytes_sent, payload.len());

        // Receive on B
        let packet = timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed");

        assert_eq!(packet.data, payload);
        assert_eq!(packet.remote_addr.as_str(), Some(hex_a.as_str()));
        assert_eq!(packet.transport_id, TransportId::new(2));

        // Verify stats
        assert_eq!(
            transport_a.stats().events_published.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            transport_b.stats().events_received.load(Ordering::Relaxed),
            1
        );

        // Stop both transports
        transport_a.stop_async().await.unwrap();
        transport_b.stop_async().await.unwrap();
    }

    #[tokio::test]
    #[ignore] // requires local relay at ws://127.0.0.1:7777
    async fn test_bidirectional_via_relay() {
        let kp_a = make_keypair(3);
        let kp_b = make_keypair(4);

        let (xonly_a, _) = kp_a.x_only_public_key();
        let (xonly_b, _) = kp_b.x_only_public_key();
        let hex_a = hex::encode(xonly_a.serialize());
        let hex_b = hex::encode(xonly_b.serialize());

        let (tx_a, mut rx_a) = packet_channel(100);
        let (tx_b, mut rx_b) = packet_channel(100);

        let mut transport_a =
            NostrTransport::new(TransportId::new(1), None, make_config(), tx_a);
        let mut transport_b =
            NostrTransport::new(TransportId::new(2), None, make_config(), tx_b);

        transport_a.set_keypair(kp_a);
        transport_b.set_keypair(kp_b);

        transport_a.start_async().await.unwrap();
        transport_b.start_async().await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        // A -> B
        let addr_b = TransportAddr::from_string(&hex_b);
        transport_a.send_async(&addr_b, b"ping").await.unwrap();

        let packet = timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, b"ping");

        // B -> A
        let addr_a = TransportAddr::from_string(&hex_a);
        transport_b.send_async(&addr_a, b"pong").await.unwrap();

        let packet = timeout(Duration::from_secs(5), rx_a.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(packet.data, b"pong");

        transport_a.stop_async().await.unwrap();
        transport_b.stop_async().await.unwrap();
    }
}
