//! UDP hole-punch packet format and state machine.
//!
//! Implements the punch phase of the Nostr UDP Hole Punch Protocol:
//! both peers simultaneously send NPTC probe packets to each other's
//! reflexive address, and reply with NPTA ack packets. The hole is
//! considered punched only after a peer has both received a probe from the
//! other side and received an ack to one of its own probes. This prevents one
//! side from exiting too early and leaving the other side waiting for an ack.
//!
//! Packet format (24 bytes):
//!
//! ```text
//! NPTC (probe):
//!   Bytes 0–3:   0x4E505443  ("NPTC" magic)
//!   Bytes 4–7:   sequence number (u32 big-endian)
//!   Bytes 8–23:  first 16 bytes of SHA-256(session_id)
//!
//! NPTA (ack):
//!   Bytes 0–3:   0x4E505441  ("NPTA" magic)
//!   Bytes 4–7:   echoed sequence number from the received probe
//!   Bytes 8–23:  first 16 bytes of SHA-256(session_id)
//! ```

use super::HolePunchError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, interval};
use tracing::{debug, trace};

/// Magic bytes for a punch probe: "NPTC" (Nostr P2P Tunnel Connect).
const NPTC_MAGIC: [u8; 4] = *b"NPTC";

/// Magic bytes for a punch ack: "NPTA" (Nostr P2P Tunnel Ack).
const NPTA_MAGIC: [u8; 4] = *b"NPTA";

/// Total punch packet size: 4 (magic) + 4 (seq) + 16 (session hash).
const PUNCH_PACKET_LEN: usize = 24;

/// Default probe interval.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// Default punch timeout.
pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed punch packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchPacket {
    /// NPTC probe with a sequence number.
    Probe { seq: u32 },
    /// NPTA ack echoing the sequence number from a received probe.
    Ack { seq: u32 },
}

/// Derive the 16-byte session hash from a session_id string.
///
/// Both peers must use the same session_id (exchanged during Nostr
/// signaling) so their punch packets carry matching hashes.
pub fn session_hash(session_id: &str) -> [u8; 16] {
    let digest = Sha256::digest(session_id.as_bytes());
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// Build a 24-byte NPTC punch probe packet.
pub fn build_punch(seq: u32, hash: &[u8; 16]) -> [u8; PUNCH_PACKET_LEN] {
    let mut buf = [0u8; PUNCH_PACKET_LEN];
    buf[0..4].copy_from_slice(&NPTC_MAGIC);
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..24].copy_from_slice(hash);
    buf
}

/// Build a 24-byte NPTA punch ack packet.
pub fn build_punch_ack(echo_seq: u32, hash: &[u8; 16]) -> [u8; PUNCH_PACKET_LEN] {
    let mut buf = [0u8; PUNCH_PACKET_LEN];
    buf[0..4].copy_from_slice(&NPTA_MAGIC);
    buf[4..8].copy_from_slice(&echo_seq.to_be_bytes());
    buf[8..24].copy_from_slice(hash);
    buf
}

/// Parse a received buffer as a punch packet.
///
/// Returns `None` if the buffer is too short, has an unrecognized magic,
/// or the session hash doesn't match. This lets callers silently ignore
/// stray traffic (STUN leftovers, other protocols on the same socket).
pub fn parse_punch(buf: &[u8], expected_hash: &[u8; 16]) -> Option<PunchPacket> {
    if buf.len() < PUNCH_PACKET_LEN {
        return None;
    }

    // Check session hash first (bytes 8–23) to reject unrelated traffic cheaply.
    if &buf[8..24] != expected_hash {
        return None;
    }

    let seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    match &buf[0..4] {
        b"NPTC" => Some(PunchPacket::Probe { seq }),
        b"NPTA" => Some(PunchPacket::Ack { seq }),
        _ => None,
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PunchProgress {
    got_probe: bool,
    got_ack: bool,
}

/// Run the hole-punch exchange on the given socket.
///
/// Sends NPTC probes every `probe_interval` to `peer_addr`, listens for
/// incoming NPTC/NPTA packets. Returns `Ok(())` when bidirectional
/// connectivity is confirmed (we have seen the peer's probe and received an
/// ack to one of our own probes), or `Err(Timeout)` if `punch_timeout`
/// elapses without success.
///
/// The caller must ensure the socket is already bound and is the same
/// socket used for the preceding STUN query (to preserve the NAT mapping).
pub async fn run_punch(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    session_id: &str,
    probe_interval: Duration,
    punch_timeout: Duration,
) -> Result<(), HolePunchError> {
    run_punch_candidates(
        socket,
        &[peer_addr],
        session_id,
        probe_interval,
        punch_timeout,
    )
    .await
    .map(|_| ())
}

/// Run the hole-punch exchange against multiple candidate peer addresses.
///
/// Probes are sent to every candidate on each tick. Progress is tracked per
/// source address and the first fully confirmed path wins.
pub async fn run_punch_candidates(
    socket: &UdpSocket,
    peer_addrs: &[SocketAddr],
    session_id: &str,
    probe_interval: Duration,
    punch_timeout: Duration,
) -> Result<SocketAddr, HolePunchError> {
    let mut candidates = Vec::with_capacity(peer_addrs.len());
    for &addr in peer_addrs {
        if !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }

    if candidates.is_empty() {
        return Err(HolePunchError::InvalidSignal(
            "no punch candidate addresses".into(),
        ));
    }

    let hash = session_hash(session_id);
    let start = Instant::now();
    let mut ticker = interval(probe_interval);
    let mut seq: u32 = 0;
    let mut buf = [0u8; 64];
    let mut progress: HashMap<SocketAddr, PunchProgress> = HashMap::new();

    debug!(targets = ?candidates, timeout = ?punch_timeout, "hole punching: sending to candidate addresses");

    loop {
        if start.elapsed() > punch_timeout {
            return Err(HolePunchError::Timeout(punch_timeout));
        }

        tokio::select! {
            _ = ticker.tick() => {
                let packet = build_punch(seq, &hash);
                for peer_addr in &candidates {
                    socket.send_to(&packet, peer_addr).await?;
                    trace!("sent NPTC seq={seq} to {peer_addr}");
                }
                seq = seq.wrapping_add(1);
            }
            result = socket.recv_from(&mut buf) => {
                let (n, from) = result?;

                // Ignore packets not from any expected peer candidate.
                if !candidates.contains(&from) {
                    trace!("ignoring packet from unexpected source {from}");
                    continue;
                }

                match parse_punch(&buf[..n], &hash) {
                    Some(PunchPacket::Probe { seq: peer_seq }) => {
                        let state = progress.entry(from).or_default();
                        trace!("received NPTC seq={peer_seq} from {from}");
                        state.got_probe = true;
                        // Immediately ack the probe.
                        let ack = build_punch_ack(peer_seq, &hash);
                        socket.send_to(&ack, from).await?;
                        trace!("sent NPTA seq={peer_seq} to {from}");

                        if state.got_ack {
                            debug!(
                                "hole punch complete: received peer probe and prior NPTA from {from} \
                                 after {:.1}s",
                                start.elapsed().as_secs_f64()
                            );
                            return Ok(from);
                        }
                    }
                    Some(PunchPacket::Ack { seq: acked_seq }) => {
                        let state = progress.entry(from).or_default();
                        // The peer received one of our probes and acked it.
                        state.got_ack = true;
                        trace!("received NPTA seq={acked_seq} from {from}");

                        if state.got_probe {
                            debug!(
                                "hole punch complete: received peer probe and NPTA seq={acked_seq} \
                                 from {from} after {:.1}s",
                                start.elapsed().as_secs_f64()
                            );
                            return Ok(from);
                        }
                    }
                    None => {
                        // Not a punch packet (stray traffic, STUN leftover, etc.)
                        trace!("ignoring non-punch packet from {from}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Packet format unit tests ---

    #[test]
    fn session_hash_deterministic() {
        let h1 = session_hash("abc123");
        let h2 = session_hash("abc123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn session_hash_differs_for_different_ids() {
        let h1 = session_hash("session_a");
        let h2 = session_hash("session_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn punch_probe_roundtrip() {
        let hash = session_hash("test-session");
        let packet = build_punch(42, &hash);

        assert_eq!(packet.len(), PUNCH_PACKET_LEN);
        assert_eq!(&packet[0..4], b"NPTC");

        let parsed = parse_punch(&packet, &hash);
        assert_eq!(parsed, Some(PunchPacket::Probe { seq: 42 }));
    }

    #[test]
    fn punch_ack_roundtrip() {
        let hash = session_hash("test-session");
        let packet = build_punch_ack(99, &hash);

        assert_eq!(packet.len(), PUNCH_PACKET_LEN);
        assert_eq!(&packet[0..4], b"NPTA");

        let parsed = parse_punch(&packet, &hash);
        assert_eq!(parsed, Some(PunchPacket::Ack { seq: 99 }));
    }

    #[test]
    fn parse_rejects_wrong_session() {
        let hash_a = session_hash("session_a");
        let hash_b = session_hash("session_b");

        let packet = build_punch(0, &hash_a);
        assert_eq!(parse_punch(&packet, &hash_b), None);
    }

    #[test]
    fn parse_rejects_short_packet() {
        let hash = session_hash("test");
        assert_eq!(parse_punch(&[0u8; 23], &hash), None); // one byte short
        assert_eq!(parse_punch(&[], &hash), None);
    }

    #[test]
    fn parse_rejects_garbage() {
        let hash = session_hash("test");
        assert_eq!(parse_punch(b"this is not a punch packet", &hash), None);
    }

    #[test]
    fn sequence_number_preserved() {
        let hash = session_hash("test");

        // Test a few boundary values.
        for seq in [0, 1, 255, 65535, u32::MAX] {
            let probe = build_punch(seq, &hash);
            assert_eq!(parse_punch(&probe, &hash), Some(PunchPacket::Probe { seq }));

            let ack = build_punch_ack(seq, &hash);
            assert_eq!(parse_punch(&ack, &hash), Some(PunchPacket::Ack { seq }));
        }
    }

    // --- Integration tests ---

    #[tokio::test]
    async fn punch_two_peers_localhost() {
        let session_id = "integration-test-session-1234";

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // Both peers punch concurrently. On localhost without NAT,
        // the first probe from each side arrives immediately.
        let (result_a, result_b) = tokio::join!(
            run_punch(
                &sock_a,
                addr_b,
                session_id,
                DEFAULT_PROBE_INTERVAL,
                DEFAULT_PUNCH_TIMEOUT
            ),
            run_punch(
                &sock_b,
                addr_a,
                session_id,
                DEFAULT_PROBE_INTERVAL,
                DEFAULT_PUNCH_TIMEOUT
            ),
        );

        result_a.unwrap();
        result_b.unwrap();
    }

    #[tokio::test]
    async fn punch_two_peers_staggered_start() {
        let session_id = "staggered-start-session-1234";

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // Start peer A first, then let peer B join later. This mirrors the
        // real-world case where one side finishes signaling and begins
        // punching slightly before the other.
        let punch_a = tokio::spawn(async move {
            run_punch(
                &sock_a,
                addr_b,
                session_id,
                DEFAULT_PROBE_INTERVAL,
                DEFAULT_PUNCH_TIMEOUT,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(600)).await;

        let result_b = run_punch(
            &sock_b,
            addr_a,
            session_id,
            DEFAULT_PROBE_INTERVAL,
            DEFAULT_PUNCH_TIMEOUT,
        )
        .await;

        let result_a = punch_a.await.unwrap();

        result_a.unwrap();
        result_b.unwrap();
    }

    #[tokio::test]
    async fn punch_timeout_when_no_peer() {
        let session_id = "timeout-test-session";

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Point at an address where nobody is listening.
        let fake_peer: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let short_timeout = Duration::from_millis(500);
        let start = Instant::now();

        let result = run_punch(
            &sock,
            fake_peer,
            session_id,
            DEFAULT_PROBE_INTERVAL,
            short_timeout,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HolePunchError::Timeout(_)));
        // Should have taken roughly the timeout duration, not longer.
        assert!(start.elapsed() < short_timeout + Duration::from_millis(300));
    }

    #[tokio::test]
    async fn punch_candidates_returns_winning_address() {
        let session_id = "candidate-punch-session";

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let bogus_a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let bogus_b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let candidates_a = [bogus_b, addr_b];
        let candidates_b = [bogus_a, addr_a];

        let (result_a, result_b) = tokio::join!(
            run_punch_candidates(
                &sock_a,
                &candidates_a,
                session_id,
                DEFAULT_PROBE_INTERVAL,
                DEFAULT_PUNCH_TIMEOUT,
            ),
            run_punch_candidates(
                &sock_b,
                &candidates_b,
                session_id,
                DEFAULT_PROBE_INTERVAL,
                DEFAULT_PUNCH_TIMEOUT,
            ),
        );

        assert_eq!(result_a.unwrap(), addr_b);
        assert_eq!(result_b.unwrap(), addr_a);
    }
}
