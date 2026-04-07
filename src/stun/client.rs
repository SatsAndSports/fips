//! STUN Binding Request client.
//!
//! Sends a Binding Request to a STUN server and parses the response to
//! extract the reflexive (public) address.

use super::StunError;
use super::wire::{build_binding_request, parse_binding_response};
use std::net::{SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

/// Default timeout for a STUN Binding Request/Response exchange.
const STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// Send a STUN Binding Request and return the reflexive (mapped) address.
///
/// The provided `socket` must already be bound. It will be used as-is —
/// this is important for hole punching, where the same socket must be
/// reused for the subsequent punch phase to preserve the NAT mapping.
///
/// `stun_server` is a `"host:port"` string that will be resolved via DNS.
pub async fn stun_query(
    socket: &UdpSocket,
    stun_server: &str,
) -> Result<SocketAddrV4, StunError> {
    let (request, txn_id) = build_binding_request();

    // Resolve the STUN server address.
    let server_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await
        .map_err(|e| StunError::DnsLookup {
            host: stun_server.to_string(),
            reason: e.to_string(),
        })?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| StunError::DnsLookup {
            host: stun_server.to_string(),
            reason: "no IPv4 address found".to_string(),
        })?;

    // Send the Binding Request.
    socket
        .send_to(&request, server_addr)
        .await
        .map_err(StunError::Io)?;

    // Wait for the response. We don't check the source address of the
    // response — the 96-bit random transaction ID provides sufficient
    // correlation to reject spoofed packets.
    let mut buf = [0u8; 1024];
    let (n, _from) = timeout(STUN_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .map_err(|_| StunError::Timeout)?
        .map_err(StunError::Io)?;

    parse_binding_response(&buf[..n], &txn_id).map(|r| r.mapped_addr)
}
