//! STUN Binding Response server.
//!
//! A lightweight async STUN server that responds to Binding Requests with
//! XOR-MAPPED-ADDRESS containing the observed source address. Useful both
//! as a test fixture and as a self-hosted STUN service for FIPS mesh nodes.

use super::StunError;
use super::wire::{build_binding_response, parse_binding_request};
use std::net::{SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

/// A running STUN server instance.
///
/// Responds to STUN Binding Requests with the observed source address.
/// Non-STUN traffic is silently ignored.
pub struct StunServer {
    local_addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl StunServer {
    /// Bind to the given address and start serving STUN Binding Requests.
    ///
    /// Use `"127.0.0.1:0"` or `"0.0.0.0:0"` for an OS-assigned port.
    /// The actual bound address is available via [`local_addr()`](Self::local_addr).
    pub async fn bind(addr: &str) -> Result<Self, StunError> {
        let socket = UdpSocket::bind(addr).await.map_err(StunError::Io)?;
        let local_addr = socket.local_addr().map_err(StunError::Io)?;

        debug!("STUN server listening on {local_addr}");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(Self::serve_loop(socket, shutdown_rx));

        Ok(Self {
            local_addr,
            shutdown_tx,
            task,
        })
    }

    /// The address this server is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shut down the server and wait for the task to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.task.await;
    }

    /// Main server loop: receive Binding Requests, respond with
    /// XOR-MAPPED-ADDRESS echoing the observed source address.
    async fn serve_loop(socket: UdpSocket, mut shutdown_rx: tokio::sync::oneshot::Receiver<()>) {
        let mut buf = [0u8; 1024];

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("STUN server shutting down");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    let (n, from) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("STUN server recv error: {e}");
                            continue;
                        }
                    };

                    let data = &buf[..n];

                    // Try to parse as a Binding Request; ignore anything else.
                    let txn_id = match parse_binding_request(data) {
                        Some(id) => id,
                        None => {
                            trace!("STUN server: ignoring non-STUN packet from {from}");
                            continue;
                        }
                    };

                    // Convert source address to SocketAddrV4 (we only handle IPv4).
                    let from_v4 = match from {
                        SocketAddr::V4(v4) => v4,
                        SocketAddr::V6(v6) => {
                            // Handle IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
                            match v6.ip().to_ipv4_mapped() {
                                Some(ipv4) => SocketAddrV4::new(ipv4, v6.port()),
                                None => {
                                    trace!("STUN server: ignoring IPv6 request from {from}");
                                    continue;
                                }
                            }
                        }
                    };

                    let response = build_binding_response(&txn_id, from_v4);

                    if let Err(e) = socket.send_to(&response, from).await {
                        warn!("STUN server send error to {from}: {e}");
                    } else {
                        trace!("STUN server: replied to {from} with mapped addr {from_v4}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::client::stun_query;
    use std::net::SocketAddrV4;
    use std::time::Duration;

    /// Extract the IPv4 address from a SocketAddr, panicking if IPv6.
    fn to_v4(addr: SocketAddr) -> SocketAddrV4 {
        match addr {
            SocketAddr::V4(v4) => v4,
            other => panic!("expected IPv4, got {other}"),
        }
    }

    #[tokio::test]
    async fn stun_client_server_roundtrip() {
        let server = StunServer::bind("127.0.0.1:0").await.unwrap();

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_local = to_v4(client_sock.local_addr().unwrap());

        // On localhost with no NAT, the reflexive address should match
        // the client's local address exactly.
        let reflexive = stun_query(&client_sock, &server.local_addr().to_string())
            .await
            .unwrap();
        assert_eq!(reflexive, client_local);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn stun_server_ignores_garbage() {
        let server = StunServer::bind("127.0.0.1:0").await.unwrap();

        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_local = to_v4(client_sock.local_addr().unwrap());

        // Send garbage — server should not crash or respond.
        client_sock
            .send_to(b"not a stun packet", server.local_addr())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A real STUN request should still work fine.
        let reflexive = stun_query(&client_sock, &server.local_addr().to_string())
            .await
            .unwrap();
        assert_eq!(reflexive, client_local);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn stun_multiple_clients() {
        let server = StunServer::bind("127.0.0.1:0").await.unwrap();
        let server_str = server.local_addr().to_string();

        // Three clients should each get their own unique reflexive address.
        let mut ports = Vec::new();
        for _ in 0..3 {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = sock.local_addr().unwrap();
            let reflexive = stun_query(&sock, &server_str).await.unwrap();

            assert_eq!(reflexive.port(), local.port());
            ports.push(reflexive.port());
        }

        // All ports should be distinct (OS-assigned).
        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), 3);

        server.shutdown().await;
    }
}
