//! STUN (Session Traversal Utilities for NAT) implementation.
//!
//! Provides a minimal RFC 8489 STUN Binding Request/Response implementation
//! for NAT traversal. Includes both a client (for discovering reflexive
//! addresses) and a server (for responding to binding requests).
//!
//! Only IPv4 and the Binding method are supported. This is sufficient for
//! STUN-assisted UDP hole punching.

pub mod client;
pub mod server;
pub mod wire;

pub use client::stun_query;
pub use server::StunServer;

/// Errors that can occur during STUN operations.
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("STUN response timed out")]
    Timeout,

    #[error("DNS lookup failed for {host}: {reason}")]
    DnsLookup { host: String, reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}
