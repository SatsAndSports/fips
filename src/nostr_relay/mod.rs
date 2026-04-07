//! Nostr relay client and test utilities.
//!
//! Provides a minimal async client for communicating with Nostr relays
//! over WebSocket, and an in-process test relay for integration testing.

pub mod relay_client;

#[cfg(test)]
pub(crate) mod test_relay;

pub use relay_client::{RelayClient, Subscription};

/// Errors that can occur during Nostr relay operations.
#[derive(Debug, thiserror::Error)]
pub enum NostrError {
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("relay rejected event: {0}")]
    Rejected(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("timeout waiting for EOSE")]
    EoseTimeout,

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Initialize tracing for tests. Safe to call multiple times — only the
/// first call takes effect.
#[cfg(test)]
pub(crate) fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();
}
