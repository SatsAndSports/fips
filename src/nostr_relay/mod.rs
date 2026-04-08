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

    #[error("relay {relay} rejected event: {message}")]
    Rejected { relay: String, message: String },

    #[error("relay connection closed")]
    ConnectionClosed,

    #[error("relay {0} connection closed")]
    ConnectionClosedAt(String),

    #[error("timeout waiting for EOSE")]
    EoseTimeout,

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl NostrError {
    pub fn with_relay(self, relay: &str) -> Self {
        match self {
            Self::Rejected { message, .. } => Self::Rejected {
                relay: relay.to_string(),
                message,
            },
            Self::ConnectionClosed => Self::ConnectionClosedAt(relay.to_string()),
            other => other,
        }
    }
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
