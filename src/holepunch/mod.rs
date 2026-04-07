//! Nostr-signaled UDP hole punching.
//!
//! Implements the hole-punch protocol for establishing direct UDP connectivity
//! between two peers behind NAT. The protocol uses:
//!
//! - **STUN** for reflexive address discovery (see [`crate::stun`])
//! - **Nostr relays** for signaling (offer/answer exchange)
//! - **UDP punch packets** for NAT traversal
//!
//! The punch packet format follows the Nostr UDP Hole Punch Protocol proposal,
//! using `NPTC` (probe) and `NPTA` (ack) packets with a shared session hash
//! for correlation.

pub mod orchestrator;
pub mod punch;
pub mod signaling;

#[cfg(test)]
mod tests;

use std::time::Duration;

/// Errors that can occur during hole punching.
#[derive(Debug, thiserror::Error)]
pub enum HolePunchError {
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("STUN error: {0}")]
    Stun(#[from] crate::stun::StunError),

    #[error("Nostr error: {0}")]
    Nostr(#[from] crate::nostr_relay::NostrError),

    #[error("invalid advertisement: {0}")]
    InvalidAdvertisement(String),

    #[error("service advertisement not found")]
    AdvertisementNotFound,

    #[error("invalid signal: {0}")]
    InvalidSignal(String),

    #[error("session mismatch: expected {expected}, got {actual}")]
    SessionMismatch { expected: String, actual: String },

    #[error("all relay subscriptions closed")]
    AllSubscriptionsClosed,

    #[error("no STUN servers configured")]
    NoStunServers,
}
