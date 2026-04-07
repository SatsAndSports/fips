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

pub mod punch;
pub mod signaling;

#[cfg(test)]
mod tests;

use std::time::Duration;

/// Errors that can occur during hole punching.
#[derive(Debug, thiserror::Error)]
pub enum HolePunchError {
    #[error("hole punch timed out after {0:?}")]
    Timeout(Duration),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
