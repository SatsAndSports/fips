//! Nostr NIP-01 event building and parsing.
//!
//! Minimal implementation for constructing and signing ephemeral events,
//! and parsing incoming relay messages (EVENT, NOTICE, OK, EOSE).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// Build a signed Nostr event JSON string.
///
/// Constructs a `kind` event with a `["p", recipient_hex]` tag and
/// Base64-encoded content. The event is signed with the sender's keypair
/// using Schnorr signatures per NIP-01.
pub fn build_event(
    keypair: &Keypair,
    recipient_pubkey: &str,
    content_bytes: &[u8],
    kind: u32,
) -> String {
    let secp = Secp256k1::new();
    let (xonly, _parity) = keypair.x_only_public_key();
    let pubkey_hex = hex::encode(xonly.serialize());
    let content = BASE64.encode(content_bytes);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // NIP-01 event ID: SHA-256 of the serialized event array:
    // [0, <pubkey_hex>, <created_at>, <kind>, <tags>, <content>]
    let tags_json = format!("[[\"p\",\"{}\"]]", recipient_pubkey);
    let serialized = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        pubkey_hex, created_at, kind, tags_json, content
    );

    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let id_bytes: [u8; 32] = hasher.finalize().into();
    let id_hex = hex::encode(id_bytes);

    // Sign the event ID with Schnorr (secp256k1 v0.30: sign_schnorr takes &[u8])
    let sig = secp.sign_schnorr(&id_bytes, keypair);
    let sig_hex = hex::encode(sig.to_byte_array());

    // Build the full event JSON
    format!(
        "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{},\"kind\":{},\"tags\":[[\"p\",\"{}\"]],\"content\":\"{}\",\"sig\":\"{}\"}}",
        id_hex, pubkey_hex, created_at, kind, recipient_pubkey, content, sig_hex
    )
}

/// Build a REQ subscription message for receiving FIPS packets.
///
/// Subscribes to events of the given `kind` that are tagged with our pubkey.
pub fn build_subscription(our_pubkey: &XOnlyPublicKey, kind: u32) -> String {
    let pubkey_hex = hex::encode(our_pubkey.serialize());
    format!(
        "[\"REQ\",\"fips\",{{\"kinds\":[{}],\"#p\":[\"{}\"]}}]",
        kind, pubkey_hex
    )
}

/// Build a CLOSE message for our subscription.
pub fn build_close() -> String {
    "[\"CLOSE\",\"fips\"]".to_string()
}

/// Build an EVENT publish message wrapping a signed event.
pub fn build_publish(event_json: &str) -> String {
    format!("[\"EVENT\",{}]", event_json)
}

// ============================================================================
// Relay Message Parsing
// ============================================================================

/// Parsed incoming Nostr event.
#[derive(Debug)]
pub struct ParsedEvent {
    /// Sender's hex-encoded x-only public key.
    pub sender_pubkey_hex: String,
    /// Decoded content bytes (Base64-decoded).
    pub content_bytes: Vec<u8>,
}

/// A message received from a Nostr relay.
#[derive(Debug)]
pub enum RelayMessage {
    /// An event matching our subscription.
    Event(ParsedEvent),
    /// A NOTICE message from the relay (human-readable string).
    Notice(String),
    /// An OK response to a published event.
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    /// End of stored events for a subscription.
    Eose(String),
    /// Unrecognized message type.
    Other(String),
}

/// Parse a relay message into a typed enum.
///
/// Handles EVENT, NOTICE, OK, EOSE, and falls back to Other for
/// unrecognized message types.
pub fn parse_relay_message(msg: &str) -> Option<RelayMessage> {
    let value: serde_json::Value = serde_json::from_str(msg).ok()?;
    let arr = value.as_array()?;

    if arr.is_empty() {
        return None;
    }

    let msg_type = arr[0].as_str()?;

    match msg_type {
        "EVENT" => {
            if arr.len() < 3 {
                return None;
            }
            let event = &arr[2];
            let sender_pubkey_hex = event.get("pubkey")?.as_str()?.to_string();
            let content_b64 = event.get("content")?.as_str()?;
            let content_bytes = BASE64.decode(content_b64).ok()?;

            Some(RelayMessage::Event(ParsedEvent {
                sender_pubkey_hex,
                content_bytes,
            }))
        }
        "NOTICE" => {
            let message = arr.get(1)?.as_str()?.to_string();
            Some(RelayMessage::Notice(message))
        }
        "OK" => {
            let event_id = arr.get(1)?.as_str().unwrap_or_default().to_string();
            let accepted = arr.get(2)?.as_bool().unwrap_or(false);
            let message = arr.get(3)?.as_str().unwrap_or_default().to_string();
            Some(RelayMessage::Ok {
                event_id,
                accepted,
                message,
            })
        }
        "EOSE" => {
            let sub_id = arr.get(1)?.as_str().unwrap_or_default().to_string();
            Some(RelayMessage::Eose(sub_id))
        }
        _ => Some(RelayMessage::Other(msg_type.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn test_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    #[test]
    fn test_build_and_parse_event() {
        let kp = test_keypair();
        let recipient = "a".repeat(64);
        let payload = b"hello fips";

        let event_json = build_event(&kp, &recipient, payload, 21210);
        let publish_msg = build_publish(&event_json);

        // Wrap as relay would send it: ["EVENT", "fips", <event>]
        let relay_msg = format!("[\"EVENT\",\"fips\",{}]", event_json);

        let parsed = parse_relay_message(&relay_msg);
        let event = match parsed.unwrap() {
            RelayMessage::Event(e) => e,
            other => panic!("expected Event, got {:?}", other),
        };
        assert_eq!(event.content_bytes, payload);

        let (xonly, _) = kp.x_only_public_key();
        assert_eq!(event.sender_pubkey_hex, hex::encode(xonly.serialize()));

        // Verify the publish message wraps correctly
        assert!(publish_msg.starts_with("[\"EVENT\",{"));
    }

    #[test]
    fn test_build_subscription() {
        let kp = test_keypair();
        let (xonly, _) = kp.x_only_public_key();
        let sub = build_subscription(&xonly, 21210);

        assert!(sub.contains("\"REQ\""));
        assert!(sub.contains("\"fips\""));
        assert!(sub.contains("21210"));
        assert!(sub.contains(&hex::encode(xonly.serialize())));
    }

    #[test]
    fn test_parse_notice() {
        let msg = "[\"NOTICE\",\"rate limited\"]";
        match parse_relay_message(msg).unwrap() {
            RelayMessage::Notice(s) => assert_eq!(s, "rate limited"),
            other => panic!("expected Notice, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ok_accepted() {
        let msg = "[\"OK\",\"abc123\",true,\"\"]";
        match parse_relay_message(msg).unwrap() {
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, "abc123");
                assert!(accepted);
                assert_eq!(message, "");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ok_rejected() {
        let msg = "[\"OK\",\"abc123\",false,\"blocked: event kind not allowed\"]";
        match parse_relay_message(msg).unwrap() {
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, "abc123");
                assert!(!accepted);
                assert_eq!(message, "blocked: event kind not allowed");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_eose() {
        let msg = "[\"EOSE\",\"fips\"]";
        match parse_relay_message(msg).unwrap() {
            RelayMessage::Eose(sub_id) => assert_eq!(sub_id, "fips"),
            other => panic!("expected Eose, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_unknown_type() {
        let msg = "[\"AUTH\",\"challenge123\"]";
        match parse_relay_message(msg).unwrap() {
            RelayMessage::Other(t) => assert_eq!(t, "AUTH"),
            other => panic!("expected Other, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_invalid_returns_none() {
        assert!(parse_relay_message("not json").is_none());
        assert!(parse_relay_message("[]").is_none());
        assert!(parse_relay_message("[42]").is_none());
    }

    #[test]
    fn test_event_id_is_valid_sha256() {
        let kp = test_keypair();
        let recipient = "b".repeat(64);
        let event_json = build_event(&kp, &recipient, b"test", 21210);

        let event: serde_json::Value = serde_json::from_str(&event_json).unwrap();
        let id = event["id"].as_str().unwrap();

        // ID should be 64 hex chars (32 bytes)
        assert_eq!(id.len(), 64);
        assert!(hex::decode(id).is_ok());
    }

    #[test]
    fn test_event_signature_verifies() {
        let secp = Secp256k1::new();
        let kp = test_keypair();
        let (xonly, _) = kp.x_only_public_key();
        let recipient = "c".repeat(64);
        let event_json = build_event(&kp, &recipient, b"verify me", 21210);

        let event: serde_json::Value = serde_json::from_str(&event_json).unwrap();
        let id_hex = event["id"].as_str().unwrap();
        let sig_hex = event["sig"].as_str().unwrap();

        let id_bytes: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();

        assert!(secp.verify_schnorr(&sig, &id_bytes, &xonly).is_ok());
    }
}
