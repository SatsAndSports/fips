//! Nostr signaling for UDP hole-punch negotiation.
//!
//! Implements the offer/answer exchange that precedes hole punching:
//!
//! 1. **Responder** subscribes for incoming signals, then publishes a
//!    kind 30078 service advertisement.
//! 2. **Initiator** discovers the advertisement, does STUN, and sends
//!    a kind 21059 offer with its reflexive address.
//! 3. **Responder** receives the offer, does STUN, and sends back a
//!    kind 21059 answer.
//! 4. Both peers begin hole punching.
//!
//! Signaling events (offers and answers) are NIP-44 encrypted and NIP-59
//! gift-wrapped using kind 21059 (ephemeral range). The three-layer
//! structure is:
//!
//! - **Rumor** (unsigned, kind 21059): contains the JSON payload and a
//!   `p` tag for the recipient.
//! - **Seal** (kind 13, signed by sender's real keys): NIP-44 encrypts
//!   the rumor JSON to the recipient's pubkey.
//! - **Outer wrap** (kind 21059, signed by an ephemeral key): NIP-44
//!   encrypts the seal JSON to the recipient's pubkey. Carries the `p`
//!   tag for relay filtering and an `expiration` tag (120 s).

use super::HolePunchError;
use crate::nostr_relay::NostrError;
use crate::nostr_relay::RelayClient;
use crate::nostr_relay::Subscription;
use futures::future::join_all;
use nostr::nips::nip09::EventDeletionRequest;
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, warn};

/// The `d` tag value for FIPS service advertisements.
const FIPS_SERVICE_TAG: &str = "udp-service-v1/fips";

/// Kind for service advertisements (parameterized replaceable, NIP-78).
const SERVICE_AD_KIND: u16 = 30078;

/// Kind for signaling messages (ephemeral).
const SIGNAL_KIND: u16 = 21059;

/// Per-relay deadline for waiting on an EVENT `OK` response.
const RELAY_PUBLISH_TIMEOUT: Duration = Duration::from_secs(3);

/// Default reason for deleting completed or abandoned signaling events.
pub const SIGNAL_CLEANUP_REASON: &str = "session concluded";

/// Default reason for deleting a responder advertisement at shutdown.
pub const SERVICE_AD_CLEANUP_REASON: &str = "responder offline";

/// Build the stable coordinate for the responder service advertisement.
pub fn service_advertisement_coordinate(pubkey: PublicKey) -> Coordinate {
    Coordinate::new(Kind::Custom(SERVICE_AD_KIND), pubkey).identifier(FIPS_SERVICE_TAG)
}

/// The signaling payload exchanged between initiator and responder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct SignalingPayload {
    /// Whether this is an offer or answer.
    #[serde(rename = "type")]
    pub msg_type: SignalingType,
    /// Random hex string identifying this connection attempt.
    pub session_id: String,
    /// The sender's reflexive address as reported by STUN.
    pub reflexive_addr: String,
    /// The sender's local socket address.
    pub local_addr: String,
    /// Which STUN server was used.
    pub stun_server: String,
    /// Per-session pubkey where the responder should send the answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_pubkey: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
}

/// Whether a signaling payload is an offer or answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignalingType {
    #[serde(rename = "offer")]
    Offer,
    #[serde(rename = "answer")]
    Answer,
}

/// A typed offer used by the initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub session_id: String,
    pub reflexive_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub stun_server: String,
    pub reply_pubkey: PublicKey,
    pub timestamp: u64,
}

/// A typed answer used by the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub session_id: String,
    pub reflexive_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub stun_server: String,
    pub timestamp: u64,
}

/// A typed inbound offer with sender identity metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingOffer {
    pub sender_pubkey: PublicKey,
    pub event_id: EventId,
    pub offer: Offer,
}

/// A parsed responder advertisement discovered on Nostr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    /// The responder's Nostr public key.
    pub peer_pubkey: PublicKey,
    /// STUN servers advertised by the responder.
    pub stun_servers: Vec<String>,
    /// Relay URLs where the responder listens for signaling messages.
    pub relays: Vec<String>,
    /// Signed Nostr creation timestamp.
    pub created_at: Timestamp,
    /// The Nostr event ID of the advertisement.
    pub event_id: EventId,
}

/// Publish a kind 30078 service advertisement.
///
/// Call this **after** [`subscribe_signals`] to avoid a race where an
/// initiator sends an offer before the responder is listening.
///
/// `relay_urls` are embedded in a `relays` tag so the initiator knows
/// where to send signaling messages. `expiration` sets a NIP-40
/// expiration timestamp for automatic garbage collection by relays.
///
/// Returns the published event (useful for later deletion).
pub async fn publish_service_advertisement(
    relays: &[&RelayClient],
    keys: &Keys,
    stun_servers: &[&str],
    relay_urls: &[&str],
    expiration: Option<Timestamp>,
) -> Result<Event, NostrError> {
    let mut builder =
        EventBuilder::new(Kind::Custom(SERVICE_AD_KIND), "").tag(Tag::identifier(FIPS_SERVICE_TAG));

    if !stun_servers.is_empty() {
        builder = builder.tag(Tag::custom(
            TagKind::custom("stun"),
            stun_servers.iter().copied(),
        ));
    }

    if !relay_urls.is_empty() {
        builder = builder.tag(Tag::custom(
            TagKind::custom("relays"),
            relay_urls.iter().copied(),
        ));
    }

    if let Some(expiration) = expiration {
        builder = builder.tag(Tag::expiration(expiration));
    }

    let event = builder
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    debug!(
        "publishing service advertisement: event_id={}, pubkey={}",
        event.id, event.pubkey
    );

    publish_event_all(relays, event, "service advertisement").await
}

/// Publish a kind 30078 service advertisement with a TTL-based expiration tag.
pub async fn publish_service_advertisement_with_ttl(
    relays: &[&RelayClient],
    keys: &Keys,
    stun_servers: &[&str],
    relay_urls: &[&str],
    ttl: Duration,
) -> Result<Event, NostrError> {
    let expiration = Timestamp::from(Timestamp::now().as_secs() + ttl.as_secs());
    publish_service_advertisement(relays, keys, stun_servers, relay_urls, Some(expiration)).await
}

/// Discover a responder's service advertisement (kind 30078).
///
/// Returns the first matching event. Waits for EOSE (end of stored events)
/// to ensure we've seen all available advertisements.
pub async fn discover_service(
    client: &RelayClient,
    responder_pubkey: &PublicKey,
) -> Result<Option<Event>, NostrError> {
    let filter = service_advertisement_filter().author(*responder_pubkey);

    debug!(relay = %client.url(), "discovering service for {responder_pubkey}");

    let mut sub = client.subscribe(vec![filter]).await?;
    sub.wait_for_eose().await?;

    // Try to receive a stored event (should arrive before EOSE).
    // Use a short timeout since EOSE already arrived — if there's an
    // event it's already in the channel.
    let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.next())
        .await
        .ok()
        .flatten();

    sub.close().await?;

    if let Some(ref e) = event {
        debug!(relay = %client.url(), event_id = %e.id, "discovered service advertisement");
    } else {
        debug!(relay = %client.url(), "no service advertisement found for {responder_pubkey}");
    }

    Ok(event)
}

/// Build the base filter for FIPS responder advertisements.
pub fn service_advertisement_filter() -> Filter {
    Filter::new()
        .kind(Kind::Custom(SERVICE_AD_KIND))
        .identifier(FIPS_SERVICE_TAG)
}

/// Discover a responder service advertisement and parse it into a typed struct.
pub async fn discover_service_typed(
    client: &RelayClient,
    responder_pubkey: &PublicKey,
) -> Result<Option<ServiceAdvertisement>, NostrError> {
    discover_service(client, responder_pubkey)
        .await?
        .map(|event| parse_service_advertisement(&event))
        .transpose()
}

/// Try to discover a responder advertisement across multiple relays.
pub async fn discover_service_across_relays(
    relays: &[&RelayClient],
    responder_pubkey: &PublicKey,
) -> Result<ServiceAdvertisement, HolePunchError> {
    for relay in relays {
        match discover_service_typed(relay, responder_pubkey).await {
            Ok(Some(advertisement)) => return Ok(advertisement),
            Ok(None) => continue,
            Err(e) => warn!(relay = %relay.url(), error = %e, "service discovery failed on relay"),
        }
    }

    Err(HolePunchError::AdvertisementNotFound)
}

/// Subscribe for incoming signaling events (kind 21059) addressed to us.
///
/// Returns a subscription that yields offer or answer events.
pub async fn subscribe_signals(
    client: &RelayClient,
    my_pubkey: &PublicKey,
) -> Result<Subscription, NostrError> {
    let filter = Filter::new()
        .kind(Kind::Custom(SIGNAL_KIND))
        .pubkey(*my_pubkey);

    debug!(relay = %client.url(), "subscribing for signals addressed to {my_pubkey}");
    let mut sub = client.subscribe(vec![filter]).await?;
    sub.wait_for_eose().await?;
    Ok(sub)
}

/// Send an offer to the responder (kind 21059).
pub async fn send_offer(
    client: &RelayClient,
    keys: &Keys,
    responder_pubkey: &PublicKey,
    offer: &Offer,
) -> Result<Event, NostrError> {
    let event = build_offer_event(keys, responder_pubkey, offer)?;

    debug!(
        relay = %client.url(),
        "sending offer: session_id={}, event_id={}",
        offer.session_id, event.id
    );

    client
        .publish_with_timeout(event.clone(), RELAY_PUBLISH_TIMEOUT)
        .await?;
    Ok(event)
}

/// Send an offer to all configured relays using the same signed event.
pub async fn send_offer_all(
    relays: &[&RelayClient],
    keys: &Keys,
    responder_pubkey: &PublicKey,
    offer: &Offer,
) -> Result<Event, NostrError> {
    let event = build_offer_event(keys, responder_pubkey, offer)?;

    debug!(
        "sending offer to {} relays: session_id={}, event_id={}",
        relays.len(),
        offer.session_id,
        event.id
    );

    publish_event_all(relays, event, "offer").await
}

/// Send an answer to the initiator (kind 21059).
pub async fn send_answer(
    client: &RelayClient,
    keys: &Keys,
    initiator_pubkey: &PublicKey,
    answer: &Answer,
) -> Result<Event, NostrError> {
    let event = build_answer_event(keys, initiator_pubkey, answer)?;

    debug!(
        relay = %client.url(),
        "sending answer: session_id={}, event_id={}",
        answer.session_id, event.id
    );

    client
        .publish_with_timeout(event.clone(), RELAY_PUBLISH_TIMEOUT)
        .await?;
    Ok(event)
}

/// Send an answer to all configured relays using the same signed event.
pub async fn send_answer_all(
    relays: &[&RelayClient],
    keys: &Keys,
    initiator_pubkey: &PublicKey,
    answer: &Answer,
) -> Result<Event, NostrError> {
    let event = build_answer_event(keys, initiator_pubkey, answer)?;

    debug!(
        "sending answer to {} relays: session_id={}, event_id={}",
        relays.len(),
        answer.session_id,
        event.id
    );

    publish_event_all(relays, event, "answer").await
}

/// Publish a kind 5 deletion request for previously published signaling events.
pub async fn publish_deletion_event(
    relays: &[&RelayClient],
    keys: &Keys,
    event_ids: &[EventId],
    reason: &str,
) -> Result<Event, NostrError> {
    if event_ids.is_empty() {
        return Err(NostrError::InvalidEvent(
            "deletion request requires at least one event id".into(),
        ));
    }

    let mut request = EventDeletionRequest::new().ids(event_ids.iter().copied());
    if !reason.is_empty() {
        request = request.reason(reason);
    }

    let event = EventBuilder::delete(request)
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    debug!(
        event_id = %event.id,
        targets = event_ids.len(),
        "publishing deletion request"
    );

    publish_event_all(relays, event, "deletion request").await
}

/// Publish a kind 5 deletion request for the responder service advertisement.
pub async fn delete_service_advertisement(
    relays: &[&RelayClient],
    keys: &Keys,
    reason: &str,
) -> Result<Event, NostrError> {
    let coordinate = service_advertisement_coordinate(keys.public_key());
    let mut request = EventDeletionRequest::new().coordinate(coordinate);
    if !reason.is_empty() {
        request = request.reason(reason);
    }

    let event = EventBuilder::delete(request)
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    debug!(event_id = %event.id, "publishing service advertisement deletion request");

    publish_event_all(relays, event, "service advertisement deletion").await
}

async fn publish_event_all(
    relays: &[&RelayClient],
    event: Event,
    event_type: &str,
) -> Result<Event, NostrError> {
    if relays.is_empty() {
        return Err(NostrError::InvalidEvent(format!(
            "no relays configured for {event_type} publish"
        )));
    }

    let results = join_all(relays.iter().map(|relay| {
        let relay_url = relay.url().to_string();
        let event = event.clone();
        async move {
            match relay.publish_with_timeout(event, RELAY_PUBLISH_TIMEOUT).await {
                Ok(()) => Ok(relay_url),
                Err(err) => Err((relay_url, err)),
            }
        }
    }))
    .await;

    let mut accepted = 0usize;
    let mut failures = Vec::new();

    for result in results {
        match result {
            Ok(_relay_url) => {
                accepted += 1;
            }
            Err((relay_url, err)) => {
                warn!(
                    relay = %relay_url,
                    event_id = %event.id,
                    event_type,
                    error = %err,
                    "relay publish failed"
                );
                failures.push(format!("{relay_url}: {err}"));
            }
        }
    }

    if accepted > 0 {
        debug!(
            event_type,
            event_id = %event.id,
            accepted,
            total = relays.len(),
            failed = failures.len(),
            "published event to relays"
        );
        Ok(event)
    } else {
        Err(NostrError::Rejected {
            relay: "all relays".into(),
            message: failures.join("; "),
        })
    }
}

/// Parse a typed inbound offer from a gift-wrapped event.
///
/// Unwraps the NIP-59 gift wrap, verifies the seal, and extracts the
/// offer payload. The sender's real public key comes from the seal,
/// not the outer event (which uses an ephemeral key).
pub fn parse_offer_event(keys: &Keys, event: &Event) -> Result<IncomingOffer, NostrError> {
    let (sender_pubkey, payload) = unwrap_signal_event(keys, event)?;
    let offer = payload_to_offer(payload)?;
    Ok(IncomingOffer {
        sender_pubkey,
        event_id: event.id,
        offer,
    })
}

/// Parse a typed answer from a gift-wrapped event.
///
/// Unwraps the NIP-59 gift wrap, verifies the seal, and extracts the
/// answer payload. Returns both the sender's real public key and the
/// answer so the caller can verify the sender identity.
pub fn parse_answer_event(
    keys: &Keys,
    event: &Event,
) -> Result<(PublicKey, Answer), NostrError> {
    let (sender_pubkey, payload) = unwrap_signal_event(keys, event)?;
    let answer = payload_to_answer(payload)?;
    Ok((sender_pubkey, answer))
}

/// Parse a typed responder advertisement from a raw Nostr event.
pub fn parse_service_advertisement(event: &Event) -> Result<ServiceAdvertisement, NostrError> {
    if event.kind != Kind::Custom(SERVICE_AD_KIND) {
        return Err(NostrError::InvalidEvent(format!(
            "expected service advertisement kind {}, got {}",
            SERVICE_AD_KIND,
            event.kind.as_u16()
        )));
    }

    let has_service_tag = event.tags.iter().any(|tag| {
        tag.kind() == TagKind::d()
            && tag
                .content()
                .is_some_and(|content| content == FIPS_SERVICE_TAG)
    });
    if !has_service_tag {
        return Err(NostrError::InvalidEvent(
            "missing or incorrect service identifier tag".into(),
        ));
    }

    Ok(ServiceAdvertisement {
        peer_pubkey: event.pubkey,
        stun_servers: extract_stun_servers(event),
        relays: extract_relays(event),
        created_at: event.created_at,
        event_id: event.id,
    })
}

/// Extract STUN server addresses from a service advertisement event.
///
/// The `stun` tag is a single tag with multiple values:
/// `["stun", "server1:3478", "server2:3478"]`. Returns all values
/// after the tag name.
pub fn extract_stun_servers(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("stun"))
        .map(|t| {
            t.as_slice()
                .iter()
                .skip(1) // skip the tag name "stun"
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Extract relay URLs from a service advertisement event.
///
/// The `relays` tag is a single tag with multiple values:
/// `["relays", "wss://relay1", "wss://relay2"]`. Returns all values
/// after the tag name.
fn extract_relays(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::custom("relays"))
        .map(|t| {
            t.as_slice()
                .iter()
                .skip(1) // skip the tag name "relays"
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn build_offer_event(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    offer: &Offer,
) -> Result<Event, NostrError> {
    build_gift_wrapped_signal(keys, recipient_pubkey, &offer_to_payload(offer))
}

fn build_answer_event(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    answer: &Answer,
) -> Result<Event, NostrError> {
    build_gift_wrapped_signal(keys, recipient_pubkey, &answer_to_payload(answer))
}

/// Build a NIP-59 gift-wrapped signaling event (kind 21059).
///
/// Three layers:
/// 1. Rumor (unsigned, kind 21059) — the JSON payload.
/// 2. Seal (kind 13, signed by `keys`) — NIP-44 encrypts the rumor.
/// 3. Outer wrap (kind 21059, signed by ephemeral key) — NIP-44 encrypts
///    the seal. Carries `p` tag + `expiration` tag (120 s).
fn build_gift_wrapped_signal(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    payload: &SignalingPayload,
) -> Result<Event, NostrError> {
    let content =
        serde_json::to_string(payload).map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    // Layer 1: Rumor (unsigned event with the plaintext payload).
    let mut rumor = EventBuilder::new(Kind::Custom(SIGNAL_KIND), &content)
        .tag(Tag::public_key(*recipient_pubkey))
        .build(keys.public_key());
    rumor.ensure_id();

    // Layer 2: Seal (encrypt rumor to recipient, sign with our real keys).
    let encrypted_rumor = nip44::encrypt(
        keys.secret_key(),
        recipient_pubkey,
        rumor.as_json(),
        nip44::Version::default(),
    )
    .map_err(|e| NostrError::InvalidEvent(format!("NIP-44 seal encrypt: {e}")))?;

    let seal = EventBuilder::new(Kind::Seal, encrypted_rumor)
        .custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(format!("seal sign: {e}")))?;

    // Layer 3: Outer gift wrap (encrypt seal to recipient, sign with
    // ephemeral key). Uses kind 21059 (ephemeral) instead of standard 1059.
    let ephemeral_keys = Keys::generate();
    let encrypted_seal = nip44::encrypt(
        ephemeral_keys.secret_key(),
        recipient_pubkey,
        seal.as_json(),
        nip44::Version::default(),
    )
    .map_err(|e| NostrError::InvalidEvent(format!("NIP-44 wrap encrypt: {e}")))?;

    let expiration = Timestamp::from(Timestamp::now().as_secs() + 120);

    EventBuilder::new(Kind::Custom(SIGNAL_KIND), encrypted_seal)
        .tag(Tag::public_key(*recipient_pubkey))
        .tag(Tag::expiration(expiration))
        .custom_created_at(Timestamp::now())
        .sign_with_keys(&ephemeral_keys)
        .map_err(|e| NostrError::InvalidEvent(format!("wrap sign: {e}")))
}

/// Unwrap a NIP-59 gift-wrapped signaling event and extract the payload.
///
/// Returns the real sender's public key (from the seal) and the parsed
/// signaling payload (from the rumor).
fn unwrap_signal_event(
    keys: &Keys,
    event: &Event,
) -> Result<(PublicKey, SignalingPayload), NostrError> {
    // Decrypt the seal from the outer gift wrap.
    let seal_json = nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content)
        .map_err(|e| NostrError::InvalidEvent(format!("NIP-44 wrap decrypt: {e}")))?;

    let seal = Event::from_json(&seal_json)
        .map_err(|e| NostrError::InvalidEvent(format!("invalid seal event: {e}")))?;
    seal.verify()
        .map_err(|e| NostrError::InvalidEvent(format!("seal signature invalid: {e}")))?;

    if seal.kind != Kind::Seal {
        return Err(NostrError::InvalidEvent(format!(
            "expected seal kind 13, got {}",
            seal.kind.as_u16()
        )));
    }

    // Decrypt the rumor from the seal.
    let rumor_json = nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)
        .map_err(|e| NostrError::InvalidEvent(format!("NIP-44 rumor decrypt: {e}")))?;

    let rumor = UnsignedEvent::from_json(&rumor_json)
        .map_err(|e| NostrError::InvalidEvent(format!("invalid rumor event: {e}")))?;

    // Verify sender consistency: rumor author must match seal signer.
    if rumor.pubkey != seal.pubkey {
        return Err(NostrError::InvalidEvent(
            "rumor pubkey does not match seal signer".into(),
        ));
    }

    let payload: SignalingPayload = serde_json::from_str(&rumor.content)
        .map_err(|e| NostrError::InvalidEvent(format!("invalid signaling payload: {e}")))?;

    Ok((seal.pubkey, payload))
}

fn offer_to_payload(offer: &Offer) -> SignalingPayload {
    SignalingPayload {
        msg_type: SignalingType::Offer,
        session_id: offer.session_id.clone(),
        reflexive_addr: offer.reflexive_addr.to_string(),
        local_addr: offer.local_addr.to_string(),
        stun_server: offer.stun_server.clone(),
        reply_pubkey: Some(offer.reply_pubkey.to_string()),
        timestamp: offer.timestamp,
    }
}

fn answer_to_payload(answer: &Answer) -> SignalingPayload {
    SignalingPayload {
        msg_type: SignalingType::Answer,
        session_id: answer.session_id.clone(),
        reflexive_addr: answer.reflexive_addr.to_string(),
        local_addr: answer.local_addr.to_string(),
        stun_server: answer.stun_server.clone(),
        reply_pubkey: None,
        timestamp: answer.timestamp,
    }
}

fn payload_to_offer(payload: SignalingPayload) -> Result<Offer, NostrError> {
    if payload.msg_type != SignalingType::Offer {
        return Err(NostrError::InvalidEvent(format!(
            "expected offer payload, got {:?}",
            payload.msg_type
        )));
    }

    Ok(Offer {
        session_id: payload.session_id,
        reflexive_addr: parse_socket_addr(&payload.reflexive_addr, "offer reflexive_addr")?,
        local_addr: parse_socket_addr(&payload.local_addr, "offer local_addr")?,
        stun_server: payload.stun_server,
        reply_pubkey: parse_public_key(
            payload
                .reply_pubkey
                .as_deref()
                .ok_or_else(|| NostrError::InvalidEvent("offer missing reply_pubkey".into()))?,
            "offer reply_pubkey",
        )?,
        timestamp: payload.timestamp,
    })
}

fn payload_to_answer(payload: SignalingPayload) -> Result<Answer, NostrError> {
    if payload.msg_type != SignalingType::Answer {
        return Err(NostrError::InvalidEvent(format!(
            "expected answer payload, got {:?}",
            payload.msg_type
        )));
    }

    Ok(Answer {
        session_id: payload.session_id,
        reflexive_addr: parse_socket_addr(&payload.reflexive_addr, "answer reflexive_addr")?,
        local_addr: parse_socket_addr(&payload.local_addr, "answer local_addr")?,
        stun_server: payload.stun_server,
        timestamp: payload.timestamp,
    })
}

fn parse_socket_addr(addr: &str, field: &str) -> Result<SocketAddr, NostrError> {
    addr.parse()
        .map_err(|e| NostrError::InvalidEvent(format!("invalid {field} '{addr}': {e}")))
}

fn parse_public_key(pubkey: &str, field: &str) -> Result<PublicKey, NostrError> {
    PublicKey::parse(pubkey)
        .map_err(|e| NostrError::InvalidEvent(format!("invalid {field} '{pubkey}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_relay::init_test_logging;
    use crate::nostr_relay::test_relay::TestRelay;
    use std::time::Duration;
    use tokio::time::timeout;

    fn make_offer(session_id: &str, reply_pubkey: PublicKey) -> Offer {
        Offer {
            session_id: session_id.to_string(),
            reflexive_addr: "1.2.3.4:5678".parse().unwrap(),
            local_addr: "192.168.1.10:5678".parse().unwrap(),
            stun_server: "stun.example.com:3478".to_string(),
            reply_pubkey,
            timestamp: 1700000000,
        }
    }

    fn make_answer(session_id: &str) -> Answer {
        Answer {
            session_id: session_id.to_string(),
            reflexive_addr: "5.6.7.8:9012".parse().unwrap(),
            local_addr: "192.168.2.20:9012".parse().unwrap(),
            stun_server: "stun.example.com:3478".to_string(),
            timestamp: 1700000001,
        }
    }

    #[tokio::test]
    async fn service_advertisement_roundtrip() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();

        let responder_keys = Keys::generate();

        // Publish a service advertisement.
        publish_service_advertisement(
            &[&client],
            &responder_keys,
            &["stun.example.com:3478"],
            &["wss://relay1.example.com", "wss://relay2.example.com"],
            None,
        )
        .await
        .unwrap();

        // Discover it from the same relay.
        let discovered = discover_service_typed(&client, &responder_keys.public_key())
            .await
            .unwrap();

        assert!(discovered.is_some(), "should find the advertisement");
        let ad = discovered.unwrap();
        assert_eq!(ad.peer_pubkey, responder_keys.public_key());
        assert_eq!(ad.stun_servers, vec!["stun.example.com:3478".to_string()]);
        assert_eq!(
            ad.relays,
            vec![
                "wss://relay1.example.com".to_string(),
                "wss://relay2.example.com".to_string(),
            ]
        );

        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn publish_service_advertisement_succeeds_if_one_relay_accepts() {
        init_test_logging();

        let accepting = TestRelay::start().await;
        let rejecting = TestRelay::start_rejecting_events("rate-limited").await;
        let accepting_client = RelayClient::connect(accepting.url()).await.unwrap();
        let rejecting_client = RelayClient::connect(rejecting.url()).await.unwrap();
        let responder_keys = Keys::generate();

        let event = publish_service_advertisement(
            &[&accepting_client, &rejecting_client],
            &responder_keys,
            &["stun.example.com:3478"],
            &[],
            None,
        )
        .await
        .unwrap();

        let discovered = discover_service_typed(&accepting_client, &responder_keys.public_key())
            .await
            .unwrap();
        assert!(discovered.is_some());
        assert_eq!(event.kind, Kind::Custom(SERVICE_AD_KIND));

        accepting_client.disconnect().await;
        rejecting_client.disconnect().await;
        accepting.shutdown().await;
        rejecting.shutdown().await;
    }

    #[tokio::test]
    async fn publish_deletion_event_creates_kind5_request() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();
        let referenced_a =
            EventId::parse("00000000000000000000000000000000000000000000000000000000000000aa")
                .unwrap();
        let referenced_b =
            EventId::parse("00000000000000000000000000000000000000000000000000000000000000bb")
                .unwrap();

        let event = publish_deletion_event(
            &[&client],
            &keys,
            &[referenced_a, referenced_b],
            SIGNAL_CLEANUP_REASON,
        )
        .await
        .unwrap();

        assert_eq!(event.kind, Kind::EventDeletion);
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.content, SIGNAL_CLEANUP_REASON);
        assert_eq!(event.tags.iter().filter(|tag| tag.kind() == TagKind::e()).count(), 2);

        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .author(keys.public_key());
        let mut sub = client.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        let stored = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out waiting for stored deletion event")
            .expect("subscription closed");
        assert_eq!(stored.id, event.id);

        sub.close().await.unwrap();
        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn delete_service_advertisement_creates_coordinate_deletion_request() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();
        let keys = Keys::generate();

        let event = delete_service_advertisement(&[&client], &keys, SERVICE_AD_CLEANUP_REASON)
            .await
            .unwrap();

        assert_eq!(event.kind, Kind::EventDeletion);
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.content, SERVICE_AD_CLEANUP_REASON);
        assert_eq!(event.tags.iter().filter(|tag| tag.kind() == TagKind::a()).count(), 1);

        let coordinate = event
            .tags
            .coordinates()
            .next()
            .expect("missing coordinate tag");
        assert_eq!(coordinate.kind, Kind::Custom(SERVICE_AD_KIND));
        assert_eq!(coordinate.public_key, keys.public_key());
        assert_eq!(coordinate.identifier, FIPS_SERVICE_TAG);

        let filter = Filter::new()
            .kind(Kind::EventDeletion)
            .author(keys.public_key());
        let mut sub = client.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        let stored = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out waiting for stored advertisement deletion event")
            .expect("subscription closed");
        assert_eq!(stored.id, event.id);

        sub.close().await.unwrap();
        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn offer_answer_exchange() {
        init_test_logging();

        let relay = TestRelay::start().await;

        let initiator_keys = Keys::generate();
        let responder_keys = Keys::generate();
        let reply_keys = Keys::generate();

        // Both peers connect to the relay.
        let initiator_client = RelayClient::connect(relay.url()).await.unwrap();
        let responder_client = RelayClient::connect(relay.url()).await.unwrap();

        // --- Responder setup (order matters!) ---
        // 1. Subscribe for signals FIRST.
        let mut responder_sub = subscribe_signals(&responder_client, &responder_keys.public_key())
            .await
            .unwrap();

        // 2. Then publish service advertisement.
        publish_service_advertisement(
            &[&responder_client],
            &responder_keys,
            &["stun.example.com:3478"],
            &[],
            None,
        )
        .await
        .unwrap();

        // --- Initiator discovers and sends offer ---
        let discovered = discover_service_typed(&initiator_client, &responder_keys.public_key())
            .await
            .unwrap();
        assert!(discovered.is_some(), "initiator should find the service");

        let session_id = "deadbeef12345678deadbeef12345678";
        let offer = make_offer(session_id, reply_keys.public_key());

        send_offer(
            &initiator_client,
            &initiator_keys,
            &responder_keys.public_key(),
            &offer,
        )
        .await
        .unwrap();

        // --- Responder receives offer ---
        let offer_event = timeout(Duration::from_secs(2), responder_sub.next())
            .await
            .expect("responder timed out waiting for offer")
            .expect("responder subscription closed");

        let received_offer = parse_offer_event(&responder_keys, &offer_event).unwrap();
        assert_eq!(received_offer.sender_pubkey, initiator_keys.public_key());
        assert_eq!(received_offer.offer.session_id, session_id);
        assert_eq!(received_offer.offer.reflexive_addr, "1.2.3.4:5678".parse::<SocketAddr>().unwrap());
        assert_eq!(received_offer.offer.reply_pubkey, reply_keys.public_key());

        // --- Responder sends answer ---
        // First subscribe for the answer on the initiator reply pubkey.
        let mut initiator_sub = subscribe_signals(&initiator_client, &reply_keys.public_key())
            .await
            .unwrap();

        let answer = make_answer(session_id);
        send_answer(
            &responder_client,
            &responder_keys,
            &reply_keys.public_key(),
            &answer,
        )
        .await
        .unwrap();

        // --- Initiator receives answer ---
        let answer_event = timeout(Duration::from_secs(2), initiator_sub.next())
            .await
            .expect("initiator timed out waiting for answer")
            .expect("initiator subscription closed");

        let reply_pubkey = reply_keys.public_key().to_string();
        assert_eq!(
            answer_event
                .tags
                .iter()
                .find(|tag| tag.kind() == TagKind::p())
                .and_then(|tag| tag.content()),
            Some(reply_pubkey.as_str())
        );

        let (answer_sender, received_answer) = parse_answer_event(&reply_keys, &answer_event).unwrap();
        assert_eq!(answer_sender, responder_keys.public_key());
        assert_eq!(received_answer.session_id, session_id);
        assert_eq!(received_answer.reflexive_addr, "5.6.7.8:9012".parse::<SocketAddr>().unwrap());

        // Cleanup.
        responder_sub.close().await.unwrap();
        initiator_sub.close().await.unwrap();
        initiator_client.disconnect().await;
        responder_client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn send_offer_all_succeeds_if_one_relay_accepts() {
        init_test_logging();

        let accepting = TestRelay::start().await;
        let rejecting = TestRelay::start_rejecting_events("rate-limited").await;
        let accepting_client = RelayClient::connect(accepting.url()).await.unwrap();
        let rejecting_client = RelayClient::connect(rejecting.url()).await.unwrap();

        let initiator_keys = Keys::generate();
        let responder_keys = Keys::generate();
        let reply_keys = Keys::generate();
        let offer = make_offer("offer-partial-success", reply_keys.public_key());

        let event = send_offer_all(
            &[&accepting_client, &rejecting_client],
            &initiator_keys,
            &responder_keys.public_key(),
            &offer,
        )
        .await
        .unwrap();

        let discovered = discover_service_typed(&accepting_client, &responder_keys.public_key())
            .await
            .unwrap();
        assert!(discovered.is_none(), "offer is ephemeral and should not be stored");
        assert_eq!(event.kind, Kind::Custom(SIGNAL_KIND));

        accepting_client.disconnect().await;
        rejecting_client.disconnect().await;
        accepting.shutdown().await;
        rejecting.shutdown().await;
    }

    #[tokio::test]
    async fn send_answer_all_fails_if_all_relays_reject() {
        init_test_logging();

        let reject_a = TestRelay::start_rejecting_events("rate-limited-a").await;
        let reject_b = TestRelay::start_rejecting_events("rate-limited-b").await;
        let client_a = RelayClient::connect(reject_a.url()).await.unwrap();
        let client_b = RelayClient::connect(reject_b.url()).await.unwrap();

        let responder_keys = Keys::generate();
        let initiator_keys = Keys::generate();
        let answer = make_answer("answer-all-reject");

        let err = send_answer_all(
            &[&client_a, &client_b],
            &responder_keys,
            &initiator_keys.public_key(),
            &answer,
        )
        .await
        .unwrap_err();

        let text = err.to_string();
        assert!(text.contains(reject_a.url()));
        assert!(text.contains(reject_b.url()));

        client_a.disconnect().await;
        client_b.disconnect().await;
        reject_a.shutdown().await;
        reject_b.shutdown().await;
    }

    #[test]
    fn outer_signal_event_uses_current_timestamp_and_future_expiration() {
        let initiator_keys = Keys::generate();
        let responder_keys = Keys::generate();
        let reply_keys = Keys::generate();
        let offer = make_offer("timestamp-check", reply_keys.public_key());

        let before = Timestamp::now();
        let event = build_offer_event(&initiator_keys, &responder_keys.public_key(), &offer).unwrap();
        let after = Timestamp::now();

        assert_eq!(event.kind, Kind::Custom(SIGNAL_KIND));
        assert!(event.created_at >= before);
        assert!(event.created_at <= after);

        let expiration = event.tags.expiration().copied().expect("missing expiration tag");
        assert!(expiration > event.created_at);
        assert!(expiration.as_secs() - event.created_at.as_secs() <= 120);
        assert!(!event.is_expired());
    }
}
