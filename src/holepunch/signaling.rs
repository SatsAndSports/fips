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
//! Currently uses plaintext signaling events. NIP-44 encryption and
//! NIP-59 gift wrapping will be added later.

use super::HolePunchError;
use crate::nostr_relay::NostrError;
use crate::nostr_relay::RelayClient;
use crate::nostr_relay::Subscription;
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{debug, warn};

/// The `d` tag value for FIPS service advertisements.
const FIPS_SERVICE_TAG: &str = "udp-service-v1/fips";

/// Kind for service advertisements (parameterized replaceable, NIP-78).
const SERVICE_AD_KIND: u16 = 30078;

/// Kind for signaling messages (ephemeral).
const SIGNAL_KIND: u16 = 21059;

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
    /// The Nostr event ID of the advertisement.
    pub event_id: EventId,
}

/// Publish a kind 30078 service advertisement.
///
/// Call this **after** [`subscribe_signals`] to avoid a race where an
/// initiator sends an offer before the responder is listening.
///
/// Returns the published event (useful for later deletion).
pub async fn publish_service_advertisement(
    relays: &[&RelayClient],
    keys: &Keys,
    stun_servers: &[&str],
) -> Result<Event, NostrError> {
    let mut builder =
        EventBuilder::new(Kind::Custom(SERVICE_AD_KIND), "").tag(Tag::identifier(FIPS_SERVICE_TAG));

    for stun in stun_servers {
        builder = builder.tag(Tag::custom(TagKind::custom("stun"), [*stun]));
    }

    let event = builder
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    debug!(
        "publishing service advertisement: event_id={}, pubkey={}",
        event.id, event.pubkey
    );

    for relay in relays {
        relay.publish(event.clone()).await?;
    }

    Ok(event)
}

/// Discover a responder's service advertisement (kind 30078).
///
/// Returns the first matching event. Waits for EOSE (end of stored events)
/// to ensure we've seen all available advertisements.
pub async fn discover_service(
    client: &RelayClient,
    responder_pubkey: &PublicKey,
) -> Result<Option<Event>, NostrError> {
    let filter = Filter::new()
        .kind(Kind::Custom(SERVICE_AD_KIND))
        .author(*responder_pubkey)
        .identifier(FIPS_SERVICE_TAG);

    debug!("discovering service for {responder_pubkey}");

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
        debug!("discovered service advertisement: event_id={}", e.id);
    } else {
        debug!("no service advertisement found for {responder_pubkey}");
    }

    Ok(event)
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
            Err(e) => warn!(error = %e, "service discovery failed on one relay"),
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

    debug!("subscribing for signals addressed to {my_pubkey}");
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
        "sending offer: session_id={}, event_id={}",
        offer.session_id, event.id
    );

    client.publish(event.clone()).await?;
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

    for relay in relays {
        relay.publish(event.clone()).await?;
    }

    Ok(event)
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
        "sending answer: session_id={}, event_id={}",
        answer.session_id, event.id
    );

    client.publish(event.clone()).await?;
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

    for relay in relays {
        relay.publish(event.clone()).await?;
    }

    Ok(event)
}

/// Parse a typed inbound offer from an incoming event.
pub fn parse_offer_event(event: &Event) -> Result<IncomingOffer, NostrError> {
    let payload = parse_signal_payload(event)?;
    let offer = payload_to_offer(payload)?;
    Ok(IncomingOffer {
        sender_pubkey: event.pubkey,
        event_id: event.id,
        offer,
    })
}

/// Parse a typed answer from an incoming event.
pub fn parse_answer_event(event: &Event) -> Result<Answer, NostrError> {
    let payload = parse_signal_payload(event)?;
    payload_to_answer(payload)
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
        event_id: event.id,
    })
}

/// Extract STUN server addresses from a service advertisement event.
///
/// Returns the values of all `stun` tags in the event. The initiator
/// picks one to query for its reflexive address.
pub fn extract_stun_servers(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.kind() == TagKind::custom("stun"))
        .filter_map(|t| t.content().map(|s| s.to_string()))
        .collect()
}

fn build_offer_event(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    offer: &Offer,
) -> Result<Event, NostrError> {
    build_signal_event(keys, recipient_pubkey, &offer_to_payload(offer))
}

fn build_answer_event(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    answer: &Answer,
) -> Result<Event, NostrError> {
    build_signal_event(keys, recipient_pubkey, &answer_to_payload(answer))
}

fn build_signal_event(
    keys: &Keys,
    recipient_pubkey: &PublicKey,
    payload: &SignalingPayload,
) -> Result<Event, NostrError> {
    let content =
        serde_json::to_string(payload).map_err(|e| NostrError::InvalidEvent(e.to_string()))?;

    EventBuilder::new(Kind::Custom(SIGNAL_KIND), &content)
        .tag(Tag::public_key(*recipient_pubkey))
        .sign_with_keys(keys)
        .map_err(|e| NostrError::InvalidEvent(e.to_string()))
}

fn parse_signal_payload(event: &Event) -> Result<SignalingPayload, NostrError> {
    serde_json::from_str(&event.content)
        .map_err(|e| NostrError::InvalidEvent(format!("invalid signaling payload: {e}")))
}

fn offer_to_payload(offer: &Offer) -> SignalingPayload {
    SignalingPayload {
        msg_type: SignalingType::Offer,
        session_id: offer.session_id.clone(),
        reflexive_addr: offer.reflexive_addr.to_string(),
        local_addr: offer.local_addr.to_string(),
        stun_server: offer.stun_server.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_relay::init_test_logging;
    use crate::nostr_relay::test_relay::TestRelay;
    use std::time::Duration;
    use tokio::time::timeout;

    fn make_offer(session_id: &str) -> Offer {
        Offer {
            session_id: session_id.to_string(),
            reflexive_addr: "1.2.3.4:5678".parse().unwrap(),
            local_addr: "192.168.1.10:5678".parse().unwrap(),
            stun_server: "stun.example.com:3478".to_string(),
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
        publish_service_advertisement(&[&client], &responder_keys, &["stun.example.com:3478"])
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

        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn offer_answer_exchange() {
        init_test_logging();

        let relay = TestRelay::start().await;

        let initiator_keys = Keys::generate();
        let responder_keys = Keys::generate();

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
        )
        .await
        .unwrap();

        // --- Initiator discovers and sends offer ---
        let discovered = discover_service_typed(&initiator_client, &responder_keys.public_key())
            .await
            .unwrap();
        assert!(discovered.is_some(), "initiator should find the service");

        let session_id = "deadbeef12345678deadbeef12345678";
        let offer = make_offer(session_id);

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

        let received_offer = parse_offer_event(&offer_event).unwrap();
        assert_eq!(received_offer.sender_pubkey, initiator_keys.public_key());
        assert_eq!(received_offer.offer.session_id, session_id);
        assert_eq!(received_offer.offer.reflexive_addr, "1.2.3.4:5678".parse::<SocketAddr>().unwrap());

        // --- Responder sends answer ---
        // First subscribe for the answer on the initiator side.
        let mut initiator_sub = subscribe_signals(&initiator_client, &initiator_keys.public_key())
            .await
            .unwrap();

        let answer = make_answer(session_id);
        send_answer(
            &responder_client,
            &responder_keys,
            &initiator_keys.public_key(),
            &answer,
        )
        .await
        .unwrap();

        // --- Initiator receives answer ---
        let answer_event = timeout(Duration::from_secs(2), initiator_sub.next())
            .await
            .expect("initiator timed out waiting for answer")
            .expect("initiator subscription closed");

        let received_answer = parse_answer_event(&answer_event).unwrap();
        assert_eq!(received_answer.session_id, session_id);
        assert_eq!(received_answer.reflexive_addr, "5.6.7.8:9012".parse::<SocketAddr>().unwrap());

        // Cleanup.
        responder_sub.close().await.unwrap();
        initiator_sub.close().await.unwrap();
        initiator_client.disconnect().await;
        responder_client.disconnect().await;
        relay.shutdown().await;
    }
}
