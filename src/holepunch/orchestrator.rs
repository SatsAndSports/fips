//! Reusable orchestration helpers for Nostr-signaled UDP hole punching.
//!
//! These helpers sit above the packet/signaling primitives and below the demo
//! binary. They are intended to be the first reusable library boundary before
//! integrating hole punching into the wider FIPS transport system.

use super::HolePunchError;
use super::punch::{DEFAULT_PROBE_INTERVAL, DEFAULT_PUNCH_TIMEOUT, run_punch};
use super::signaling::{
    Answer, IncomingOffer, Offer, ServiceAdvertisement, parse_answer_event, parse_offer_event,
    publish_deletion_event, send_answer_all, send_offer_all, subscribe_signals,
    SIGNAL_CLEANUP_REASON,
};
use crate::nostr_relay::{RelayClient, Subscription};
use crate::stun::stun_query_any;
use nostr::prelude::*;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Maximum age for an offer/answer payload before we consider it stale.
const SIGNAL_MAX_AGE: Duration = Duration::from_secs(60);

/// Configuration for the orchestration layer.
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Maximum time to wait for an answer or incoming signal.
    pub signal_timeout: Duration,
    /// Per-STUN-server timeout when trying multiple servers.
    pub stun_attempt_timeout: Duration,
    /// Interval between punch probes.
    pub probe_interval: Duration,
    /// Maximum time to spend in the punch phase.
    pub punch_timeout: Duration,
    /// Maximum initiator attempts per call, including the first attempt.
    pub max_attempts: usize,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            signal_timeout: Duration::from_secs(10),
            stun_attempt_timeout: Duration::from_secs(2),
            probe_interval: DEFAULT_PROBE_INTERVAL,
            punch_timeout: DEFAULT_PUNCH_TIMEOUT,
            max_attempts: 2,
        }
    }
}

/// Metadata describing a ready punched UDP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchedPath {
    /// The remote peer's public key.
    pub peer_pubkey: PublicKey,
    /// The peer's punched UDP address.
    pub peer_addr: SocketAddr,
    /// Session ID used for signaling and punch packets.
    pub session_id: String,
    /// Our own reflexive address as reported by STUN.
    pub local_reflexive_addr: SocketAddrV4,
    /// Which STUN server succeeded.
    pub used_stun_server: String,
}

/// Subscribe for incoming signals on all relays.
pub async fn subscribe_signals_all(
    relays: &[&RelayClient],
    my_pubkey: PublicKey,
) -> Result<Vec<Subscription>, HolePunchError> {
    let mut subscriptions = Vec::with_capacity(relays.len());
    let mut last_err = None;

    for relay in relays {
        match subscribe_signals(relay, &my_pubkey).await {
            Ok(sub) => subscriptions.push(sub),
            Err(err) => {
                warn!(relay = %relay.url(), error = %err, "failed to subscribe for signals on relay");
                last_err = Some(err);
            }
        }
    }

    if subscriptions.is_empty() {
        return Err(last_err
            .map(HolePunchError::from)
            .unwrap_or(HolePunchError::AllSubscriptionsClosed));
    }

    Ok(subscriptions)
}

/// Wait for the first signal across multiple relay subscriptions.
pub async fn wait_for_first_signal(
    subscriptions: &mut [Subscription],
    timeout_duration: Option<Duration>,
) -> Result<Event, HolePunchError> {
    if subscriptions.is_empty() {
        return Err(HolePunchError::AllSubscriptionsClosed);
    }

    let deadline = timeout_duration.map(|duration| Instant::now() + duration);
    let poll_step = Duration::from_millis(50);

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            return Err(HolePunchError::Timeout(
                timeout_duration.expect("deadline implies timeout duration"),
            ));
        }

        let mut any_open = false;
        for sub in subscriptions.iter_mut() {
            match timeout(poll_step, sub.next_with_source()).await {
                Ok(Some((relay, event))) => {
                    debug!(relay = %relay, event_id = %event.id, author = %event.pubkey, "received signal event");
                    return Ok(event);
                }
                Ok(None) => continue,
                Err(_) => any_open = true,
            }
        }

        if !any_open {
            return Err(HolePunchError::AllSubscriptionsClosed);
        }
    }
}

/// Initiate a punch from a discovered responder advertisement using an already
/// bound UDP socket.
pub async fn initiate_from_advertisement(
    socket: &UdpSocket,
    relays: &[&RelayClient],
    keys: &Keys,
    advertisement: &ServiceAdvertisement,
    config: &HolePunchConfig,
) -> Result<PunchedPath, HolePunchError> {
    if advertisement.stun_servers.is_empty() {
        return Err(HolePunchError::NoStunServers);
    }

    let max_attempts = config.max_attempts.max(1);
    let mut last_timeout = None;

    for attempt in 1..=max_attempts {
        match initiate_single_attempt_from_advertisement(socket, relays, keys, advertisement, config)
            .await
        {
            Ok(path) => return Ok(path),
            Err(HolePunchError::Timeout(duration)) if attempt < max_attempts => {
                warn!(attempt, max_attempts, timeout = ?duration, "initiator attempt timed out; retrying");
                last_timeout = Some(duration);
            }
            Err(err) => return Err(err),
        }
    }

    Err(HolePunchError::Timeout(last_timeout.expect(
        "initiator retries should record the last timeout",
    )))
}

async fn initiate_single_attempt_from_advertisement(
    socket: &UdpSocket,
    relays: &[&RelayClient],
    keys: &Keys,
    advertisement: &ServiceAdvertisement,
    config: &HolePunchConfig,
) -> Result<PunchedPath, HolePunchError> {

    let (local_reflexive_addr, used_stun_server) = query_stun_with_failover(
        socket,
        &advertisement.stun_servers,
        config.stun_attempt_timeout,
    )
    .await?;

    let mut published_offer_ids = Vec::with_capacity(1);

    let result = async {
        let session_id = hex::encode(rand::random::<[u8; 16]>());
        let reply_keys = Keys::generate();
        let mut subscriptions = subscribe_signals_all(relays, reply_keys.public_key()).await?;
        let result = async {
            let offer = Offer {
                session_id: session_id.clone(),
                reflexive_addr: SocketAddr::V4(local_reflexive_addr),
                local_addr: socket.local_addr()?,
                stun_server: used_stun_server.clone(),
                reply_pubkey: reply_keys.public_key(),
                timestamp: Timestamp::now().as_secs(),
            };

            let offer_event = send_offer_all(relays, keys, &advertisement.peer_pubkey, &offer).await?;
            published_offer_ids.push(offer_event.id);

            loop {
                let answer_event = wait_for_first_signal(&mut subscriptions, Some(config.signal_timeout)).await?;

            let (sender_pubkey, answer) = match parse_answer_event(&reply_keys, &answer_event) {
                Ok(result) => result,
                Err(_) => {
                    debug!(event_id = %answer_event.id, "ignoring non-answer signal while awaiting answer");
                    continue;
                }
            };
            if !is_fresh_signal_timestamp(answer.timestamp, SIGNAL_MAX_AGE) {
                debug!(
                    event_id = %answer_event.id,
                    session_id = %answer.session_id,
                    timestamp = answer.timestamp,
                    max_age_secs = SIGNAL_MAX_AGE.as_secs(),
                    "ignoring stale answer"
                );
                continue;
            }
            if sender_pubkey != advertisement.peer_pubkey {
                debug!(
                    event_id = %answer_event.id,
                    author = %sender_pubkey,
                    expected = %advertisement.peer_pubkey,
                        "ignoring answer from unexpected peer"
                    );
                    continue;
                }
                if answer.session_id != session_id {
                    debug!(
                        event_id = %answer_event.id,
                        expected = %session_id,
                        actual = %answer.session_id,
                        "ignoring answer for a different session"
                    );
                    continue;
                }

                let peer_addr = answer.reflexive_addr;

                run_punch(
                    socket,
                    peer_addr,
                    &session_id,
                    config.probe_interval,
                    config.punch_timeout,
                )
                .await?;

                return Ok(PunchedPath {
                    peer_pubkey: advertisement.peer_pubkey,
                    peer_addr,
                    session_id,
                    local_reflexive_addr,
                    used_stun_server: used_stun_server.clone(),
                });
            }
        }
        .await;

        close_subscriptions(subscriptions).await;
        result
    }
    .await;

    cleanup_signaling_events(relays, keys, &published_offer_ids).await;
    result
}

/// Accept and complete one punch attempt from a received offer event.
pub async fn accept_offer(
    socket: &UdpSocket,
    relays: &[&RelayClient],
    keys: &Keys,
    incoming_offer: &IncomingOffer,
    fallback_stun_servers: &[String],
    config: &HolePunchConfig,
) -> Result<PunchedPath, HolePunchError> {
    let offer = &incoming_offer.offer;

    let stun_servers = prefer_stun_server(&offer.stun_server, fallback_stun_servers);
    let (local_reflexive_addr, used_stun_server) =
        query_stun_with_failover(socket, &stun_servers, config.stun_attempt_timeout).await?;

    let answer = Answer {
        session_id: offer.session_id.clone(),
        reflexive_addr: SocketAddr::V4(local_reflexive_addr),
        local_addr: socket.local_addr()?,
        stun_server: used_stun_server.clone(),
        timestamp: Timestamp::now().as_secs(),
    };

    let answer_event = send_answer_all(relays, keys, &offer.reply_pubkey, &answer).await?;
    let published_answer_ids = [answer_event.id];

    let peer_addr = offer.reflexive_addr;

    let result = async {
        run_punch(
            socket,
            peer_addr,
            &offer.session_id,
            config.probe_interval,
            config.punch_timeout,
        )
        .await?;

        Ok(PunchedPath {
            peer_pubkey: incoming_offer.sender_pubkey,
            peer_addr,
            session_id: offer.session_id.clone(),
            local_reflexive_addr,
            used_stun_server: used_stun_server.clone(),
        })
    }
    .await;

    cleanup_signaling_events(relays, keys, &published_answer_ids).await;
    result
}

/// Wait for the first incoming offer across multiple relay subscriptions.
///
/// `keys` are needed to unwrap the NIP-59 gift-wrapped offer.
pub async fn wait_for_first_offer(
    subscriptions: &mut [Subscription],
    keys: &Keys,
    timeout_duration: Option<Duration>,
) -> Result<IncomingOffer, HolePunchError> {
    loop {
        let event = wait_for_first_signal(subscriptions, timeout_duration).await?;
        match parse_offer_event(keys, &event) {
            Ok(offer) => {
                if !is_fresh_signal_timestamp(offer.offer.timestamp, SIGNAL_MAX_AGE) {
                    debug!(
                        event_id = %event.id,
                        session_id = %offer.offer.session_id,
                        timestamp = offer.offer.timestamp,
                        max_age_secs = SIGNAL_MAX_AGE.as_secs(),
                        "ignoring stale offer"
                    );
                    continue;
                }
                return Ok(offer);
            }
            Err(_) => {
                debug!(event_id = %event.id, "ignoring non-offer signal while awaiting offer");
            }
        }
    }
}

async fn query_stun_with_failover(
    socket: &UdpSocket,
    stun_servers: &[String],
    timeout_duration: Duration,
) -> Result<(SocketAddrV4, String), HolePunchError> {
    if stun_servers.is_empty() {
        return Err(HolePunchError::NoStunServers);
    }

    stun_query_any(socket, stun_servers, timeout_duration)
        .await
        .map_err(Into::into)
}

fn prefer_stun_server(primary: &str, fallbacks: &[String]) -> Vec<String> {
    let mut servers = vec![primary.to_string()];
    for server in fallbacks {
        if server != primary {
            servers.push(server.clone());
        }
    }
    servers
}

async fn close_subscriptions(subscriptions: Vec<Subscription>) {
    for sub in subscriptions {
        let _ = sub.close().await;
    }
}

async fn cleanup_signaling_events(relays: &[&RelayClient], keys: &Keys, event_ids: &[EventId]) {
    if event_ids.is_empty() {
        return;
    }

    match publish_deletion_event(relays, keys, event_ids, SIGNAL_CLEANUP_REASON).await {
        Ok(event) => {
            debug!(
                event_id = %event.id,
                targets = event_ids.len(),
                "published signaling cleanup deletion request"
            );
        }
        Err(err) => {
            warn!(
                error = %err,
                targets = event_ids.len(),
                "failed to publish signaling cleanup deletion request"
            );
        }
    }
}

fn is_fresh_signal_timestamp(timestamp_secs: u64, max_age: Duration) -> bool {
    let now = Timestamp::now().as_secs();
    now.saturating_sub(timestamp_secs) <= max_age.as_secs()
}
