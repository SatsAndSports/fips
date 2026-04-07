//! Reusable orchestration helpers for Nostr-signaled UDP hole punching.
//!
//! These helpers sit above the packet/signaling primitives and below the demo
//! binary. They are intended to be the first reusable library boundary before
//! integrating hole punching into the wider FIPS transport system.

use super::HolePunchError;
use super::punch::{DEFAULT_PROBE_INTERVAL, DEFAULT_PUNCH_TIMEOUT, run_punch};
use super::signaling::{
    Answer, IncomingOffer, Offer, ServiceAdvertisement, parse_answer_event, parse_offer_event,
    send_answer_all, send_offer_all, subscribe_signals,
};
use crate::nostr_relay::{RelayClient, Subscription};
use crate::stun::stun_query_any;
use nostr::prelude::*;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

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
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            signal_timeout: Duration::from_secs(10),
            stun_attempt_timeout: Duration::from_secs(2),
            probe_interval: DEFAULT_PROBE_INTERVAL,
            punch_timeout: DEFAULT_PUNCH_TIMEOUT,
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
                warn!(error = %err, "failed to subscribe for signals on one relay");
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
            match timeout(poll_step, sub.next()).await {
                Ok(Some(event)) => {
                    debug!(event_id = %event.id, author = %event.pubkey, "received signal event");
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

    let (local_reflexive_addr, used_stun_server) = query_stun_with_failover(
        socket,
        &advertisement.stun_servers,
        config.stun_attempt_timeout,
    )
    .await?;

    let mut subscriptions = subscribe_signals_all(relays, keys.public_key()).await?;

    let result = async {
        let session_id = hex::encode(rand::random::<[u8; 16]>());
        let offer = Offer {
            session_id: session_id.clone(),
            reflexive_addr: SocketAddr::V4(local_reflexive_addr),
            local_addr: socket.local_addr()?,
            stun_server: used_stun_server.clone(),
            timestamp: Timestamp::now().as_secs(),
        };

        send_offer_all(relays, keys, &advertisement.peer_pubkey, &offer).await?;

        loop {
            let answer_event = wait_for_first_signal(&mut subscriptions, Some(config.signal_timeout)).await?;
            if answer_event.pubkey != advertisement.peer_pubkey {
                debug!(
                    event_id = %answer_event.id,
                    author = %answer_event.pubkey,
                    expected = %advertisement.peer_pubkey,
                    "ignoring signal from unexpected peer"
                );
                continue;
            }

            let answer = match parse_answer_event(&answer_event) {
                Ok(answer) => answer,
                Err(_) => {
                    debug!(event_id = %answer_event.id, "ignoring non-answer signal while awaiting answer");
                    continue;
                }
            };
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

    send_answer_all(relays, keys, &incoming_offer.sender_pubkey, &answer).await?;

    let peer_addr = offer.reflexive_addr;

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

/// Wait for the first incoming offer across multiple relay subscriptions.
pub async fn wait_for_first_offer(
    subscriptions: &mut [Subscription],
    timeout_duration: Option<Duration>,
) -> Result<IncomingOffer, HolePunchError> {
    loop {
        let event = wait_for_first_signal(subscriptions, timeout_duration).await?;
        match parse_offer_event(&event) {
            Ok(offer) => return Ok(offer),
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
