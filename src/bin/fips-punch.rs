//! fips-punch - demo UDP hole punch over Nostr signaling.
//!
//! This binary is intended for real-world manual testing across two machines.
//! It uses a real Nostr relay and STUN server, prints the responder's npub,
//! and performs a simple UDP hello exchange after the punch succeeds.

use clap::{Parser, ValueEnum};
use fips::holepunch::punch::{parse_punch, run_punch, session_hash};
use fips::holepunch::signaling::{
    SignalingPayload, SignalingType, discover_service, extract_stun_servers, parse_signaling_event,
    publish_service_advertisement, send_answer_all, send_offer_all, subscribe_signals,
};
use fips::nostr_relay::{RelayClient, Subscription};
use fips::stun::stun_query;
use fips::version;
use futures::future::join_all;
use nostr::prelude::*;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

/// Demo UDP hole punch over Nostr signaling.
#[derive(Parser, Debug)]
#[command(
    name = "fips-punch",
    version = version::short_version(),
    long_version = version::long_version(),
    about = "Demo UDP hole punch over Nostr signaling"
)]
struct Args {
    /// Role to run.
    #[arg(long, value_enum)]
    role: Role,

    /// Nostr relay URL. Repeat to use multiple relays.
    #[arg(long, required = true, value_name = "URL")]
    relay: Vec<String>,

    /// STUN server address. Required for responder. Repeating advertises multiple servers.
    #[arg(long, value_name = "HOST:PORT")]
    stun: Vec<String>,

    /// Responder npub. Required for initiator.
    #[arg(long, value_name = "NPUB")]
    responder_npub: Option<String>,

    /// Nostr secret key as nsec or 32-byte hex. If omitted, a random key is generated.
    #[arg(long, value_name = "NSEC_OR_HEX")]
    secret_key: Option<String>,

    /// Local UDP bind address for STUN and punch.
    #[arg(long, default_value = "0.0.0.0:0", value_name = "ADDR")]
    bind: String,

    /// Probe interval in milliseconds.
    #[arg(long, default_value_t = 200)]
    probe_ms: u64,

    /// Timeout in seconds for offer/answer waits and punch completion.
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// Default tracing level when RUST_LOG is not set.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Role {
    Responder,
    Initiator,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Responder => "responder",
            Self::Initiator => "initiator",
        }
    }

    fn hello(self) -> &'static str {
        match self {
            Self::Responder => "HELLO FROM RESPONDER",
            Self::Initiator => "HELLO FROM INITIATOR",
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args = Args::parse();

    if let Err(e) = init_logging(&args.log_level) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    validate_args(&args)?;

    let (keys, ephemeral) = load_keys(args.secret_key.as_deref())?;
    let npub = keys
        .public_key()
        .to_bech32()
        .map_err(|e| format!("failed to encode npub: {e}"))?;

    info!(role = args.role.as_str(), "starting fips-punch");
    info!("local identity: {npub}");
    if ephemeral {
        info!("using ephemeral keypair; pass --secret-key to reuse an identity");
    }
    for relay in &args.relay {
        info!(relay = %relay, "configured relay");
    }
    for stun in &args.stun {
        info!(stun = %stun, "configured STUN server");
    }

    let relays = connect_relays(&args.relay).await?;
    let relay_refs = relay_refs(&relays);

    let result = match args.role {
        Role::Responder => run_responder(&args, &keys, &npub, &relay_refs).await,
        Role::Initiator => run_initiator(&args, &keys, &relay_refs).await,
    };

    for relay in relays {
        relay.disconnect().await;
    }

    result
}

fn init_logging(default_level: &str) -> Result<(), String> {
    let directive = default_level
        .parse()
        .map_err(|e| format!("invalid --log-level '{default_level}': {e}"))?;
    let filter = EnvFilter::builder()
        .with_default_directive(directive)
        .from_env_lossy();

    fmt().with_env_filter(filter).with_target(true).init();
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), String> {
    match args.role {
        Role::Responder if args.stun.is_empty() => {
            Err("responder requires at least one --stun server".into())
        }
        Role::Initiator if args.responder_npub.is_none() => {
            Err("initiator requires --responder-npub".into())
        }
        _ => Ok(()),
    }
}

fn load_keys(secret_key: Option<&str>) -> Result<(Keys, bool), String> {
    match secret_key {
        Some(secret) => Keys::parse(secret)
            .map(|keys| (keys, false))
            .map_err(|e| format!("invalid secret key: {e}")),
        None => Ok((Keys::generate(), true)),
    }
}

async fn connect_relays(urls: &[String]) -> Result<Vec<RelayClient>, String> {
    let results = join_all(urls.iter().map(|url| RelayClient::connect(url))).await;

    let mut relays = Vec::new();
    for (url, result) in urls.iter().zip(results) {
        match result {
            Ok(client) => {
                info!(relay = %url, "connected to relay");
                relays.push(client);
            }
            Err(e) => warn!(relay = %url, error = %e, "failed to connect to relay"),
        }
    }

    if relays.is_empty() {
        return Err("failed to connect to any relay".into());
    }

    Ok(relays)
}

fn relay_refs(relays: &[RelayClient]) -> Vec<&RelayClient> {
    relays.iter().collect()
}

async fn run_responder(
    args: &Args,
    keys: &Keys,
    npub: &str,
    relays: &[&RelayClient],
) -> Result<(), String> {
    info!("responder ready; give this npub to the initiator");
    println!("Responder npub:");
    println!("{npub}");

    let socket = UdpSocket::bind(&args.bind)
        .await
        .map_err(|e| format!("failed to bind UDP socket {}: {e}", args.bind))?;
    info!(addr = %socket.local_addr().map_err(|e| e.to_string())?, "bound UDP socket");

    let mut subs = subscribe_on_all(relays, keys.public_key()).await?;

    let stun_refs: Vec<&str> = args.stun.iter().map(String::as_str).collect();
    publish_service_advertisement(relays, keys, &stun_refs)
        .await
        .map_err(|e| format!("failed to publish service advertisement: {e}"))?;
    info!("published service advertisement");

    loop {
        match handle_responder_session(args, keys, relays, &socket, &mut subs).await {
            Ok(()) => info!("responder ready for another connection"),
            Err(e) => warn!(error = %e, "responder session failed; continuing to listen"),
        }
    }
}

async fn handle_responder_session(
    args: &Args,
    keys: &Keys,
    relays: &[&RelayClient],
    socket: &UdpSocket,
    subs: &mut [Subscription],
) -> Result<(), String> {
    let offer_event = wait_for_first_signal(subs, None).await?;
    let offer =
        parse_signaling_event(&offer_event).map_err(|e| format!("failed to parse offer: {e}"))?;
    if offer.msg_type != SignalingType::Offer {
        return Err(format!("expected offer, got {:?}", offer.msg_type));
    }
    info!(session_id = %offer.session_id, from = %offer.reflexive_addr, "received offer");

    let reflexive = stun_query(socket, &offer.stun_server)
        .await
        .map_err(|e| format!("STUN query failed: {e}"))?;
    info!(reflexive = %reflexive, stun = %offer.stun_server, "STUN reflexive address");

    let answer = SignalingPayload {
        msg_type: SignalingType::Answer,
        session_id: offer.session_id.clone(),
        reflexive_addr: reflexive.to_string(),
        local_addr: socket.local_addr().map_err(|e| e.to_string())?.to_string(),
        stun_server: offer.stun_server.clone(),
        timestamp: Timestamp::now().as_secs(),
    };
    let initiator_pubkey = offer_event.pubkey;

    send_answer_all(relays, keys, &initiator_pubkey, &answer)
        .await
        .map_err(|e| format!("failed to send answer: {e}"))?;
    info!(session_id = %answer.session_id, "sent answer");

    let peer_addr: SocketAddr = offer.reflexive_addr.parse().map_err(|e| {
        format!(
            "invalid peer reflexive address '{}': {e}",
            offer.reflexive_addr
        )
    })?;
    let punch_timeout = Duration::from_secs(args.timeout_secs);
    let probe_interval = Duration::from_millis(args.probe_ms);

    run_punch(
        socket,
        peer_addr,
        &offer.session_id,
        probe_interval,
        punch_timeout,
    )
    .await
    .map_err(|e| format!("hole punch failed: {e}"))?;
    info!(peer = %peer_addr, "hole punch succeeded");

    let received = exchange_hello(
        socket,
        peer_addr,
        Role::Responder,
        &offer.session_id,
        punch_timeout,
    )
    .await?;
    info!(peer = %peer_addr, payload = %received, "received UDP payload");

    Ok(())
}

async fn run_initiator(args: &Args, keys: &Keys, relays: &[&RelayClient]) -> Result<(), String> {
    let responder_npub = args
        .responder_npub
        .as_deref()
        .ok_or("missing responder npub")?;
    let responder_pubkey = PublicKey::parse(responder_npub)
        .map_err(|e| format!("invalid responder npub '{responder_npub}': {e}"))?;

    let advertisement = discover_across_relays(relays, &responder_pubkey).await?;
    let mut advertised_stun = extract_stun_servers(&advertisement);
    if advertised_stun.is_empty() {
        advertised_stun = args.stun.clone();
    }
    let chosen_stun = advertised_stun
        .first()
        .cloned()
        .ok_or("no STUN servers found in advertisement and none provided locally")?;
    info!(stun = %chosen_stun, "chosen STUN server");

    let socket = UdpSocket::bind(&args.bind)
        .await
        .map_err(|e| format!("failed to bind UDP socket {}: {e}", args.bind))?;
    info!(addr = %socket.local_addr().map_err(|e| e.to_string())?, "bound UDP socket");

    let reflexive = stun_query(&socket, &chosen_stun)
        .await
        .map_err(|e| format!("STUN query failed: {e}"))?;
    info!(reflexive = %reflexive, stun = %chosen_stun, "STUN reflexive address");

    let mut subs = subscribe_on_all(relays, keys.public_key()).await?;

    let session_id = hex::encode(rand::random::<[u8; 16]>());
    let offer = SignalingPayload {
        msg_type: SignalingType::Offer,
        session_id: session_id.clone(),
        reflexive_addr: reflexive.to_string(),
        local_addr: socket.local_addr().map_err(|e| e.to_string())?.to_string(),
        stun_server: chosen_stun,
        timestamp: Timestamp::now().as_secs(),
    };

    send_offer_all(relays, keys, &responder_pubkey, &offer)
        .await
        .map_err(|e| format!("failed to send offer: {e}"))?;
    info!(session_id = %offer.session_id, to = %responder_npub, "sent offer");

    let answer_event =
        wait_for_first_signal(&mut subs, Some(Duration::from_secs(args.timeout_secs))).await?;
    let answer =
        parse_signaling_event(&answer_event).map_err(|e| format!("failed to parse answer: {e}"))?;
    if answer.msg_type != SignalingType::Answer {
        return Err(format!("expected answer, got {:?}", answer.msg_type));
    }
    if answer.session_id != session_id {
        return Err(format!(
            "session mismatch: expected {}, got {}",
            session_id, answer.session_id
        ));
    }
    info!(session_id = %answer.session_id, from = %answer.reflexive_addr, "received answer");

    let peer_addr: SocketAddr = answer.reflexive_addr.parse().map_err(|e| {
        format!(
            "invalid peer reflexive address '{}': {e}",
            answer.reflexive_addr
        )
    })?;
    let punch_timeout = Duration::from_secs(args.timeout_secs);
    let probe_interval = Duration::from_millis(args.probe_ms);

    run_punch(
        &socket,
        peer_addr,
        &session_id,
        probe_interval,
        punch_timeout,
    )
    .await
    .map_err(|e| format!("hole punch failed: {e}"))?;
    info!(peer = %peer_addr, "hole punch succeeded");

    let received = exchange_hello(
        &socket,
        peer_addr,
        Role::Initiator,
        &session_id,
        punch_timeout,
    )
    .await?;
    info!(peer = %peer_addr, payload = %received, "received UDP payload");

    close_subscriptions(subs).await;
    Ok(())
}

async fn subscribe_on_all(
    relays: &[&RelayClient],
    my_pubkey: PublicKey,
) -> Result<Vec<Subscription>, String> {
    let mut subs = Vec::with_capacity(relays.len());
    for relay in relays {
        let sub = subscribe_signals(relay, &my_pubkey)
            .await
            .map_err(|e| format!("failed to subscribe for signals: {e}"))?;
        subs.push(sub);
    }
    Ok(subs)
}

async fn discover_across_relays(
    relays: &[&RelayClient],
    responder_pubkey: &PublicKey,
) -> Result<Event, String> {
    for relay in relays {
        match discover_service(relay, responder_pubkey).await {
            Ok(Some(event)) => {
                info!(event_id = %event.id, author = %event.pubkey, "discovered service advertisement");
                return Ok(event);
            }
            Ok(None) => continue,
            Err(e) => warn!(error = %e, "service discovery failed on one relay"),
        }
    }

    Err("service advertisement not found on any relay".into())
}

async fn wait_for_first_signal(
    subscriptions: &mut [Subscription],
    timeout_duration: Option<Duration>,
) -> Result<Event, String> {
    let deadline = timeout_duration.map(|duration| Instant::now() + duration);
    let poll_step = Duration::from_millis(50);

    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            let duration = timeout_duration.expect("deadline implies timeout duration");
            return Err(format!("timed out waiting for signal after {duration:?}"));
        }

        for sub in subscriptions.iter_mut() {
            match timeout(poll_step, sub.next()).await {
                Ok(Some(event)) => {
                    debug!(event_id = %event.id, author = %event.pubkey, "received signal event");
                    return Ok(event);
                }
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
    }
}

async fn exchange_hello(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    role: Role,
    session_id: &str,
    timeout_duration: Duration,
) -> Result<String, String> {
    let payload = role.hello();
    socket
        .send_to(payload.as_bytes(), peer_addr)
        .await
        .map_err(|e| format!("failed to send hello payload: {e}"))?;
    info!(peer = %peer_addr, payload = %payload, "sent UDP payload");

    let hash = session_hash(session_id);
    let start = Instant::now();
    let mut buf = [0u8; 2048];

    loop {
        let remaining = timeout_duration
            .checked_sub(start.elapsed())
            .ok_or_else(|| {
                format!("timed out waiting for hello payload after {timeout_duration:?}")
            })?;

        let (n, from) = timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| format!("timed out waiting for hello payload after {timeout_duration:?}"))?
            .map_err(|e| format!("failed to receive hello payload: {e}"))?;

        if from != peer_addr {
            debug!(from = %from, expected = %peer_addr, "ignoring UDP packet from unexpected peer");
            continue;
        }

        if parse_punch(&buf[..n], &hash).is_some() {
            debug!("ignoring leftover punch packet while waiting for hello");
            continue;
        }

        return Ok(String::from_utf8_lossy(&buf[..n]).to_string());
    }
}

async fn close_subscriptions(subscriptions: Vec<Subscription>) {
    for sub in subscriptions {
        if let Err(e) = sub.close().await {
            warn!(error = %e, "failed to close subscription");
        }
    }
}
