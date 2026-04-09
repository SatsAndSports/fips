//! nostr-punch - demo UDP hole punch over Nostr signaling.
//!
//! This binary is intended for real-world manual testing across two machines.
//! It uses a real Nostr relay and STUN server, prints the responder's npub,
//! and performs a simple UDP hello exchange after the punch succeeds.

use clap::{Parser, ValueEnum};
use fips::holepunch::orchestrator::{
    HolePunchConfig, accept_offer, initiate_from_advertisement, subscribe_signals_all,
    wait_for_first_offer,
};
use fips::holepunch::punch::{parse_punch, session_hash};
use fips::holepunch::signaling::{discover_service_across_relays, publish_service_advertisement};
use fips::nostr_relay::{RelayClient, Subscription};
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
    name = "nostr-punch",
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

    info!(role = args.role.as_str(), "starting nostr-punch");
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

    let config = hole_punch_config(args);
    let mut subs = subscribe_signals_all(relays, keys.public_key())
        .await
        .map_err(|e| e.to_string())?;

    let stun_refs: Vec<&str> = args.stun.iter().map(String::as_str).collect();
    let relay_url_refs: Vec<&str> = args.relay.iter().map(String::as_str).collect();
    publish_service_advertisement(relays, keys, &stun_refs, &relay_url_refs, None)
        .await
        .map_err(|e| format!("failed to publish service advertisement: {e}"))?;
    info!("published service advertisement");

    loop {
        match handle_responder_session(keys, relays, &socket, &mut subs, &args.stun, &config).await
        {
            Ok(()) => info!("responder ready for another connection"),
            Err(e) if e == "all relay subscriptions closed" => {
                return Err(
                    "all relay subscriptions closed; restart the responder or add reconnect logic"
                        .into(),
                );
            }
            Err(e) => warn!(error = %e, "responder session failed; continuing to listen"),
        }
    }
}

async fn handle_responder_session(
    keys: &Keys,
    relays: &[&RelayClient],
    socket: &UdpSocket,
    subs: &mut [Subscription],
    fallback_stun_servers: &[String],
    config: &HolePunchConfig,
) -> Result<(), String> {
    let incoming_offer = wait_for_first_offer(subs, keys, None)
        .await
        .map_err(|e| e.to_string())?;
    let path = accept_offer(socket, relays, keys, &incoming_offer, fallback_stun_servers, config)
        .await
        .map_err(|e| e.to_string())?;
    info!(session_id = %path.session_id, peer = %path.peer_addr, "hole punch succeeded");

    let received = exchange_hello(
        socket,
        path.peer_addr,
        Role::Responder,
        &path.session_id,
        config.punch_timeout,
    )
    .await?;
    info!(peer = %path.peer_addr, payload = %received, "received UDP payload");

    Ok(())
}

async fn run_initiator(args: &Args, keys: &Keys, relays: &[&RelayClient]) -> Result<(), String> {
    let responder_npub = args
        .responder_npub
        .as_deref()
        .ok_or("missing responder npub")?;
    let responder_pubkey = PublicKey::parse(responder_npub)
        .map_err(|e| format!("invalid responder npub '{responder_npub}': {e}"))?;

    let advertisement = discover_service_across_relays(relays, &responder_pubkey)
        .await
        .map_err(|e| e.to_string())?;
    let config = hole_punch_config(args);

    let socket = UdpSocket::bind(&args.bind)
        .await
        .map_err(|e| format!("failed to bind UDP socket {}: {e}", args.bind))?;
    info!(addr = %socket.local_addr().map_err(|e| e.to_string())?, "bound UDP socket");

    let path = initiate_from_advertisement(&socket, relays, keys, &advertisement, &config)
        .await
        .map_err(|e| e.to_string())?;
    info!(session_id = %path.session_id, peer = %path.peer_addr, "hole punch succeeded");

    let received = exchange_hello(
        &socket,
        path.peer_addr,
        Role::Initiator,
        &path.session_id,
        config.punch_timeout,
    )
    .await?;
    info!(peer = %path.peer_addr, payload = %received, "received UDP payload");

    Ok(())
}

fn hole_punch_config(args: &Args) -> HolePunchConfig {
    HolePunchConfig {
        signal_timeout: Duration::from_secs(args.timeout_secs),
        stun_attempt_timeout: Duration::from_secs(2),
        probe_interval: Duration::from_millis(args.probe_ms),
        punch_timeout: Duration::from_secs(args.timeout_secs),
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
