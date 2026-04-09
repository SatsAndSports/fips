//! End-to-end integration test for the full hole-punch protocol.
//!
//! Exercises all phases on localhost: STUN discovery → Nostr signaling
//! (service advertisement, offer, answer) → UDP punch.

use crate::holepunch::orchestrator::{
    HolePunchConfig, accept_offer, initiate_from_advertisement, subscribe_signals_all,
    wait_for_first_offer,
};
use crate::holepunch::signaling::{
    SIGNAL_CLEANUP_REASON, discover_service_across_relays, publish_service_advertisement,
};
use crate::nostr_relay::RelayClient;
use crate::nostr_relay::init_test_logging;
use crate::nostr_relay::test_relay::TestRelay;
use crate::stun::StunServer;
use nostr::prelude::*;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn full_holepunch_localhost() {
    init_test_logging();
    let config = HolePunchConfig::default();

    // --- Infrastructure ---
    let stun_server = StunServer::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_server.local_addr().to_string();
    let relay = TestRelay::start().await;

    // --- Keys ---
    let initiator_keys = Keys::generate();
    let responder_keys = Keys::generate();

    // --- Responder setup (order matters: subscribe before advertise) ---
    let responder_client = RelayClient::connect(relay.url()).await.unwrap();

    let responder_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut responder_subs =
        subscribe_signals_all(&[&responder_client], responder_keys.public_key())
            .await
            .unwrap();

    publish_service_advertisement(
        &[&responder_client],
        &responder_keys,
        &[&stun_addr],
        &[relay.url()],
        None,
    )
    .await
    .unwrap();

    // --- Initiator: discover service ---
    let initiator_client = RelayClient::connect(relay.url()).await.unwrap();
    let initiator_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let responder_relays = [&responder_client];
    let initiator_relays = [&initiator_client];

    let advertisement = discover_service_across_relays(&initiator_relays, &responder_keys.public_key())
        .await
        .unwrap();

    let responder_stun_fallback = vec![stun_addr.clone()];
    let responder_flow = async {
        let incoming_offer = wait_for_first_offer(&mut responder_subs, &responder_keys, None)
            .await
            .unwrap();
        accept_offer(
            &responder_sock,
            &responder_relays,
            &responder_keys,
            &incoming_offer,
            &responder_stun_fallback,
            &config,
        )
        .await
        .unwrap()
    };
    let initiator_flow = initiate_from_advertisement(
        &initiator_sock,
        &initiator_relays,
        &initiator_keys,
        &advertisement,
        &config,
    );

    let (initiator_path, responder_path) = tokio::join!(initiator_flow, responder_flow);
    let initiator_path = initiator_path.expect("initiator orchestration failed");
    let responder_path = responder_path;

    assert_eq!(initiator_path.peer_pubkey, responder_keys.public_key());
    assert_eq!(responder_path.peer_pubkey, initiator_keys.public_key());
    assert_eq!(initiator_path.session_id, responder_path.session_id);
    assert_eq!(
        initiator_path.peer_addr,
        responder_sock.local_addr().unwrap()
    );
    assert_eq!(
        responder_path.peer_addr,
        initiator_sock.local_addr().unwrap()
    );

    let mut initiator_deletions = initiator_client
        .subscribe(vec![
            Filter::new()
                .kind(Kind::EventDeletion)
                .author(initiator_keys.public_key()),
        ])
        .await
        .unwrap();
    initiator_deletions.wait_for_eose().await.unwrap();
    let initiator_deletion = timeout(Duration::from_secs(2), initiator_deletions.next())
        .await
        .expect("timed out waiting for initiator deletion")
        .expect("initiator deletion subscription closed");
    assert_eq!(initiator_deletion.content, SIGNAL_CLEANUP_REASON);
    assert_eq!(
        initiator_deletion
            .tags
            .iter()
            .filter(|tag| tag.kind() == TagKind::e())
            .count(),
        1
    );

    let mut responder_deletions = responder_client
        .subscribe(vec![
            Filter::new()
                .kind(Kind::EventDeletion)
                .author(responder_keys.public_key()),
        ])
        .await
        .unwrap();
    responder_deletions.wait_for_eose().await.unwrap();
    let responder_deletion = timeout(Duration::from_secs(2), responder_deletions.next())
        .await
        .expect("timed out waiting for responder deletion")
        .expect("responder deletion subscription closed");
    assert_eq!(responder_deletion.content, SIGNAL_CLEANUP_REASON);
    assert_eq!(
        responder_deletion
            .tags
            .iter()
            .filter(|tag| tag.kind() == TagKind::e())
            .count(),
        1
    );

    // --- Cleanup ---
    initiator_deletions.close().await.unwrap();
    responder_deletions.close().await.unwrap();
    for sub in responder_subs {
        sub.close().await.unwrap();
    }
    initiator_client.disconnect().await;
    responder_client.disconnect().await;
    relay.shutdown().await;
    stun_server.shutdown().await;
}

#[tokio::test]
async fn initiator_failed_attempt_cleans_up_its_offer() {
    init_test_logging();

    let stun_server = StunServer::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_server.local_addr().to_string();
    let relay = TestRelay::start().await;

    let responder_keys = Keys::generate();
    let initiator_keys = Keys::generate();

    let responder_client = RelayClient::connect(relay.url()).await.unwrap();
    publish_service_advertisement(
        &[&responder_client],
        &responder_keys,
        &[&stun_addr],
        &[relay.url()],
        None,
    )
    .await
    .unwrap();

    let initiator_client = RelayClient::connect(relay.url()).await.unwrap();
    let initiator_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let initiator_relays = [&initiator_client];

    let advertisement = discover_service_across_relays(&initiator_relays, &responder_keys.public_key())
        .await
        .unwrap();
    let config = HolePunchConfig {
        signal_timeout: Duration::from_millis(150),
        stun_attempt_timeout: Duration::from_secs(1),
        probe_interval: Duration::from_millis(50),
        punch_timeout: Duration::from_millis(150),
    };

    let err = initiate_from_advertisement(
        &initiator_sock,
        &initiator_relays,
        &initiator_keys,
        &advertisement,
        &config,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, crate::holepunch::HolePunchError::Timeout(_)));

    let mut deletions = initiator_client
        .subscribe(vec![
            Filter::new()
                .kind(Kind::EventDeletion)
                .author(initiator_keys.public_key()),
        ])
        .await
        .unwrap();
    deletions.wait_for_eose().await.unwrap();

    let deletion = timeout(Duration::from_secs(2), deletions.next())
        .await
        .expect("timed out waiting for failed-attempt deletion")
        .expect("deletion subscription closed");
    assert_eq!(deletion.content, SIGNAL_CLEANUP_REASON);
    assert_eq!(
        deletion
            .tags
            .iter()
            .filter(|tag| tag.kind() == TagKind::e())
            .count(),
        1
    );

    deletions.close().await.unwrap();
    initiator_client.disconnect().await;
    responder_client.disconnect().await;
    relay.shutdown().await;
    stun_server.shutdown().await;
}
