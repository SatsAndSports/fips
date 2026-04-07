//! End-to-end integration test for the full hole-punch protocol.
//!
//! Exercises all phases on localhost: STUN discovery → Nostr signaling
//! (service advertisement, offer, answer) → UDP punch.

use crate::holepunch::orchestrator::{
    HolePunchConfig, accept_offer, initiate_from_advertisement, subscribe_signals_all,
    wait_for_first_offer,
};
use crate::holepunch::signaling::{discover_service_across_relays, publish_service_advertisement};
use crate::nostr_relay::RelayClient;
use crate::nostr_relay::init_test_logging;
use crate::nostr_relay::test_relay::TestRelay;
use crate::stun::StunServer;
use nostr::prelude::*;
use tokio::net::UdpSocket;

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

    publish_service_advertisement(&[&responder_client], &responder_keys, &[&stun_addr])
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
        let incoming_offer = wait_for_first_offer(&mut responder_subs, None)
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

    // --- Cleanup ---
    for sub in responder_subs {
        sub.close().await.unwrap();
    }
    initiator_client.disconnect().await;
    responder_client.disconnect().await;
    relay.shutdown().await;
    stun_server.shutdown().await;
}
