//! End-to-end integration test for the full hole-punch protocol.
//!
//! Exercises all phases on localhost: STUN discovery → Nostr signaling
//! (service advertisement, offer, answer) → UDP punch.

use crate::holepunch::punch::{DEFAULT_PROBE_INTERVAL, DEFAULT_PUNCH_TIMEOUT, run_punch};
use crate::holepunch::signaling::{
    SignalingPayload, SignalingType, discover_service, extract_stun_servers, parse_signaling_event,
    publish_service_advertisement, send_answer, send_offer, subscribe_signals,
};
use crate::nostr_relay::RelayClient;
use crate::nostr_relay::init_test_logging;
use crate::nostr_relay::test_relay::TestRelay;
use crate::stun::{StunServer, stun_query};
use nostr::prelude::*;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::test]
async fn full_holepunch_localhost() {
    init_test_logging();

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

    let mut responder_sub = subscribe_signals(&responder_client, &responder_keys.public_key())
        .await
        .unwrap();

    publish_service_advertisement(&[&responder_client], &responder_keys, &[&stun_addr])
        .await
        .unwrap();

    // --- Initiator: discover service ---
    let initiator_client = RelayClient::connect(relay.url()).await.unwrap();

    let advertisement = discover_service(&initiator_client, &responder_keys.public_key())
        .await
        .unwrap()
        .expect("should find responder's service advertisement");

    // Extract the STUN server from the advertisement.
    let stun_servers = extract_stun_servers(&advertisement);
    assert!(
        !stun_servers.is_empty(),
        "advertisement should list STUN servers"
    );
    let chosen_stun = &stun_servers[0];

    // --- Initiator: STUN query + send offer ---
    let initiator_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let initiator_reflexive = stun_query(&initiator_sock, chosen_stun).await.unwrap();

    let session_id = hex::encode(rand::random::<[u8; 16]>());

    let mut initiator_sub = subscribe_signals(&initiator_client, &initiator_keys.public_key())
        .await
        .unwrap();

    let offer = SignalingPayload {
        msg_type: SignalingType::Offer,
        session_id: session_id.clone(),
        reflexive_addr: initiator_reflexive.to_string(),
        local_addr: initiator_sock.local_addr().unwrap().to_string(),
        stun_server: chosen_stun.clone(),
        timestamp: Timestamp::now().as_secs(),
    };

    send_offer(
        &initiator_client,
        &initiator_keys,
        &responder_keys.public_key(),
        &offer,
    )
    .await
    .unwrap();

    // --- Responder: receive offer, STUN query, send answer ---
    let offer_event = tokio::time::timeout(std::time::Duration::from_secs(5), responder_sub.next())
        .await
        .expect("responder timed out waiting for offer")
        .expect("responder subscription closed");

    let received_offer = parse_signaling_event(&offer_event).unwrap();
    assert_eq!(received_offer.msg_type, SignalingType::Offer);
    assert_eq!(received_offer.session_id, session_id);

    // Responder does its own STUN query using the punch socket.
    let responder_reflexive = stun_query(&responder_sock, &received_offer.stun_server)
        .await
        .unwrap();

    let answer = SignalingPayload {
        msg_type: SignalingType::Answer,
        session_id: session_id.clone(),
        reflexive_addr: responder_reflexive.to_string(),
        local_addr: responder_sock.local_addr().unwrap().to_string(),
        stun_server: received_offer.stun_server.clone(),
        timestamp: Timestamp::now().as_secs(),
    };

    send_answer(
        &responder_client,
        &responder_keys,
        &initiator_keys.public_key(),
        &answer,
    )
    .await
    .unwrap();

    // --- Initiator: receive answer ---
    let answer_event =
        tokio::time::timeout(std::time::Duration::from_secs(5), initiator_sub.next())
            .await
            .expect("initiator timed out waiting for answer")
            .expect("initiator subscription closed");

    let received_answer = parse_signaling_event(&answer_event).unwrap();
    assert_eq!(received_answer.msg_type, SignalingType::Answer);
    assert_eq!(received_answer.session_id, session_id);

    // --- Both punch concurrently ---
    let initiator_peer: SocketAddr = received_answer.reflexive_addr.parse().unwrap();
    let responder_peer: SocketAddr = received_offer.reflexive_addr.parse().unwrap();

    let (punch_a, punch_b) = tokio::join!(
        run_punch(
            &initiator_sock,
            initiator_peer,
            &session_id,
            DEFAULT_PROBE_INTERVAL,
            DEFAULT_PUNCH_TIMEOUT,
        ),
        run_punch(
            &responder_sock,
            responder_peer,
            &session_id,
            DEFAULT_PROBE_INTERVAL,
            DEFAULT_PUNCH_TIMEOUT,
        ),
    );

    punch_a.expect("initiator punch failed");
    punch_b.expect("responder punch failed");

    // --- Cleanup ---
    responder_sub.close().await.unwrap();
    initiator_sub.close().await.unwrap();
    initiator_client.disconnect().await;
    responder_client.disconnect().await;
    relay.shutdown().await;
    stun_server.shutdown().await;
}
