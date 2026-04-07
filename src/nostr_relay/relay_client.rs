//! Async Nostr relay client over WebSocket.
//!
//! A thin wrapper around a `tokio-tungstenite` WebSocket connection that
//! speaks the NIP-01 client protocol: EVENT, REQ, CLOSE.

use super::NostrError;
use futures::{SinkExt, StreamExt};
use nostr::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

/// A connection to a single Nostr relay.
pub struct RelayClient {
    /// Channel for outgoing WebSocket messages.
    write_tx: mpsc::Sender<String>,
    /// Active subscriptions, keyed by subscription ID.
    subscriptions: Arc<Mutex<HashMap<SubscriptionId, SubscriptionSender>>>,
    /// Pending OK responses, keyed by event ID.
    pending_oks: Arc<Mutex<HashMap<EventId, oneshot::Sender<(bool, String)>>>>,
    /// Background reader task.
    _reader: JoinHandle<()>,
    /// Background writer task.
    _writer: JoinHandle<()>,
}

/// Internal state for routing messages to a subscription.
struct SubscriptionSender {
    event_tx: mpsc::Sender<Event>,
    eose_tx: Option<oneshot::Sender<()>>,
}

/// A live subscription that receives events matching its filter.
pub struct Subscription {
    id: SubscriptionId,
    event_rx: mpsc::Receiver<Event>,
    eose_rx: Option<oneshot::Receiver<()>>,
    write_tx: mpsc::Sender<String>,
}

impl RelayClient {
    /// Connect to a Nostr relay by WebSocket URL.
    ///
    /// Example: `RelayClient::connect("ws://127.0.0.1:12345").await`
    pub async fn connect(url: &str) -> Result<Self, NostrError> {
        debug!("connecting to relay at {url}");

        let (ws, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| NostrError::WebSocket(e.to_string()))?;

        let (mut ws_write, mut ws_read) = ws.split();

        // Channel for outgoing messages.
        let (write_tx, mut write_rx) = mpsc::channel::<String>(256);

        // Writer task: drains the channel and sends to WebSocket.
        let writer = tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if ws_write
                    .send(tokio_tungstenite::tungstenite::Message::Text(msg.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let subscriptions: Arc<Mutex<HashMap<SubscriptionId, SubscriptionSender>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_oks: Arc<Mutex<HashMap<EventId, oneshot::Sender<(bool, String)>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Reader task: receives WebSocket messages and routes them.
        let subs_clone = subscriptions.clone();
        let oks_clone = pending_oks.clone();
        let reader = tokio::spawn(async move {
            while let Some(msg) = ws_read.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        Self::handle_relay_message(&text, &subs_clone, &oks_clone).await;
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                        debug!("relay connection closed by server");
                        break;
                    }
                    Err(e) => {
                        debug!("relay WebSocket read error: {e}");
                        break;
                    }
                    _ => {} // ping, pong, binary
                }
            }

            // Connection closed — wake up any pending waiters.
            let mut oks = oks_clone.lock().await;
            for (_, tx) in oks.drain() {
                let _ = tx.send((false, "connection closed".to_string()));
            }
        });

        debug!("connected to relay at {url}");

        Ok(Self {
            write_tx,
            subscriptions,
            pending_oks,
            _reader: reader,
            _writer: writer,
        })
    }

    /// Publish a signed event to the relay. Waits for the OK response.
    pub async fn publish(&self, event: Event) -> Result<(), NostrError> {
        let event_id = event.id;
        trace!("publishing event {event_id}");

        // Register for the OK response before sending.
        let (ok_tx, ok_rx) = oneshot::channel();
        {
            let mut oks = self.pending_oks.lock().await;
            oks.insert(event_id, ok_tx);
        }

        // Send the EVENT message.
        let msg = ClientMessage::event(event);
        self.write_tx
            .send(msg.as_json())
            .await
            .map_err(|_| NostrError::ConnectionClosed)?;

        // Wait for the OK response.
        let (accepted, message) = ok_rx.await.map_err(|_| NostrError::ConnectionClosed)?;

        if accepted {
            trace!("event {event_id} accepted");
            Ok(())
        } else {
            Err(NostrError::Rejected(message))
        }
    }

    /// Open a subscription with the given filters.
    ///
    /// Returns a [`Subscription`] that yields matching events. Call
    /// [`Subscription::wait_for_eose`] to wait for the relay to finish
    /// sending stored events before processing live events.
    pub async fn subscribe(&self, filters: Vec<Filter>) -> Result<Subscription, NostrError> {
        let sub_id = SubscriptionId::generate();
        trace!("subscribing with id {sub_id}");

        let (event_tx, event_rx) = mpsc::channel(256);
        let (eose_tx, eose_rx) = oneshot::channel();

        {
            let mut subs = self.subscriptions.lock().await;
            subs.insert(
                sub_id.clone(),
                SubscriptionSender {
                    event_tx,
                    eose_tx: Some(eose_tx),
                },
            );
        }

        // Send the REQ message.
        let msg = ClientMessage::req(sub_id.clone(), filters);
        self.write_tx
            .send(msg.as_json())
            .await
            .map_err(|_| NostrError::ConnectionClosed)?;

        Ok(Subscription {
            id: sub_id,
            event_rx,
            eose_rx: Some(eose_rx),
            write_tx: self.write_tx.clone(),
        })
    }

    /// Close the connection to the relay.
    pub async fn disconnect(self) {
        drop(self.write_tx);
        // Tasks will exit when the channel closes.
    }

    /// Route an incoming relay message to the right waiter.
    async fn handle_relay_message(
        text: &str,
        subscriptions: &Arc<Mutex<HashMap<SubscriptionId, SubscriptionSender>>>,
        pending_oks: &Arc<Mutex<HashMap<EventId, oneshot::Sender<(bool, String)>>>>,
    ) {
        let msg = match RelayMessage::from_json(text) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("invalid relay message: {e}");
                return;
            }
        };

        match msg {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                trace!("received EVENT for subscription {subscription_id}");
                let subs = subscriptions.lock().await;
                if let Some(sub) = subs.get(&subscription_id) {
                    let _ = sub.event_tx.send(event.into_owned()).await;
                }
            }
            RelayMessage::Ok {
                event_id,
                status,
                message,
            } => {
                trace!("received OK for event {event_id}: status={status}");
                let mut oks = pending_oks.lock().await;
                if let Some(tx) = oks.remove(&event_id) {
                    let _ = tx.send((status, message.to_string()));
                }
            }
            RelayMessage::EndOfStoredEvents(sub_id) => {
                trace!("received EOSE for subscription {sub_id}");
                let mut subs = subscriptions.lock().await;
                if let Some(sub) = subs.get_mut(&sub_id) {
                    if let Some(eose_tx) = sub.eose_tx.take() {
                        let _ = eose_tx.send(());
                    }
                }
            }
            RelayMessage::Notice(message) => {
                debug!("relay notice: {message}");
            }
            _ => {
                trace!("ignoring unhandled relay message");
            }
        }
    }
}

impl Subscription {
    /// The subscription ID.
    pub fn id(&self) -> &SubscriptionId {
        &self.id
    }

    /// Wait for the next event. Returns `None` if the subscription
    /// or connection is closed.
    pub async fn next(&mut self) -> Option<Event> {
        self.event_rx.recv().await
    }

    /// Wait for EOSE (End of Stored Events), indicating the relay has
    /// finished sending stored/historical events. After this, only
    /// live events will arrive via [`next()`](Self::next).
    pub async fn wait_for_eose(&mut self) -> Result<(), NostrError> {
        if let Some(rx) = self.eose_rx.take() {
            rx.await.map_err(|_| NostrError::ConnectionClosed)
        } else {
            Ok(()) // already received
        }
    }

    /// Close this subscription (sends CLOSE to the relay).
    pub async fn close(self) -> Result<(), NostrError> {
        let msg = ClientMessage::close(self.id);
        self.write_tx
            .send(msg.as_json())
            .await
            .map_err(|_| NostrError::ConnectionClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr_relay::init_test_logging;
    use crate::nostr_relay::test_relay::TestRelay;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn relay_connect_publish_subscribe() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();

        let keys = Keys::generate();

        // Publish an event.
        let event = EventBuilder::new(Kind::TextNote, "hello nostr")
            .sign_with_keys(&keys)
            .unwrap();
        client.publish(event.clone()).await.unwrap();

        // Subscribe with a matching filter.
        let filter = Filter::new().kind(Kind::TextNote).author(keys.public_key());
        let mut sub = client.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        // Should receive the stored event.
        let received = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out waiting for event")
            .expect("subscription closed");
        assert_eq!(received.id, event.id);
        assert_eq!(received.content, "hello nostr");

        sub.close().await.unwrap();
        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn relay_ephemeral_not_stored() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();

        let keys = Keys::generate();

        // Kind 21059 is ephemeral (20000–29999 range).
        let event = EventBuilder::new(Kind::Custom(21059), "ephemeral data")
            .tag(Tag::public_key(keys.public_key()))
            .sign_with_keys(&keys)
            .unwrap();
        client.publish(event).await.unwrap();

        // A late subscriber should NOT see the ephemeral event.
        let filter = Filter::new().kind(Kind::Custom(21059));
        let mut sub = client.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        // next() should time out — no stored events to replay.
        let result = timeout(Duration::from_millis(200), sub.next()).await;
        assert!(
            result.is_err(),
            "should have timed out — ephemeral events must not be stored"
        );

        sub.close().await.unwrap();
        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn relay_ephemeral_delivered_live() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let subscriber = RelayClient::connect(relay.url()).await.unwrap();
        let publisher = RelayClient::connect(relay.url()).await.unwrap();

        let sender_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let kind = Kind::Custom(21059);

        // Subscribe FIRST, then publish — live delivery.
        let filter = Filter::new().kind(kind).pubkey(receiver_keys.public_key());
        let mut sub = subscriber.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        // Publish from a different connection.
        let event = EventBuilder::new(kind, "live ephemeral")
            .tag(Tag::public_key(receiver_keys.public_key()))
            .sign_with_keys(&sender_keys)
            .unwrap();
        let event_id = event.id;
        publisher.publish(event).await.unwrap();

        // Should receive it live via broadcast.
        let received = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(received.id, event_id);

        sub.close().await.unwrap();
        subscriber.disconnect().await;
        publisher.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn relay_replaceable_latest_wins() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let client = RelayClient::connect(relay.url()).await.unwrap();

        let keys = Keys::generate();
        let kind = Kind::Custom(30078);
        let d_tag = "udp-service-v1/fips";

        // Publish two replaceable events with the same d tag.
        let event1 = EventBuilder::new(kind, "version 1")
            .tag(Tag::identifier(d_tag))
            .sign_with_keys(&keys)
            .unwrap();
        client.publish(event1).await.unwrap();

        // Small delay so created_at differs.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let event2 = EventBuilder::new(kind, "version 2")
            .tag(Tag::identifier(d_tag))
            .sign_with_keys(&keys)
            .unwrap();
        let event2_id = event2.id;
        client.publish(event2).await.unwrap();

        // Query — should only get the latest.
        let filter = Filter::new()
            .kind(kind)
            .author(keys.public_key())
            .identifier(d_tag);
        let mut sub = client.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        let received = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(received.id, event2_id);
        assert_eq!(received.content, "version 2");

        // No more events.
        let result = timeout(Duration::from_millis(200), sub.next()).await;
        assert!(result.is_err(), "should only receive one event");

        sub.close().await.unwrap();
        client.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn relay_filter_by_p_tag() {
        init_test_logging();

        let relay = TestRelay::start().await;
        let subscriber = RelayClient::connect(relay.url()).await.unwrap();
        let publisher = RelayClient::connect(relay.url()).await.unwrap();

        let sender_keys = Keys::generate();
        let target_keys = Keys::generate();
        let other_keys = Keys::generate();

        // Subscribe for events tagged with target's pubkey.
        let filter = Filter::new()
            .kind(Kind::Custom(21059))
            .pubkey(target_keys.public_key());
        let mut sub = subscriber.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        // Publish two events from a different connection: one tagged
        // with target's pubkey, one with other's.
        let event_for_target = EventBuilder::new(Kind::Custom(21059), "for target")
            .tag(Tag::public_key(target_keys.public_key()))
            .sign_with_keys(&sender_keys)
            .unwrap();

        let event_for_other = EventBuilder::new(Kind::Custom(21059), "for other")
            .tag(Tag::public_key(other_keys.public_key()))
            .sign_with_keys(&sender_keys)
            .unwrap();

        let target_event_id = event_for_target.id;
        publisher.publish(event_for_target).await.unwrap();
        publisher.publish(event_for_other).await.unwrap();

        // Should only receive the one tagged for target.
        let received = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(received.id, target_event_id);

        // No more events.
        let result = timeout(Duration::from_millis(200), sub.next()).await;
        assert!(result.is_err(), "should only receive the targeted event");

        sub.close().await.unwrap();
        subscriber.disconnect().await;
        publisher.disconnect().await;
        relay.shutdown().await;
    }

    #[tokio::test]
    async fn relay_eose_then_live() {
        init_test_logging();

        let relay = TestRelay::start().await;

        // Use separate clients for subscribing and publishing, as would
        // happen in production (different peers on different connections).
        let subscriber = RelayClient::connect(relay.url()).await.unwrap();
        let publisher = RelayClient::connect(relay.url()).await.unwrap();

        let keys = Keys::generate();

        // Subscribe first — no stored events.
        let filter = Filter::new().kind(Kind::TextNote).author(keys.public_key());
        let mut sub = subscriber.subscribe(vec![filter]).await.unwrap();
        sub.wait_for_eose().await.unwrap();

        // Publish from a different connection — arrives as a live event
        // via the relay's broadcast channel.
        let event = EventBuilder::new(Kind::TextNote, "live event")
            .sign_with_keys(&keys)
            .unwrap();
        let event_id = event.id;
        publisher.publish(event).await.unwrap();

        let received = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(received.id, event_id);

        sub.close().await.unwrap();
        subscriber.disconnect().await;
        publisher.disconnect().await;
        relay.shutdown().await;
    }
}
