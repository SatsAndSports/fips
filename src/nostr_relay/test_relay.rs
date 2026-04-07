//! Minimal in-process Nostr relay for integration testing.
//!
//! Implements just enough NIP-01 to support the hole-punch signaling
//! protocol: EVENT (store + fan out), REQ (replay + live subscription),
//! CLOSE, OK, EOSE. Handles ephemeral kinds (20000–29999) and
//! parameterized replaceable events (kind 30000–39999).

use futures::{SinkExt, StreamExt};
use nostr::prelude::*;
use nostr::filter::MatchEventOptions;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

/// A running in-process Nostr relay.
pub struct TestRelay {
    url: String,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Shared state across all connections.
struct RelayState {
    events: Vec<Event>,
}

impl TestRelay {
    /// Start a test relay on a random localhost port.
    /// Returns the relay with its WebSocket URL (e.g., "ws://127.0.0.1:12345").
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test relay");
        let port = listener.local_addr().unwrap().port();
        let url = format!("ws://127.0.0.1:{port}");

        let state = Arc::new(RwLock::new(RelayState {
            events: Vec::new(),
        }));
        let (broadcast_tx, _) = broadcast::channel::<Event>(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(Self::accept_loop(listener, state, broadcast_tx, shutdown_rx));

        debug!("test relay started on {url}");
        Self {
            url,
            shutdown_tx,
            task,
        }
    }

    /// The WebSocket URL of this relay.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Shut down the relay.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.task.await;
    }

    async fn accept_loop(
        listener: TcpListener,
        state: Arc<RwLock<RelayState>>,
        broadcast_tx: broadcast::Sender<Event>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("test relay shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            debug!("test relay: new connection from {addr}");
                            let state = state.clone();
                            let broadcast_tx = broadcast_tx.clone();
                            let broadcast_rx = broadcast_tx.subscribe();
                            tokio::spawn(Self::handle_connection(
                                stream, state, broadcast_tx, broadcast_rx,
                            ));
                        }
                        Err(e) => warn!("test relay accept error: {e}"),
                    }
                }
            }
        }
    }

    async fn handle_connection(
        stream: tokio::net::TcpStream,
        state: Arc<RwLock<RelayState>>,
        broadcast_tx: broadcast::Sender<Event>,
        mut broadcast_rx: broadcast::Receiver<Event>,
    ) {
        let ws = match tokio_tungstenite::accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                warn!("test relay: WebSocket handshake failed: {e}");
                return;
            }
        };

        let (mut ws_write, mut ws_read) = ws.split();

        // Channel for outgoing WebSocket messages so both the client
        // message handler and the broadcast fan-out can send.
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(256);

        // Writer task: drains the channel and sends to WebSocket.
        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if ws_write
                    .send(tokio_tungstenite::tungstenite::Message::Text(msg.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Per-connection subscription state.
        let mut subscriptions: HashMap<SubscriptionId, Vec<Filter>> = HashMap::new();

        loop {
            tokio::select! {
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                            Self::handle_client_message(
                                &text,
                                &state,
                                &broadcast_tx,
                                &out_tx,
                                &mut subscriptions,
                            ).await;
                        }
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                            debug!("test relay: connection closed");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!("test relay: WebSocket read error: {e}");
                            break;
                        }
                        _ => {} // ping, pong, binary — ignore
                    }
                }
                result = broadcast_rx.recv() => {
                    match result {
                        Ok(event) => {
                            let opts = MatchEventOptions::default();
                            for (sub_id, filters) in &subscriptions {
                                if filters.iter().any(|f| f.match_event(&event, opts)) {
                                    let relay_msg = RelayMessage::event(
                                        sub_id.clone(), event.clone(),
                                    );
                                    let _ = out_tx.send(relay_msg.as_json()).await;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("test relay: broadcast lagged by {n}");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }

        drop(out_tx);
        let _ = writer.await;
    }

    async fn handle_client_message(
        text: &str,
        state: &Arc<RwLock<RelayState>>,
        broadcast_tx: &broadcast::Sender<Event>,
        out_tx: &tokio::sync::mpsc::Sender<String>,
        subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    ) {
        let msg = match ClientMessage::from_json(text) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("test relay: invalid client message: {e}");
                let notice = RelayMessage::Notice(format!("invalid message: {e}").into());
                let _ = out_tx.send(notice.as_json()).await;
                return;
            }
        };

        match msg {
            ClientMessage::Event(event) => {
                let event = event.into_owned();
                let event_id = event.id;
                trace!("test relay: EVENT {event_id}");

                let kind_u16 = event.kind.as_u16();
                let is_ephemeral = (20000..30000).contains(&kind_u16);
                let is_replaceable = (30000..40000).contains(&kind_u16);

                if !is_ephemeral {
                    let mut s = state.write().await;
                    if is_replaceable {
                        // Remove existing event with same pubkey + d tag.
                        let d_tag = extract_d_tag(&event);
                        s.events.retain(|existing| {
                            !(existing.kind == event.kind
                                && existing.pubkey == event.pubkey
                                && extract_d_tag(existing) == d_tag)
                        });
                    }
                    s.events.push(event.clone());
                }

                // Broadcast to all connections for live subscription matching.
                let _ = broadcast_tx.send(event);

                let ok = RelayMessage::Ok {
                    event_id,
                    status: true,
                    message: "".into(),
                };
                let _ = out_tx.send(ok.as_json()).await;
            }
            ClientMessage::Req {
                subscription_id,
                filters,
            } => {
                let subscription_id = subscription_id.into_owned();
                let filters: Vec<Filter> = filters.into_iter().map(|f| f.into_owned()).collect();
                trace!("test relay: REQ {subscription_id}");

                // Register subscription BEFORE replaying stored events
                // to avoid a race where events published during replay
                // are missed.
                subscriptions.insert(subscription_id.clone(), filters.clone());

                // Replay matching stored events.
                let opts = MatchEventOptions::default();
                let s = state.read().await;
                for event in &s.events {
                    if filters.iter().any(|f| f.match_event(event, opts)) {
                        let relay_msg =
                            RelayMessage::event(subscription_id.clone(), event.clone());
                        let _ = out_tx.send(relay_msg.as_json()).await;
                    }
                }
                drop(s);

                // End of stored events.
                let eose = RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(subscription_id));
                let _ = out_tx.send(eose.as_json()).await;
            }
            ClientMessage::Close(sub_id) => {
                let sub_id = sub_id.into_owned();
                trace!("test relay: CLOSE {sub_id}");
                subscriptions.remove(&sub_id);
            }
            _ => {
                trace!("test relay: ignoring unhandled message type");
            }
        }
    }
}

/// Extract the `d` tag value from an event (for replaceable event matching).
fn extract_d_tag(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.kind() == TagKind::d())
        .and_then(|t| t.content())
        .map(|s| s.to_string())
}
