//! WebSocket connection handling: the per-connection [`Conn`]
//! state, the connection loop and the live fan-out. The protocol
//! message handlers (REQ/EVENT/AUTH/COUNT/NEG) live in [`handler`].

mod handler;
mod negentropy;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip42, nip77};
use crate::relay::Relay;
use crate::stats::Stats;

/// Secondary bound on the number of queued messages (a long tail of small
/// messages must not outgrow the VecDeque either).
const OUT_QUEUE_LIMIT: usize = 4096;
/// Events queued on a connection before they are accepted as one database
/// batch (the batch shares a single write commit).
pub(crate) const EVENT_BATCH: usize = 64;

pub struct Conn {
    pub(crate) relay: Arc<Relay>,
    /// Outgoing messages awaiting a TCP write, drained by the connection
    /// loop after every select iteration.
    pub(crate) outgoing: std::collections::VecDeque<Message>,
    /// Bytes currently queued in `outgoing`; the byte cap decides whether a
    /// new message is queued or dropped.
    pub(crate) out_bytes: usize,
    /// Per-connection byte cap for the outgoing queue (`limits.max_out_queue_bytes`,
    /// cached once per connection).
    pub(crate) out_queue_bytes: usize,
    /// Subscription id -> (filters, serialized filter bytes).
    subs: HashMap<String, (Vec<Filter>, usize)>,
    /// Bytes held by the filters of all active subscriptions.
    pub(crate) sub_bytes: usize,
    /// NIP-77 negentropy state per subscription id.
    neg: HashMap<String, Vec<nip77::Item>>,
    /// Total number of negentropy items held across all open NEG-OPEN
    /// subscriptions, so that a connection cannot pin more than twice the
    /// configured per-query maximum in memory.
    pub(crate) neg_total: usize,
    pub(crate) challenge: String,
    /// Every pubkey authenticated on this connection (NIP-42: all of them
    /// are treated as authenticated).
    pub(crate) authed_pubkeys: Vec<String>,
    /// Events received but not yet accepted; flushed in batches so the
    /// database commit cost is amortized over many events.
    pub(crate) pending_events: Vec<Event>,
    /// Whether this connection delivers NIP-40 expired events live. Cached
    /// from the config on connect and refreshed whenever a message arrives,
    /// so the per-batch live path avoids the shared config lock.
    pub(crate) expiry_enabled: bool,
    /// Whether NIP-59 gift wraps are only served to their recipients
    /// (enforced with NIP-42 auth; false when NIP-42 is disabled).
    pub(crate) giftwrap_restricted: bool,
    pub(crate) dropped: u64,
    /// Per-connection message/byte counters, flushed into the shared stats
    /// once on disconnect so that a million connections do not hammer the
    /// same cache lines for every single message.
    pub(crate) in_msgs: u64,
    pub(crate) in_bytes: u64,
    pub(crate) out_msgs: u64,
    pub(crate) out_bytes_total: u64,
}

impl Conn {
    pub(crate) fn send(&mut self, msg: Message) {
        let size = message_size(&msg);
        let over_byte_cap =
            !self.outgoing.is_empty() && self.out_bytes.saturating_add(size) > self.out_queue_bytes;
        if self.outgoing.len() >= OUT_QUEUE_LIMIT || over_byte_cap {
            self.dropped += 1;
            self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
            return;
        }
        self.out_bytes += size;
        self.out_msgs += 1;
        self.out_bytes_total += size as u64;
        self.outgoing.push_back(msg);
    }

    pub(crate) fn send_json(&mut self, value: Value) {
        if let Ok(text) = serde_json::to_string(&value) {
            self.send(Message::Text(text.into()));
        }
    }

    pub(crate) fn send_notice(&mut self, text: &str) {
        self.send_json(json!(["NOTICE", text]));
    }

    /// NIP-01 CLOSED: a REQ was rejected or ended, with a machine-readable
    /// reason.
    pub(crate) fn send_closed(&mut self, sub_id: &str, reason: &str) {
        self.send_json(json!(["CLOSED", sub_id, reason]));
    }

    pub(crate) fn send_ok(&mut self, id: &str, accepted: bool, message: &str) {
        self.send_json(json!(["OK", id, accepted, message]));
    }

    /// Whether the connection is authenticated (with any pubkey).
    pub(crate) fn is_authed(&self) -> bool {
        !self.authed_pubkeys.is_empty()
    }

    pub(crate) async fn send_auth_challenge(&mut self) {
        let enabled = {
            let cfg = self.relay.config.read().await;
            cfg.nip_enabled(42) && cfg.server.send_auth_challenge
        };
        if enabled {
            self.send_json(nip42::auth_message(&self.challenge));
        }
    }
}

pub(crate) fn value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn message_size(msg: &Message) -> usize {
    match msg {
        Message::Text(text) => text.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(_) => 0,
    }
}

/// Releases the connection's accounting when the connection task ends, no
/// matter how it ends. A panic anywhere in the connection handling would
/// otherwise skip the disconnect cleanup and leak the `connections_active`
/// counter, slowly refusing every new connection.
struct ConnectionGuard(Arc<Stats>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0
            .connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub async fn handle_connection(mut socket: WebSocket, relay: Arc<Relay>) {
    let active = relay
        .stats
        .connections_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    relay.stats.bump(&relay.stats.connections_total, 1);

    let max_connections = relay.config.read().await.limits.max_connections;
    if active > max_connections as u64 {
        relay
            .stats
            .connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let _ = socket.close().await;
        return;
    }
    let _guard = ConnectionGuard(relay.stats.clone());

    let (mut sender, mut receiver) = socket.split();
    let (max_msg_size, out_queue_bytes, expiry_enabled, giftwrap_restricted) = {
        let cfg = relay.config.read().await;
        (
            cfg.limits.max_ws_message_size,
            cfg.limits.max_out_queue_bytes,
            cfg.nip_enabled(40),
            cfg.nip_enabled(42),
        )
    };

    let challenge = nip42::generate_challenge();

    let mut conn = Conn {
        relay,
        outgoing: std::collections::VecDeque::new(),
        out_bytes: 0,
        out_queue_bytes,
        subs: HashMap::new(),
        sub_bytes: 0,
        neg: HashMap::new(),
        neg_total: 0,
        challenge,
        authed_pubkeys: Vec::new(),
        pending_events: Vec::new(),
        expiry_enabled,
        giftwrap_restricted,
        dropped: 0,
        in_msgs: 0,
        in_bytes: 0,
        out_msgs: 0,
        out_bytes_total: 0,
    };
    conn.send_auth_challenge().await;

    // The live receiver is created lazily on the first REQ: connections
    // that only publish never register with the broadcast channel, so they
    // are not woken up by live events at all.
    let mut live: Option<tokio::sync::broadcast::Receiver<Arc<Vec<Event>>>> = None;

    // A single task per connection: incoming messages and live batches are
    // processed in the same loop, and outgoing messages are flushed to the
    // socket after every iteration. This halves the task count (no separate
    // writer task) and the per-connection channel.
    loop {
        // Drain pending outgoing messages. A slow reader stalls only its
        // own connection (outgoing is bounded, so new messages are dropped).
        while let Some(msg) = conn.outgoing.pop_front() {
            conn.out_bytes = conn.out_bytes.saturating_sub(message_size(&msg));
            if sender.send(msg).await.is_err() {
                break;
            }
        }
        let live_fut = async {
            match live.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > max_msg_size {
                            conn.send_notice("error: message too large");
                            break;
                        }
                        conn.in_msgs += 1;
                        conn.in_bytes += text.len() as u64;
                        conn.handle_text(&text).await;
                        // Refresh the cached NIP-40/NIP-42 flags so config
                        // reloads take effect for live delivery.
                        let cfg = conn.relay.config.read().await;
                        conn.expiry_enabled = cfg.nip_enabled(40);
                        conn.giftwrap_restricted = cfg.nip_enabled(42);
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > max_msg_size {
                            conn.send_notice("error: message too large");
                            break;
                        }
                        let text = String::from_utf8_lossy(&data).into_owned();
                        conn.in_msgs += 1;
                        conn.in_bytes += data.len() as u64;
                        conn.handle_text(&text).await;
                        let cfg = conn.relay.config.read().await;
                        conn.expiry_enabled = cfg.nip_enabled(40);
                        conn.giftwrap_restricted = cfg.nip_enabled(42);
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
                // Batch window: keep reading for a moment so consecutive
                // EVENT messages from a busy publisher share one database
                // commit, then flush the queue when the socket is idle.
                let mut too_large = false;
                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(1),
                        receiver.next(),
                    )
                    .await
                    {
                        Ok(Some(Ok(Message::Text(text)))) => {
                            if text.len() > max_msg_size {
                                conn.send_notice("error: message too large");
                                too_large = true;
                                break;
                            }
                            conn.in_msgs += 1;
                            conn.in_bytes += text.len() as u64;
                            conn.handle_text(&text).await;
                        }
                        Ok(Some(Ok(Message::Binary(data)))) => {
                            if data.len() > max_msg_size {
                                conn.send_notice("error: message too large");
                                too_large = true;
                                break;
                            }
                            let text = String::from_utf8_lossy(&data).into_owned();
                            conn.in_msgs += 1;
                            conn.in_bytes += data.len() as u64;
                            conn.handle_text(&text).await;
                        }
                        _ => break,
                    }
                }
                if too_large {
                    break;
                }
                conn.flush_pending_events().await;
                // Subscribe to live events once the first REQ arrives and
                // drop the receiver again when every subscription is closed,
                // so connections without active subscriptions are never
                // woken by live events.
                if live.is_none() && !conn.subs.is_empty() {
                    live = Some(conn.relay.live.subscribe());
                } else if live.is_some() && conn.subs.is_empty() {
                    live = None;
                }
            }
            live_batch = live_fut => {
                match live_batch {
                    Ok(batch) => {
                        // The group store lock is only taken when the batch
                        // actually contains group events (rare); ordinary
                        // traffic skips the shared lock entirely.
                        let has_group_events =
                            batch.iter().any(nip29::is_group_event);
                        // The store Arc stays alive for the whole batch so
                        // the read guard can borrow it; the lock is only
                        // taken for batches containing group events.
                        let store = Arc::clone(&conn.relay.groups);
                        let guard = if has_group_events {
                            Some(store.read().await)
                        } else {
                            None
                        };
                        let groups = guard.as_deref();
                        for event in batch.iter() {
                            conn.deliver_live(event, groups);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    // Events received but not yet batched are accepted before closing, so
    // a client that disconnects without waiting for its OKs does not lose
    // them. The live broadcast of these events still reaches subscribers.
    conn.flush_pending_events().await;

    // Final flush: deliver any queued messages (e.g. NOTICEs) before
    // closing the connection.
    while let Some(msg) = conn.outgoing.pop_front() {
        conn.out_bytes = conn.out_bytes.saturating_sub(message_size(&msg));
        if sender.send(msg).await.is_err() {
            break;
        }
    }
    let _ = sender.close().await;

    // Flush the per-connection counters into the shared stats once, so the
    // hot per-message path never contends on the shared atomics.
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_in, conn.in_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_in, conn.in_bytes);
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_out, conn.out_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_out, conn.out_bytes_total);

    // Release the connection's accounting: any subscriptions still open at
    // disconnect were never CLOSE'd, so decrement them here.
    conn.relay
        .stats
        .subscriptions_active
        .fetch_sub(conn.subs.len() as u64, std::sync::atomic::Ordering::Relaxed);
}
