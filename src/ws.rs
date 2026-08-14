use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip40, nip42, nip45, nip70, nip77};
use crate::relay::Relay;
use crate::stats::unix_now;

/// Secondary bound on the number of queued messages (a long tail of small
/// messages must not outgrow the VecDeque either).
const OUT_QUEUE_LIMIT: usize = 4096;
/// Events queued on a connection before they are accepted as one database
/// batch (the batch shares a single write commit).
const EVENT_BATCH: usize = 64;

pub struct Conn {
    relay: Arc<Relay>,
    /// Outgoing messages awaiting a TCP write, drained by the connection
    /// loop after every select iteration.
    outgoing: std::collections::VecDeque<Message>,
    /// Bytes currently queued in `outgoing`; the byte cap decides whether a
    /// new message is queued or dropped.
    out_bytes: usize,
    /// Per-connection byte cap for the outgoing queue (`limits.max_out_queue_bytes`,
    /// cached once per connection).
    out_queue_bytes: usize,
    /// Subscription id -> (filters, serialized filter bytes).
    subs: HashMap<String, (Vec<Filter>, usize)>,
    /// Bytes held by the filters of all active subscriptions.
    sub_bytes: usize,
    /// NIP-77 negentropy state per subscription id.
    neg: HashMap<String, Vec<nip77::Item>>,
    /// Total number of negentropy items held across all open NEG-OPEN
    /// subscriptions, so that a connection cannot pin more than twice the
    /// configured per-query maximum in memory.
    neg_total: usize,
    challenge: String,
    /// Every pubkey authenticated on this connection (NIP-42: all of them
    /// are treated as authenticated).
    authed_pubkeys: Vec<String>,
    /// Events received but not yet accepted; flushed in batches so the
    /// database commit cost is amortized over many events.
    pending_events: Vec<Event>,
    /// Whether this connection delivers NIP-40 expired events live. Cached
    /// from the config on connect and refreshed whenever a message arrives,
    /// so the per-batch live path avoids the shared config lock.
    expiry_enabled: bool,
    /// Whether NIP-59 gift wraps are only served to their recipients
    /// (enforced with NIP-42 auth; false when NIP-42 is disabled).
    giftwrap_restricted: bool,
    dropped: u64,
    /// Per-connection message/byte counters, flushed into the shared stats
    /// once on disconnect so that a million connections do not hammer the
    /// same cache lines for every single message.
    in_msgs: u64,
    in_bytes: u64,
    out_msgs: u64,
    out_bytes_total: u64,
}

impl Conn {
    fn send(&mut self, msg: Message) {
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

    fn send_json(&mut self, value: Value) {
        if let Ok(text) = serde_json::to_string(&value) {
            self.send(Message::Text(text.into()));
        }
    }

    fn notice(&mut self, text: &str) {
        self.send_json(json!(["NOTICE", text]));
    }

    /// NIP-01 CLOSED: a REQ was rejected or ended, with a machine-readable
    /// reason.
    fn closed(&mut self, sub_id: &str, reason: &str) {
        self.send_json(json!(["CLOSED", sub_id, reason]));
    }

    fn ok(&mut self, id: &str, accepted: bool, message: &str) {
        self.send_json(json!(["OK", id, accepted, message]));
    }

    /// Whether the connection is authenticated (with any pubkey).
    fn is_authed(&self) -> bool {
        !self.authed_pubkeys.is_empty()
    }

    async fn send_auth_challenge(&mut self) {
        let enabled = {
            let cfg = self.relay.config.read().await;
            cfg.nip_enabled(42) && cfg.server.send_auth_challenge
        };
        if enabled {
            self.send_json(nip42::auth_message(&self.challenge));
        }
    }
    async fn handle_text(&mut self, text: &str) {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            self.notice("error: invalid json");
            return;
        };
        let Some(msg) = value.as_array() else {
            self.notice("error: expected an array message");
            return;
        };
        let Some(Some(kind)) = msg.first().map(|v| v.as_str()) else {
            self.notice("error: message type must be a string");
            return;
        };

        match kind {
            // EVENT messages are queued and accepted in batches so the
            // database commit cost is paid once per batch instead of once
            // per event; the batch is flushed when it is full, when the
            // socket is momentarily idle, or before any other message.
            "EVENT" => {
                // Fast path: the message is parsed directly as a
                // `(verb, event)` pair in a single JSON pass, avoiding the
                // generic Value parse plus its clone. The generic path is
                // only taken for malformed messages (to emit the NOTICE).
                match serde_json::from_str::<(String, Event)>(text) {
                    Ok((_, event)) => self.queue_event_value(event).await,
                    Err(_) => self.queue_event(&msg[1..]).await,
                }
            }
            "REQ" => {
                self.flush_pending_events().await;
                self.handle_req(&msg[1..]).await;
            }
            "CLOSE" => {
                self.flush_pending_events().await;
                self.handle_close(&msg[1..]);
            }
            "AUTH" => {
                self.flush_pending_events().await;
                self.handle_auth(&msg[1..]).await;
            }
            "COUNT" => {
                self.flush_pending_events().await;
                self.handle_count(&msg[1..]).await;
            }
            "NEG-OPEN" => {
                self.flush_pending_events().await;
                self.handle_neg_open(&msg[1..]).await;
            }
            "NEG-MSG" => {
                self.flush_pending_events().await;
                self.handle_neg_msg(&msg[1..]).await;
            }
            "NEG-CLOSE" => {
                self.flush_pending_events().await;
                self.handle_neg_close(&msg[1..]);
            }
            "PING" => {}
            other => {
                self.flush_pending_events().await;
                self.notice(&format!("error: unsupported message type {other}"));
            }
        }
    }

    /// Queues an already-parsed event for batched acceptance.
    async fn queue_event_value(&mut self, event: Event) {
        self.relay.stats.bump(&self.relay.stats.events_received, 1);
        self.pending_events.push(event);
        if self.pending_events.len() >= EVENT_BATCH {
            self.flush_pending_events().await;
        }
    }

    /// Queues an EVENT message for batched acceptance (generic path).
    async fn queue_event(&mut self, rest: &[Value]) {
        self.relay.stats.bump(&self.relay.stats.events_received, 1);
        if rest.is_empty() {
            self.notice("error: EVENT requires an event object");
            return;
        }
        let event: Event = match serde_json::from_value(rest[0].clone()) {
            Ok(event) => event,
            Err(_) => {
                self.notice("error: invalid event object");
                return;
            }
        };
        self.queue_event_value(event).await;
    }

    /// Accepts the queued events in one database batch and sends the OKs.
    async fn flush_pending_events(&mut self) {
        if self.pending_events.is_empty() {
            return;
        }
        let events = std::mem::take(&mut self.pending_events);
        let outcomes = self
            .relay
            .accept_events_batch(events, &self.authed_pubkeys)
            .await;
        for (id, outcome) in outcomes {
            match outcome {
                crate::db::PutOutcome::Stored | crate::db::PutOutcome::Replaced => {
                    self.ok(&id, true, "");
                }
                crate::db::PutOutcome::Ephemeral => {
                    // NIP-01: ephemeral kinds are delivered live but never
                    // stored; the NIP-01 `mute:` prefix acknowledges this.
                    self.ok(&id, true, "mute: ephemeral event not stored");
                }
                crate::db::PutOutcome::Duplicate => {
                    self.ok(&id, true, "duplicate: event already stored");
                }
                crate::db::PutOutcome::Invalid(reason) => {
                    self.ok(&id, false, &reason);
                }
                crate::db::PutOutcome::Expired => {
                    self.ok(&id, false, "invalid: event has expired");
                }
                crate::db::PutOutcome::PreviouslyDeleted => {
                    self.ok(&id, false, "blocked: event has been deleted");
                }
            }
        }
    }

    async fn handle_req(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            self.notice("error: REQ requires a subscription id and filters");
            return;
        }
        let sub_id = match rest[0].as_str() {
            Some(id) => id,
            None => {
                self.notice("error: subscription id must be a string");
                return;
            }
        };

        let (max_sub_id_len, max_filters, max_subscriptions, max_limit) = {
            let limits = &self.relay.config.read().await.limits;
            (
                limits.max_sub_id_len,
                limits.max_filters,
                limits.max_subscriptions,
                limits.max_limit,
            )
        };
        if sub_id.is_empty() {
            self.closed(sub_id, "invalid: subscription id must not be empty");
            return;
        }
        if sub_id.len() > max_sub_id_len {
            self.closed(sub_id, "invalid: subscription id too long");
            return;
        }

        let mut filters = Vec::new();
        for f in &rest[1..] {
            match serde_json::from_value::<Filter>(f.clone()) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.closed(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        if filters.is_empty() {
            self.closed(sub_id, "invalid: REQ requires at least one filter");
            return;
        }
        if filters.len() > max_filters {
            self.closed(sub_id, "invalid: too many filters");
            return;
        }

        let search_disabled = filters.iter().any(|f| f.has_search())
            && !self.relay.config.read().await.nip_enabled(50);

        if self.relay.config.read().await.server.require_auth && !self.is_authed() {
            self.closed(
                sub_id,
                "auth-required: please authenticate before subscribing",
            );
            return;
        }
        if self.subs.len() >= max_subscriptions {
            self.closed(sub_id, "error: too many subscriptions");
            return;
        }

        let mut stored = filters.clone();
        if search_disabled {
            for f in &mut stored {
                f.search = None;
            }
            self.notice("search is not enabled on this relay");
        }

        // Bound the memory held by this connection's subscriptions: each
        // filter is bounded by the message size limit, so without a cap a
        // connection could pin many megabytes of filter data.
        let sub_bytes: usize = stored
            .iter()
            .map(|f| {
                serde_json::to_string(f)
                    .map(|s| s.len())
                    .unwrap_or_default()
            })
            .sum();
        let sub_bytes_limit = self.relay.config.read().await.limits.max_sub_bytes;
        let replacing = self.subs.get(sub_id).map(|(_, bytes)| *bytes);
        let next_total = self
            .sub_bytes
            .saturating_sub(replacing.unwrap_or(0))
            .saturating_add(sub_bytes);
        if next_total > sub_bytes_limit {
            self.closed(sub_id, "error: too many subscriptions");
            return;
        }
        self.sub_bytes = next_total;
        self.subs
            .insert(sub_id.to_string(), (stored.clone(), sub_bytes));
        if replacing.is_none() {
            self.relay
                .stats
                .bump(&self.relay.stats.subscriptions_total, 1);
            self.relay
                .stats
                .bump(&self.relay.stats.subscriptions_active, 1);
        }

        let now = unix_now();
        let (events, more) = self.relay.db.query(stored, max_limit, now).await;
        let mut to_send = Vec::new();
        {
            let groups = self.relay.groups.read().await;
            for event in events {
                if !self.visible_to(&groups, &event) {
                    continue;
                }
                to_send.push(event);
            }
        }
        for event in to_send {
            self.send_json(json!(["EVENT", sub_id, event]));
        }
        // NIP-67: EOSE completeness hint.
        if self.relay.config.read().await.nip_enabled(67) {
            let hint = if more { "more" } else { "finish" };
            self.send_json(json!(["EOSE", sub_id, [hint]]));
        } else {
            self.send_json(json!(["EOSE", sub_id]));
        }
    }

    fn handle_close(&mut self, rest: &[Value]) {
        let Some(Some(sub_id)) = rest.first().map(|v| v.as_str()) else {
            self.notice("error: CLOSE requires a subscription id");
            return;
        };
        if let Some((_, bytes)) = self.subs.remove(sub_id) {
            self.sub_bytes = self.sub_bytes.saturating_sub(bytes);
            self.relay
                .stats
                .subscriptions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    async fn handle_auth(&mut self, rest: &[Value]) {
        if !self.relay.config.read().await.nip_enabled(42) {
            self.notice("error: authentication is not enabled on this relay");
            return;
        }
        if rest.is_empty() {
            self.notice("error: AUTH requires an event object");
            return;
        }
        let event: Event = match serde_json::from_value(rest[0].clone()) {
            Ok(event) => event,
            Err(_) => {
                self.notice("error: invalid auth event");
                return;
            }
        };
        let id = event.id.clone();
        let accepted = {
            let cfg = self.relay.config.read().await;
            nip42::verify(
                &event,
                &self.challenge,
                self.relay.secp(),
                unix_now(),
                &cfg.server.host,
                cfg.server.port,
                &cfg.relay.public_url,
            )
        };
        if accepted {
            // NIP-42: all authenticated pubkeys are treated as authenticated.
            // Bound the list: repeated AUTHs with the same key are
            // deduplicated and the number of distinct keys is capped so a
            // connection cannot grow this vector (or the per-event
            // visibility scan over it) without limit.
            if !self.authed_pubkeys.iter().any(|pk| pk == &event.pubkey)
                && self.authed_pubkeys.len() < 64
            {
                self.authed_pubkeys.push(event.pubkey.clone());
            }
        }
        self.send_json(nip42::ok(&id, accepted));
    }

    async fn handle_count(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            self.notice("error: COUNT requires a subscription id and filters");
            return;
        }
        let Some(sub_id) = rest[0].as_str() else {
            self.notice("error: subscription id must be a string");
            return;
        };
        // NIP-45: refusals must be answered with a CLOSED message.
        if !self.relay.config.read().await.nip_enabled(45) {
            self.closed(sub_id, "error: counting is not enabled on this relay");
            return;
        }
        if self.relay.config.read().await.server.require_auth && !self.is_authed() {
            self.closed(sub_id, "auth-required: please authenticate before counting");
            return;
        }
        let mut filters = Vec::new();
        for f in &rest[1..] {
            match serde_json::from_value::<Filter>(f.clone()) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.closed(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        let count_limit = self.relay.config.read().await.limits.count_limit;
        let (events, more) = self
            .relay
            .db
            .count(filters.clone(), count_limit, unix_now())
            .await;
        // NIP-70: protected events are only counted for authenticated
        // clients, so COUNT never leaks them to unauthenticated peers.
        let events: Vec<Event> = events
            .into_iter()
            .filter(|e| self.is_authed() || !nip70::is_protected(e))
            .collect();
        self.send_json(nip45::count_response(sub_id, &filters, &events, more));
    }

    /// NIP-59 / NIP-17: gift wraps are signed by random keys, so they may
    /// only be served to their recipients, i.e. authenticated users whose
    /// pubkey appears in a `p` tag of the wrap (enforced with NIP-42 auth;
    /// skipped when NIP-42 is disabled).
    fn gift_wrap_visible(&self, event: &Event) -> bool {
        !self.giftwrap_restricted
            || event.kind != crate::nips::nip62::GIFT_WRAP_KIND
            || event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && self.authed_pubkeys.contains(&t[1]))
    }
    /// Whether a stored or live event may be served on this connection
    /// (NIP-70 protected, NIP-59 gift-wrap recipient and NIP-29 group
    /// access checks).
    fn visible_to(&self, groups: &nip29::GroupStore, event: &Event) -> bool {
        // NIP-70: protected events are only served to authenticated clients.
        // The `-` tag constrains *publication* (author-only, enforced on the
        // write path); NIP-43's relay-generated membership metadata carries
        // it by spec while remaining readable to authenticated clients.
        if !self.is_authed() && nip70::is_protected(event) {
            return false;
        }
        if !self.gift_wrap_visible(event) {
            return false;
        }
        if self.authed_pubkeys.is_empty() {
            groups.visible_to(event, None)
        } else {
            self.authed_pubkeys
                .iter()
                .any(|pk| groups.visible_to(event, Some(pk)))
        }
    }
    /// Streams live events that match active subscriptions.
    ///
    /// `groups` is only present when the batch contains group events (the
    /// caller skips the lock otherwise); `expiry_enabled` is a per-connection
    /// cache refreshed whenever a message arrives, so the hot live path does
    /// not acquire the shared config lock once per batch per connection.
    fn deliver_live(&mut self, event: &Event, groups: Option<&nip29::GroupStore>) {
        // Fast path: most connections have no subscriptions.
        if self.subs.is_empty() {
            return;
        }
        // NIP-70: protected events are only delivered to authenticated
        // clients.
        if !self.is_authed() && nip70::is_protected(event) {
            return;
        }
        // NIP-59: gift wraps are only delivered to their recipients, even
        // when the batch contains no group events (visible_to is only
        // reached when the groups lock was taken).
        if !self.gift_wrap_visible(event) {
            return;
        }
        if let Some(groups) = groups
            && !self.visible_to(groups, event)
        {
            return;
        }
        // NIP-40: expired stored events are not delivered live; ephemeral
        // kinds are exempt ("an expiration timestamp does not affect
        // storage of ephemeral events").
        if self.expiry_enabled
            && !(20000..30000).contains(&event.kind)
            && let Some(exp) = nip40::expiry(event)
            && exp < unix_now()
        {
            return;
        }
        let matching: Vec<String> = self
            .subs
            .iter()
            .filter(|(_, (filters, _))| filters.iter().any(|f| f.matches(event)))
            .map(|(sub_id, _)| sub_id.clone())
            .collect();
        if matching.is_empty() {
            return;
        }
        // Serialize the event once and wrap it per subscription: the JSON
        // of a large event would otherwise be encoded once per matching
        // subscription (a hot path on busy relays).
        let Ok(event_json) = serde_json::to_string(event) else {
            return;
        };
        let mut out = String::with_capacity(event_json.len() + 32);
        for sub_id in matching {
            let Ok(sub_json) = serde_json::to_string(&sub_id) else {
                continue;
            };
            out.clear();
            out.push_str("[\"EVENT\",");
            out.push_str(&sub_json);
            out.push(',');
            out.push_str(&event_json);
            out.push(']');
            self.send(Message::Text(out.clone().into()));
        }
    }

    // ----- NIP-77 negentropy -----

    fn neg_err(&mut self, sub_id: &str, reason: &str) {
        self.send_json(json!(["NEG-ERR", sub_id, reason]));
    }

    fn neg_msg(&mut self, sub_id: &str, message: &[u8]) {
        self.send_json(json!(["NEG-MSG", sub_id, hex::encode(message)]));
    }

    async fn handle_neg_open(&mut self, rest: &[Value]) {
        if !self.relay.config.read().await.nip_enabled(77) {
            self.notice("error: negentropy is not enabled on this relay");
            return;
        }
        if rest.len() < 3 {
            self.notice("error: NEG-OPEN requires a subscription id, filter and message");
            return;
        }
        let sub_id = match value_string(&rest[0]) {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.notice("error: NEG-OPEN subscription id must be a non-empty string");
                return;
            }
        };
        let filter: Filter = match serde_json::from_value::<Filter>(rest[1].clone()) {
            Ok(mut filter) => {
                // Negentropy needs every matching record, not a capped page.
                filter.limit = None;
                filter
            }
            Err(_) => {
                self.notice("error: invalid NEG-OPEN filter");
                return;
            }
        };
        let Some(initial) = rest[2].as_str() else {
            self.notice("error: NEG-OPEN message must be hex");
            return;
        };
        let Ok(initial) = hex::decode(initial) else {
            self.notice("error: NEG-OPEN message must be hex");
            return;
        };
        // NIP-42: an auth-requiring relay applies the same policy to
        // negentropy subscriptions as to REQ subscriptions.
        if self.relay.config.read().await.server.require_auth && !self.is_authed() {
            self.neg_err(&sub_id, "auth-required: please authenticate before syncing");
            return;
        }

        let max_items = self.relay.config.read().await.limits.neg_max_items;
        let max_subs = self.relay.config.read().await.limits.max_subscriptions;
        if self.neg.len() >= max_subs {
            self.neg_err(&sub_id, "error: too many subscriptions");
            return;
        }
        let now = unix_now();
        // The negentropy query only needs (created_at, id) records, so it
        // never materializes every matching full event in memory.
        let (items, more) = self.relay.db.neg_items(filter, max_items, now).await;
        if more || items.len() > max_items {
            // NIP-77: the maximum number of processable records may be
            // returned as the fourth element.
            self.send_json(json!([
                "NEG-ERR",
                sub_id,
                "blocked: this query is too big",
                max_items
            ]));
            return;
        }
        // NIP-70/NIP-29: withhold protected events from unauthenticated
        // peers and private/hidden group content from non-members, exactly
        // like the REQ path.
        let items: Vec<nip77::Item> = {
            let groups = self.relay.groups.read().await;
            items
                .into_iter()
                .filter(|(_, _, protected, gid, meta)| {
                    if *protected && !self.is_authed() {
                        return false;
                    }
                    if let Some(gid) = gid {
                        if self.authed_pubkeys.is_empty() {
                            groups.visible_gid(gid, *meta, None)
                        } else {
                            self.authed_pubkeys
                                .iter()
                                .any(|pk| groups.visible_gid(gid, *meta, Some(pk)))
                        }
                    } else {
                        true
                    }
                })
                .map(|(created, id, _, _, _)| (created, id))
                .collect()
        };
        let items = nip77::sort_items(items);

        // The items stay on this connection for the whole sync; bound the
        // total so that many concurrent NEG-OPENs cannot pin excessive
        // memory on a single connection.
        let total_cap = max_items.saturating_mul(2);
        // A NEG-OPEN for an already open subscription id replaces the
        // existing one (NIP-77): release the old items from the accounting
        // first so the total does not drift upward.
        if let Some(old) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(old.len());
        }
        if self.neg_total.saturating_add(items.len()) > total_cap {
            self.send_json(json!([
                "NEG-ERR",
                sub_id,
                "blocked: too many negentropy items",
                total_cap
            ]));
            return;
        }

        match nip77::respond(&items, &initial) {
            Ok(response) => {
                self.neg_total += items.len();
                self.neg.insert(sub_id.clone(), items);
                self.neg_msg(&sub_id, &response);
            }
            Err(reason) => {
                self.neg_err(&sub_id, &format!("error: {reason}"));
            }
        }
    }

    async fn handle_neg_msg(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            self.notice("error: NEG-MSG requires a subscription id and message");
            return;
        }
        let Some(sub_id) = value_string(&rest[0]) else {
            self.notice("error: NEG-MSG subscription id must be a string");
            return;
        };
        let Some(message) = rest[1].as_str() else {
            self.notice("error: NEG-MSG message must be hex");
            return;
        };
        let Ok(message) = hex::decode(message) else {
            self.notice("error: NEG-MSG message must be hex");
            return;
        };
        let Some(items) = self.neg.get(&sub_id) else {
            self.neg_err(&sub_id, "closed: unknown subscription");
            return;
        };
        match nip77::respond(items, &message) {
            Ok(response) => self.neg_msg(&sub_id, &response),
            Err(reason) => {
                // NIP-77: "After a NEG-ERR is issued, the subscription is
                // considered to be closed."
                if let Some(items) = self.neg.remove(&sub_id) {
                    self.neg_total = self.neg_total.saturating_sub(items.len());
                }
                self.neg_err(&sub_id, &format!("error: {reason}"));
            }
        }
    }

    fn handle_neg_close(&mut self, rest: &[Value]) {
        let Some(sub_id) = rest.first().and_then(value_string) else {
            self.notice("error: NEG-CLOSE requires a subscription id");
            return;
        };
        if let Some(items) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(items.len());
        }
    }
}

fn value_string(value: &Value) -> Option<String> {
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
                            conn.notice("error: message too large");
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
                            conn.notice("error: message too large");
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
                                conn.notice("error: message too large");
                                too_large = true;
                                break;
                            }
                            conn.in_msgs += 1;
                            conn.in_bytes += text.len() as u64;
                            conn.handle_text(&text).await;
                        }
                        Ok(Some(Ok(Message::Binary(data)))) => {
                            if data.len() > max_msg_size {
                                conn.notice("error: message too large");
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
    conn.relay
        .stats
        .connections_active
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}
