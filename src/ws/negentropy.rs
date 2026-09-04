//! NIP-77 negentropy message handling: `NEG-OPEN`/`NEG-MSG`/`NEG-CLOSE`
//! and the `NEG-ERR` replies. The reconciliation protocol itself lives in
//! [`crate::nips::nip77`].

use serde_json::{Value, json};

use crate::filter::Filter;
use crate::nips::nip77;
use crate::util::unix_now;

use super::value_string;

/// NIP-77 negentropy state for one open subscription.
pub(crate) struct NegState {
    pub(crate) items: Vec<nip77::Item>,
    /// Remaining NEG-MSG rounds for this subscription. The reconciliation
    /// protocol completes in a bounded number of rounds proportional to the
    /// number of divergent ranges; a peer that keeps sending NEG-MSG with
    /// bogus fingerprints would otherwise force an unbounded, CPU-bounded
    /// bisection over the held items on every message.
    pub(crate) rounds_left: u32,
}

/// Cap on the number of NEG-MSG rounds a single subscription may consume
/// before it is closed (generous for legitimate syncs).
pub(crate) const MAX_NEG_MSG_ROUNDS: u32 = 128;

impl super::Conn {
    pub(crate) fn send_neg_err(&mut self, sub_id: &str, reason: &str) {
        self.send_json(json!(["NEG-ERR", sub_id, reason]));
    }

    pub(crate) fn send_neg_msg(&mut self, sub_id: &str, message: &[u8]) {
        self.send_json(json!(["NEG-MSG", sub_id, hex::encode(message)]));
    }

    pub(crate) async fn handle_neg_open(&mut self, rest: &[Value]) {
        if !self.relay.config.read().await.nip_enabled(77) {
            self.send_notice("error: negentropy is not enabled on this relay");
            return;
        }
        if rest.len() < 3 {
            self.send_notice("error: NEG-OPEN requires a subscription id, filter and message");
            return;
        }
        let sub_id = match value_string(&rest[0]) {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.send_notice("error: NEG-OPEN subscription id must be a non-empty string");
                return;
            }
        };
        let max_sub_id_len = self.relay.config.read().await.limits.max_sub_id_len;
        if sub_id.len() > max_sub_id_len {
            self.send_neg_err(&sub_id, "error: NEG-OPEN subscription id too long");
            return;
        }
        let mut raw = rest[1].clone();
        if crate::filter::rewrite_inbox_outbox(&mut raw).is_err() {
            self.send_neg_err(&sub_id, "error: invalid NEG-OPEN filter");
            return;
        }
        let filter: Filter = match serde_json::from_value::<Filter>(raw) {
            Ok(mut filter) => {
                // Negentropy needs every matching record, not a capped page.
                filter.limit = None;
                filter
            }
            Err(_) => {
                self.send_neg_err(&sub_id, "error: invalid NEG-OPEN filter");
                return;
            }
        };
        if filter.too_many_members() {
            self.send_neg_err(&sub_id, "error: too many ids or authors in the filter");
            return;
        }
        let Some(initial) = rest[2].as_str() else {
            self.send_neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };
        let Ok(initial) = hex::decode(initial) else {
            self.send_neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };
        // NIP-42: an auth-requiring relay applies the same policy to
        // negentropy subscriptions as to REQ subscriptions.
        if self.relay.config.read().await.relay.require_auth && !self.is_authed() {
            self.send_neg_err(&sub_id, "auth-required: please authenticate before syncing");
            return;
        }

        let max_items = self.relay.config.read().await.limits.max_neg_items;
        let max_subs = self.relay.config.read().await.limits.max_subscriptions;
        if self.neg.len() >= max_subs {
            self.send_neg_err(&sub_id, "error: too many subscriptions");
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
        // NIP-70/NIP-59/NIP-29: withhold protected events from
        // unauthenticated peers, gift wraps from anyone but their
        // recipients, and private/hidden group content from non-members,
        // exactly like the REQ path.
        let items: Vec<nip77::Item> = {
            let groups = self.relay.groups.read().await;
            items
                .into_iter()
                .filter(|item| {
                    if item.protected && !self.is_authed() {
                        return false;
                    }
                    if item.wrap_recipients.is_some()
                        && !self.authed_pubkeys.iter().any(|pk| {
                            item.wrap_recipients
                                .as_ref()
                                .is_some_and(|recips| recips.iter().any(|r| r == pk))
                        })
                    {
                        return false;
                    }
                    if let Some(gid) = &item.gid {
                        if self.authed_pubkeys.is_empty() {
                            groups.visible_gid(gid, item.meta, None)
                        } else {
                            self.authed_pubkeys
                                .iter()
                                .any(|pk| groups.visible_gid(gid, item.meta, Some(pk)))
                        }
                    } else {
                        true
                    }
                })
                .map(|item| (item.created, item.id))
                .collect()
        };
        let items = nip77::sort_items(items);

        // The items stay on this connection for the whole sync; bound the
        // total so that many concurrent NEG-OPENs cannot pin excessive
        // memory on a single connection.
        let total_cap = max_items.saturating_mul(2);
        // A NEG-OPEN for an already open subscription id replaces the
        // existing one (NIP-77). Account for the replacement *before*
        // removing the old state, so a failing NEG-OPEN (too many items)
        // cannot silently close the peer's existing subscription.
        let old_len = self
            .neg
            .get(&sub_id)
            .map(|state| state.items.len())
            .unwrap_or(0);
        if self
            .neg_total
            .saturating_sub(old_len)
            .saturating_add(items.len())
            > total_cap
        {
            self.send_json(json!([
                "NEG-ERR",
                sub_id,
                "blocked: too many negentropy items",
                total_cap
            ]));
            return;
        }
        if let Some(old) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(old.items.len());
            // Release the subscription slot of the replaced negentropy
            // subscription (the new one re-acquires it below).
            self.relay
                .stats
                .subscriptions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        match nip77::respond(&items, &initial) {
            Ok(response) => {
                self.neg_total += items.len();
                self.neg.insert(
                    sub_id.clone(),
                    NegState {
                        items,
                        rounds_left: MAX_NEG_MSG_ROUNDS,
                    },
                );
                // NEG-OPEN subscriptions are active subscriptions: they hold
                // filters and items until closed, so they count towards
                // `subscriptions_active` like REQ subscriptions.
                self.relay
                    .stats
                    .subscriptions_active
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.send_neg_msg(&sub_id, &response);
            }
            Err(reason) => {
                self.send_neg_err(&sub_id, &format!("error: {reason}"));
            }
        }
    }

    pub(crate) async fn handle_neg_msg(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            self.send_notice("error: NEG-MSG requires a subscription id and message");
            return;
        }
        let Some(sub_id) = value_string(&rest[0]) else {
            self.send_notice("error: NEG-MSG subscription id must be a string");
            return;
        };
        let Some(message) = rest[1].as_str() else {
            self.send_notice("error: NEG-MSG message must be hex");
            return;
        };
        let Ok(message) = hex::decode(message) else {
            self.send_notice("error: NEG-MSG message must be hex");
            return;
        };
        let Some(state) = self.neg.get_mut(&sub_id) else {
            self.send_neg_err(&sub_id, "closed: unknown subscription");
            return;
        };
        // NIP-77: "After a NEG-ERR is issued, the subscription is considered
        // to be closed." Exhausting the round budget closes it too.
        if state.rounds_left == 0 {
            if let Some(state) = self.neg.remove(&sub_id) {
                self.neg_total = self.neg_total.saturating_sub(state.items.len());
                self.release_neg_stats_subscription();
            }
            self.send_neg_err(&sub_id, "error: too many negentropy messages");
            return;
        }
        state.rounds_left -= 1;
        match nip77::respond(&state.items, &message) {
            Ok(response) => self.send_neg_msg(&sub_id, &response),
            Err(reason) => {
                if let Some(state) = self.neg.remove(&sub_id) {
                    self.neg_total = self.neg_total.saturating_sub(state.items.len());
                    self.release_neg_stats_subscription();
                }
                self.send_neg_err(&sub_id, &format!("error: {reason}"));
            }
        }
    }

    /// Decrements `subscriptions_active` for a closed negentropy
    /// subscription (every NEG-OPEN success acquired one slot).
    pub(crate) fn release_neg_stats_subscription(&self) {
        self.relay
            .stats
            .subscriptions_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn handle_neg_close(&mut self, rest: &[Value]) {
        let Some(sub_id) = rest.first().and_then(value_string) else {
            self.send_notice("error: NEG-CLOSE requires a subscription id");
            return;
        };
        if let Some(state) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(state.items.len());
            self.release_neg_stats_subscription();
        }
    }
}
