//! NIP-43 role administration: role definitions and member assignments
//! managed through the NIP-86 RPC, plus the published membership list
//! and add/remove-user events.

use crate::db::PutOutcome;
use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

use super::relay_dtag;

impl super::Relay {
    /// Signs, stores and broadcasts a relay-generated event. For replaceable
    /// or addressable kinds the event is stamped strictly newer than the
    /// stored version so that NIP-01's same-timestamp tie-break (lowest id
    /// wins) can never keep an older version.
    pub(crate) async fn store_relay_event(&self, event: &mut Event) -> bool {
        let Some(keypair) = &self.key else {
            return false;
        };
        if (crate::nips::nip01::is_replaceable_kind(event.kind)
            || crate::nips::nip33::is_param_replaceable_kind(event.kind))
            && let Some(old_created) = self
                .db
                .replaceable_created_at(event.kind, &event.pubkey, &relay_dtag(event))
                .await
        {
            event.created_at = event.created_at.max(old_created.saturating_add(1));
        }
        if nip01::sign(event, keypair, &self.secp).is_err() {
            return false;
        }
        let now = unix_now();
        let outcome = self.db.put(event.clone(), now).await;
        if matches!(outcome, PutOutcome::Stored | PutOutcome::Replaced) {
            self.broadcast(event.clone());
            true
        } else {
            false
        }
    }

    /// Signs, stores and broadcasts a relay-generated event.
    async fn publish_relay_event(&self, mut event: Event) {
        let _ = self.store_relay_event(&mut event).await;
    }

    /// Publishes the current membership list and an add/remove user event.
    pub(crate) async fn publish_membership(&self, change: Option<(bool, String)>) {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return;
        };
        let now = unix_now();
        let (add, pubkey) = match change {
            Some((add, pubkey)) => (add, Some(pubkey)),
            None => (false, None),
        };
        let events = {
            let roles = self.roles.read().await;
            let mut events = vec![roles.membership_event(&relay_pubkey, now)];
            if let Some(pubkey) = pubkey {
                events.push(if add {
                    roles.add_user_event(&pubkey, &relay_pubkey, now)
                } else {
                    roles.remove_user_event(&pubkey, &relay_pubkey, now)
                });
            }
            events
        };
        for event in events {
            self.publish_relay_event(event).await;
        }
    }

    /// NIP-43 role management, used by the NIP-86 RPC methods.
    pub async fn create_role(
        &self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        let event = {
            let mut roles = self.roles.write().await;
            roles.create(id, label, description, color, order);
            roles.role_event(id, &relay_pubkey, unix_now())
        };
        self.publish_relay_event(event).await;
        true
    }

    pub async fn delete_role(&self, id: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let removed = self.roles.write().await.delete(id);
        if removed {
            self.publish_membership(None).await;
        }
        removed
    }

    pub async fn assign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let assigned = self.roles.write().await.assign(pubkey, role);
        if assigned {
            self.publish_membership(Some((true, pubkey.to_string())))
                .await;
        }
        assigned
    }

    pub async fn unassign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let changed = self.roles.write().await.unassign(pubkey, role);
        if changed {
            self.publish_membership(Some((false, pubkey.to_string())))
                .await;
        }
        changed
    }

    /// NIP-43 leave request: removes the user from the member list and
    /// republishes it with a remove-user event.
    pub(crate) async fn apply_leave_request(&self, event: &Event) {
        let removed = self.roles.write().await.remove_pubkey(&event.pubkey);
        if removed {
            self.publish_membership(Some((false, event.pubkey.clone())))
                .await;
        }
    }
}
