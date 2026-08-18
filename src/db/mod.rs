//! LMDB-backed event storage.
//!
//! The module is split into three layers:
//! - [`self`] (mod.rs): the [`DbClient`] handle, the request channel with
//!   its dedicated writer/reader threads and the batched write plumbing;
//! - [`store`]: the [`Store`] owning the LMDB environment, the write path
//!   (put/replace/delete/vanish/ban/expiry) and the index maintenance;
//! - [`scan`]: the query engine — filter matching, index-selected range
//!   walks and the REQ/COUNT/negentropy collectors.

mod removal;
mod scan;
mod store;
#[cfg(test)]
mod tests;
mod threads;

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use scan::NegItems;
use store::Store;

use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip09;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    Stored,
    Duplicate,
    Replaced,
    Expired,
    PreviouslyDeleted,
    /// NIP-01: kinds 20000-29999 are ephemeral and must not be stored
    /// (NIP-59 requires kind 21059 in particular to never be stored).
    /// The event is delivered live to subscribers and acknowledged with
    /// an `OK` carrying the `mute:` prefix.
    Ephemeral,
    Invalid(String),
}

impl Default for PutOutcome {
    fn default() -> Self {
        PutOutcome::Invalid("database unavailable".into())
    }
}

/// Records a database failure: bumps the error counter and logs a clear
/// operator-facing message, especially when the LMDB map size is exhausted.
pub(crate) fn db_error(errors: &Arc<std::sync::atomic::AtomicU64>, e: &crate::error::Error) {
    errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if matches!(
        e,
        crate::error::Error::Heed(heed::Error::Mdb(heed::MdbError::MapFull))
    ) {
        log::error!("database map is full: increase database.map_max_size in nostrd.toml");
    } else {
        log::error!("database error: {e}");
    }
}

enum Msg {
    Put {
        event: Event,
        now: u64,
        reply: oneshot::Sender<PutOutcome>,
    },
    Query {
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
        reply: oneshot::Sender<(Vec<Event>, bool)>,
    },
    /// Accepts many events in a single write transaction (one commit).
    PutBatch {
        events: Vec<(Event, u64)>,
        reply: oneshot::Sender<Vec<PutOutcome>>,
    },
    /// First-seen trust bookkeeping: records the arrival time of each
    /// pubkey when unknown and returns `(created, first_seen)` per entry.
    TouchFirstSeen {
        entries: Vec<([u8; 32], u64)>,
        reply: oneshot::Sender<Vec<(bool, u64)>>,
    },
    /// NIP-77: query returning only `(created_at, id)` records so that large
    /// negentropy ranges do not materialize every full event in memory.
    NegQuery {
        filter: Filter,
        limit: usize,
        now: u64,
        reply: oneshot::Sender<(NegItems, bool)>,
    },
    Count {
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        reply: oneshot::Sender<(Vec<Event>, bool)>,
    },
    Delete {
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
        reply: oneshot::Sender<usize>,
    },
    Vanish {
        pubkey: Vec<u8>,
        reply: oneshot::Sender<usize>,
    },
    /// NIP-59: delete gift wraps addressed to a pubkey (on NIP-09 deletion).
    GiftWrapPurge {
        pubkey: Vec<u8>,
        reply: oneshot::Sender<usize>,
    },
    PrefixExists {
        prefix: Vec<u8>,
        reply: oneshot::Sender<bool>,
    },
    /// Checks many event-id prefixes in one round trip (NIP-29 `previous`
    /// tag validation), so a single event cannot amplify into thousands of
    /// database requests.
    PrefixesExist {
        prefixes: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<bool>>,
    },
    ReplaceableCreatedAt {
        kind: u64,
        pubkey: String,
        d: String,
        reply: oneshot::Sender<Option<u64>>,
    },
    Ban {
        id: Vec<u8>,
        reason: String,
        reply: oneshot::Sender<bool>,
    },
    Unban {
        id: Vec<u8>,
        reply: oneshot::Sender<bool>,
    },
    ListBanned {
        reply: oneshot::Sender<Vec<(String, String)>>,
    },
    PurgeExpired {
        now: u64,
        reply: oneshot::Sender<usize>,
    },
    DatabaseSize {
        reply: oneshot::Sender<u64>,
    },
    #[cfg(test)]
    MapSize {
        reply: oneshot::Sender<u64>,
    },
    Shutdown,
}
#[derive(Clone)]
pub struct DbClient {
    tx: mpsc::UnboundedSender<Msg>,
    /// Dedicated channel for read-only requests: they are served by a
    /// separate thread that never takes the write lock, so reads keep
    /// working even when the writer is stalled (a slow disk or an external
    /// lock holder cannot take the relay down for readers).
    read_tx: mpsc::UnboundedSender<Msg>,
    /// Dedicated channel for REST API queries: served by its own reader
    /// thread, so a flood of `/api/v1` requests can never queue up behind
    /// (or in front of) WebSocket REQ/COUNT/NEG queries on the shared
    /// reader thread.
    api_read_tx: mpsc::UnboundedSender<Msg>,
    errors: Arc<std::sync::atomic::AtomicU64>,
    expiry: Arc<std::sync::atomic::AtomicBool>,
    /// Seconds a request may wait for the database thread before timing out
    /// (0 = wait forever). Keeps the relay responsive even when the storage
    /// is stuck: timed-out requests fail with a clear error instead of
    /// hanging the connection.
    timeout_secs: u64,
    /// Messages queued but not yet drained by the database thread. When the
    /// queue grows past the configured caps, new requests fail fast instead
    /// of piling up in memory: the relay keeps serving (slowly) instead of
    /// running out of memory.
    pending_msgs: Arc<std::sync::atomic::AtomicUsize>,
    /// Events inside the queued `PutBatch`/`Put` messages (the dominant
    /// memory of the queue).
    pending_events: Arc<std::sync::atomic::AtomicUsize>,
    /// Queued-but-unprocessed REST API queries, counted separately so an API
    /// flood fails fast without tripping the WebSocket-side caps.
    api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Caps for the counters above.
    max_pending_msgs: usize,
    max_pending_events: usize,
    max_api_pending: usize,
}

impl DbClient {
    pub fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: bool,
        errors: Arc<std::sync::atomic::AtomicU64>,
        request_timeout_secs: u64,
        max_indexed_words: usize,
        max_pending_msgs: usize,
        max_pending_events: usize,
    ) -> Result<DbClient> {
        let expiry = Arc::new(std::sync::atomic::AtomicBool::new(expiry_enabled));
        let store = Store::open(cfg, Arc::clone(&expiry), max_indexed_words)?;
        let threads = threads::spawn(
            store,
            expiry,
            errors,
            request_timeout_secs,
            max_pending_msgs,
            max_pending_events,
        )?;
        Ok(DbClient {
            tx: threads.tx,
            read_tx: threads.read_tx,
            api_read_tx: threads.api_read_tx,
            errors: threads.errors,
            expiry: threads.expiry,
            timeout_secs: threads.timeout_secs,
            pending_msgs: threads.pending_msgs,
            pending_events: threads.pending_events,
            api_pending: threads.api_pending,
            max_pending_msgs: threads.max_pending_msgs,
            max_pending_events: threads.max_pending_events,
            max_api_pending: threads.max_api_pending,
        })
    }

    pub fn set_expiry_enabled(&self, enabled: bool) {
        self.expiry
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    async fn request<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        self.request_with(make, &self.tx).await
    }

    /// Sends a read-only request to the dedicated reader thread.
    async fn request_read<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        self.request_with(make, &self.read_tx).await
    }

    async fn request_with<R: Default>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
    ) -> R {
        // Overload protection: when the database thread's queue is already
        // deep, new requests fail fast instead of accumulating in memory.
        // Callers degrade gracefully (empty replies, error outcomes).
        if self.pending_msgs.load(std::sync::atomic::Ordering::Relaxed) >= self.max_pending_msgs
            || self
                .pending_events
                .load(std::sync::atomic::Ordering::Relaxed)
                >= self.max_pending_events
        {
            // Surface the overload in the stats (db_errors).
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return R::default();
        }
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        self.pending_msgs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Msg::PutBatch { events, .. } = &msg {
            self.pending_events
                .fetch_add(events.len(), std::sync::atomic::Ordering::Relaxed);
        } else if let Msg::Put { .. } = &msg {
            self.pending_events
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if let Err(err) = channel.send(msg) {
            let msg = err.0;
            self.pending_msgs
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            if let Msg::PutBatch { events, .. } = &msg {
                self.pending_events
                    .fetch_sub(events.len(), std::sync::atomic::Ordering::Relaxed);
            } else if let Msg::Put { .. } = &msg {
                self.pending_events
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
            return R::default();
        }
        if self.timeout_secs == 0 {
            return rx.await.unwrap_or_default();
        }
        tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
            .await
            .map(|r| r.unwrap_or_default())
            .unwrap_or_default()
    }

    pub async fn put(&self, event: Event, now: u64) -> PutOutcome {
        self.request(|reply| Msg::Put { event, now, reply }).await
    }

    pub async fn query(&self, filters: Vec<Filter>, limit: usize, now: u64) -> (Vec<Event>, bool) {
        self.query_directed(filters, limit, now, false).await
    }

    /// Like [`Self::query`] but with an explicit scan direction: `false`
    /// returns newest events first (NIP-01), `true` returns oldest first.
    pub async fn query_directed(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
    ) -> (Vec<Event>, bool) {
        self.request_read(|reply| Msg::Query {
            filters,
            limit,
            now,
            ascending,
            reply,
        })
        .await
    }

    /// REST API query: served by the dedicated API reader thread so that
    /// `/api/v1` traffic never blocks WebSocket queries. Applies its own
    /// queue cap: when the API reader's queue is deep, the request fails
    /// fast with an empty result instead of piling up behind WebSocket
    /// work.
    pub async fn api_query(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
    ) -> (Vec<Event>, bool) {
        if self.api_pending.load(std::sync::atomic::Ordering::Relaxed) >= self.max_api_pending {
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let (tx, rx) = oneshot::channel();
        self.api_pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = Msg::Query {
            filters,
            limit,
            now,
            ascending,
            reply: tx,
        };
        if self.api_read_tx.send(msg).is_err() {
            self.api_pending
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let out = if self.timeout_secs == 0 {
            rx.await.unwrap_or_default()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default()
        };
        // The API reader thread decrements `api_pending` once it has
        // processed the message (including its panic path), so this path
        // must not decrement again.
        out
    }

    /// Records the first-seen time of each pubkey when unknown; returns
    /// `(created, first_seen)` per entry, aligned with the input.
    pub async fn touch_first_seen_batch(&self, entries: Vec<([u8; 32], u64)>) -> Vec<(bool, u64)> {
        self.request(|reply| Msg::TouchFirstSeen { entries, reply })
            .await
    }

    /// Stores a batch of events in a single write transaction.
    pub async fn put_batch(&self, events: Vec<(Event, u64)>) -> Vec<PutOutcome> {
        self.request(|reply| Msg::PutBatch { events, reply }).await
    }

    /// NIP-77: returns only `(created_at, id)` records of the matching
    /// events, keeping the memory footprint at a few bytes per record.
    pub async fn neg_items(&self, filter: Filter, limit: usize, now: u64) -> (NegItems, bool) {
        self.request_read(|reply| Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        })
        .await
    }

    pub async fn count(&self, filters: Vec<Filter>, limit: usize, now: u64) -> (Vec<Event>, bool) {
        self.request_read(|reply| Msg::Count {
            filters,
            limit,
            now,
            reply,
        })
        .await
    }

    pub async fn apply_deletion(
        &self,
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
    ) -> usize {
        self.request(|reply| Msg::Delete {
            targets,
            addresses,
            request_pubkey,
            request_created,
            reply,
        })
        .await
    }

    pub async fn apply_vanish(&self, pubkey: [u8; 32]) -> usize {
        self.request(|reply| Msg::Vanish {
            pubkey: pubkey.to_vec(),
            reply,
        })
        .await
    }

    /// NIP-59: deletes `kind:1059` gift wraps p-tagging `pubkey`.
    pub async fn delete_gift_wraps_to(&self, pubkey: [u8; 32]) -> usize {
        self.request(|reply| Msg::GiftWrapPurge {
            pubkey: pubkey.to_vec(),
            reply,
        })
        .await
    }

    pub async fn event_id_prefix_exists(&self, prefix: &[u8]) -> bool {
        self.request_read(|reply| Msg::PrefixExists {
            prefix: prefix.to_vec(),
            reply,
        })
        .await
    }

    /// Checks many event-id prefixes in a single database round trip.
    pub async fn prefixes_exist(&self, prefixes: Vec<Vec<u8>>) -> Vec<bool> {
        self.request_read(|reply| Msg::PrefixesExist { prefixes, reply })
            .await
    }

    /// Drains and returns the number of database errors since the last call.
    pub fn take_errors(&self) -> u64 {
        self.errors.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Bans an event id (NIP-86 banevent): removes it from storage and
    /// prevents re-publication. Returns whether the event was stored.
    pub async fn ban_event(&self, id: [u8; 32], reason: &str) -> bool {
        self.request(|reply| Msg::Ban {
            id: id.to_vec(),
            reason: reason.to_string(),
            reply,
        })
        .await
    }

    pub async fn unban_event(&self, id: [u8; 32]) -> bool {
        self.request(|reply| Msg::Unban {
            id: id.to_vec(),
            reply,
        })
        .await
    }

    pub async fn list_banned_events(&self) -> Vec<(String, String)> {
        self.request_read(|reply| Msg::ListBanned { reply }).await
    }

    /// The created_at of the stored version of a replaceable/addressable
    /// event, used by the relay to stamp its generated events strictly
    /// newer.
    pub async fn replaceable_created_at(&self, kind: u64, pubkey: &str, d: &str) -> Option<u64> {
        self.request_read(|reply| Msg::ReplaceableCreatedAt {
            kind,
            pubkey: pubkey.to_string(),
            d: d.to_string(),
            reply,
        })
        .await
    }

    pub async fn purge_expired(&self, now: u64) -> usize {
        self.request(|reply| Msg::PurgeExpired { now, reply }).await
    }

    pub async fn size_on_disk(&self) -> u64 {
        self.request_read(|reply| Msg::DatabaseSize { reply }).await
    }

    /// Current memory map size in bytes (used by tests to verify growth).
    #[cfg(test)]
    pub async fn map_size_now(&self) -> u64 {
        self.request_read(|reply| Msg::MapSize { reply }).await
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        let _ = self.read_tx.send(Msg::Shutdown);
        let _ = self.api_read_tx.send(Msg::Shutdown);
    }
}
