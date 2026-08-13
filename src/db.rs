use std::collections::HashSet;
use std::sync::Arc;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, RoTxn};
use tokio::sync::{mpsc, oneshot};

use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip09, nip33, nip40, nip50};

const EVENTS: &str = "events";
const BY_CREATED: &str = "by_created";
const BY_PUBKEY: &str = "by_pubkey";
const BY_KIND: &str = "by_kind";
const BY_TAG: &str = "by_tag";
const BY_WORD: &str = "by_word";
const DELETED: &str = "deleted";
const EXPIRY: &str = "expiry";
const REPLACEABLE: &str = "replaceable";
const VANISH: &str = "vanish";
const BANNED: &str = "banned";

const CREATED_LEN: usize = 8;
const ID_LEN: usize = 32;
const TAG_VALUE_MAX: usize = 1024;

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
fn db_error(errors: &Arc<std::sync::atomic::AtomicU64>, e: &crate::error::Error) {
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
        reply: oneshot::Sender<(Vec<Event>, bool)>,
    },
    /// Accepts many events in a single write transaction (one commit).
    PutBatch {
        events: Vec<(Event, u64)>,
        reply: oneshot::Sender<Vec<PutOutcome>>,
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
    errors: Arc<std::sync::atomic::AtomicU64>,
    expiry: Arc<std::sync::atomic::AtomicBool>,
}

impl DbClient {
    pub fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: bool,
        errors: Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<DbClient> {
        let expiry = Arc::new(std::sync::atomic::AtomicBool::new(expiry_enabled));
        let store = Store::open(cfg, Arc::clone(&expiry))?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let thread_errors = Arc::clone(&errors);
        std::thread::spawn(move || {
            // Puts are applied in batches sharing one write transaction so
            // that the LMDB commit cost (a full fsync by default) is paid
            // once per batch instead of once per event. Replies are only
            // sent after the commit, so an OK implies durability.
            const BATCH: usize = 64;
            let mut pending: Option<heed::RwTxn> = None;
            let mut batch_puts: Vec<(Event, u64)> = Vec::new();
            let mut senders: Vec<oneshot::Sender<PutOutcome>> = Vec::new();
            // Put batches received within the current message drain, merged
            // into a single commit at flush time.
            let mut pending_batches: Vec<PutBatchMsg> = Vec::new();
            'outer: loop {
                let Some(msg) = rx.blocking_recv() else {
                    // The channel is closed (every DbClient was dropped
                    // without a shutdown): flush any pending batch so that
                    // awaiting requests are not left hanging.
                    flush_everything(
                        &store,
                        &thread_errors,
                        &mut pending,
                        &mut batch_puts,
                        &mut senders,
                        &mut pending_batches,
                    );
                    break;
                };
                // The database thread is the single point of failure for
                // every request: a panic here would hang all clients, so
                // the whole batch handling is isolated. After a panic (which
                // the code audit makes unreachable) the state is reset and
                // the thread keeps serving.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut msgs = vec![msg];
                    for _ in 0..BATCH - 1 {
                        match rx.try_recv() {
                            Ok(m) => msgs.push(m),
                            Err(_) => break,
                        }
                    }
                    for msg in msgs {
                        match msg {
                            Msg::Put { event, now, reply } => {
                                if pending.is_none() {
                                    match store.env.write_txn() {
                                        Ok(txn) => pending = Some(txn),
                                        Err(e) => {
                                            db_error(&thread_errors, &e.into());
                                            let _ = reply
                                                .send(PutOutcome::Invalid("database error".into()));
                                            continue;
                                        }
                                    }
                                }
                                batch_puts.push((event, now));
                                senders.push(reply);
                            }
                            Msg::PutBatch { events, reply } => {
                                pending_batches.push((events, reply));
                            }
                            Msg::Shutdown => {
                                flush_everything(
                                    &store,
                                    &thread_errors,
                                    &mut pending,
                                    &mut batch_puts,
                                    &mut senders,
                                    &mut pending_batches,
                                );
                                let _ = store.env.force_sync();
                                return true;
                            }
                            other => {
                                // Work that is not a plain put commits the
                                // batch first so that ordering is preserved.
                                flush_everything(
                                    &store,
                                    &thread_errors,
                                    &mut pending,
                                    &mut batch_puts,
                                    &mut senders,
                                    &mut pending_batches,
                                );
                                match other {
                                    Msg::Query {
                                        filters,
                                        limit,
                                        now,
                                        reply,
                                    } => {
                                        let out = match store.scan(&filters, now, limit, false) {
                                            Ok(out) => out,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                (Vec::new(), false)
                                            }
                                        };
                                        let _ = reply.send(out);
                                    }
                                    Msg::NegQuery {
                                        filter,
                                        limit,
                                        now,
                                        reply,
                                    } => {
                                        let out = match store.scan_neg(&filter, now, limit) {
                                            Ok(out) => out,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                (Vec::new(), false)
                                            }
                                        };
                                        let _ = reply.send(out);
                                    }
                                    Msg::Count {
                                        filters,
                                        limit,
                                        now,
                                        reply,
                                    } => {
                                        let out = match store.scan(&filters, now, limit, true) {
                                            Ok(out) => out,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                (Vec::new(), false)
                                            }
                                        };
                                        let _ = reply.send(out);
                                    }
                                    Msg::Delete {
                                        targets,
                                        addresses,
                                        request_pubkey,
                                        request_created,
                                        reply,
                                    } => {
                                        let n = match store.apply_deletion(
                                            &targets,
                                            &addresses,
                                            request_pubkey.as_deref(),
                                            request_created,
                                        ) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                0
                                            }
                                        };
                                        let _ = reply.send(n);
                                    }
                                    Msg::Vanish { pubkey, reply } => {
                                        let n = match store.apply_vanish(&pubkey) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                0
                                            }
                                        };
                                        let _ = reply.send(n);
                                    }
                                    Msg::GiftWrapPurge { pubkey, reply } => {
                                        let n = match store.delete_gift_wraps_to(&pubkey) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                0
                                            }
                                        };
                                        let _ = reply.send(n);
                                    }
                                    Msg::PrefixExists { prefix, reply } => {
                                        let exists = match store.event_id_prefix_exists(&prefix) {
                                            Ok(exists) => exists,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        let _ = reply.send(exists);
                                    }
                                    Msg::ReplaceableCreatedAt {
                                        kind,
                                        pubkey,
                                        d,
                                        reply,
                                    } => {
                                        let created =
                                            match store.replaceable_created_at(kind, &pubkey, &d) {
                                                Ok(created) => created,
                                                Err(e) => {
                                                    db_error(&thread_errors, &e);
                                                    None
                                                }
                                            };
                                        let _ = reply.send(created);
                                    }
                                    Msg::Ban { id, reason, reply } => {
                                        let banned = match store.apply_ban(&id, &reason) {
                                            Ok(banned) => banned,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        let _ = reply.send(banned);
                                    }
                                    Msg::Unban { id, reply } => {
                                        let unbanned = match store.apply_unban(&id) {
                                            Ok(unbanned) => unbanned,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        let _ = reply.send(unbanned);
                                    }
                                    Msg::ListBanned { reply } => {
                                        let banned = match store.list_banned() {
                                            Ok(banned) => banned,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                Vec::new()
                                            }
                                        };
                                        let _ = reply.send(banned);
                                    }
                                    Msg::PurgeExpired { now, reply } => {
                                        let n = match store.purge_expired(now) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                0
                                            }
                                        };
                                        let _ = reply.send(n);
                                    }
                                    Msg::DatabaseSize { reply } => {
                                        let _ = reply.send(store.size_on_disk());
                                    }
                                    #[cfg(test)]
                                    Msg::MapSize { reply } => {
                                        let _ = reply.send(store.env.info().map_size as u64);
                                    }
                                    Msg::PutBatch { .. } | Msg::Put { .. } | Msg::Shutdown => {
                                        unreachable!()
                                    }
                                }
                            }
                        }
                    }
                    // Flush the batch before blocking again: clients await
                    // their replies, so a pending batch must not wait for
                    // the next message or every requestor deadlocks.
                    flush_everything(
                        &store,
                        &thread_errors,
                        &mut pending,
                        &mut batch_puts,
                        &mut senders,
                        &mut pending_batches,
                    );
                    false
                }));
                match result {
                    Ok(false) => {}
                    Ok(true) => break 'outer,
                    Err(_) => {
                        log::error!("database thread recovered from a panic");
                        pending = None;
                        for s in senders.drain(..) {
                            let _ = s.send(PutOutcome::Invalid("database error".into()));
                        }
                        batch_puts.clear();
                    }
                }
            }
        });
        Ok(DbClient { tx, errors, expiry })
    }

    /// Toggles NIP-40 expiration handling at runtime (config reload).
    pub fn set_expiry_enabled(&self, enabled: bool) {
        self.expiry
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    async fn request<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(make(tx)).is_err() {
            return R::default();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn put(&self, event: Event, now: u64) -> PutOutcome {
        self.request(|reply| Msg::Put { event, now, reply }).await
    }

    pub async fn query(&self, filters: Vec<Filter>, limit: usize, now: u64) -> (Vec<Event>, bool) {
        self.request(|reply| Msg::Query {
            filters,
            limit,
            now,
            reply,
        })
        .await
    }

    /// Stores a batch of events in a single write transaction.
    pub async fn put_batch(&self, events: Vec<(Event, u64)>) -> Vec<PutOutcome> {
        self.request(|reply| Msg::PutBatch { events, reply }).await
    }

    /// NIP-77: returns only `(created_at, id)` records of the matching
    /// events, keeping the memory footprint at a few bytes per record.
    pub async fn neg_items(&self, filter: Filter, limit: usize, now: u64) -> (NegItems, bool) {
        self.request(|reply| Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        })
        .await
    }

    pub async fn count(&self, filters: Vec<Filter>, limit: usize, now: u64) -> (Vec<Event>, bool) {
        self.request(|reply| Msg::Count {
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
        self.request(|reply| Msg::PrefixExists {
            prefix: prefix.to_vec(),
            reply,
        })
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
        self.request(|reply| Msg::ListBanned { reply }).await
    }

    /// The created_at of the stored version of a replaceable/addressable
    /// event, used by the relay to stamp its generated events strictly
    /// newer.
    pub async fn replaceable_created_at(&self, kind: u64, pubkey: &str, d: &str) -> Option<u64> {
        self.request(|reply| Msg::ReplaceableCreatedAt {
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
        self.request(|reply| Msg::DatabaseSize { reply }).await
    }

    /// Current memory map size in bytes (used by tests to verify growth).
    #[cfg(test)]
    pub async fn map_size_now(&self) -> u64 {
        self.request(|reply| Msg::MapSize { reply }).await
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
    }
}

/// Applies `puts` in one write transaction and commits. When the commit
/// fails because the memory map is full, the map is grown (up to
/// `map_max_size`) and the whole batch is re-applied in a fresh
/// transaction. Returns one outcome per put; all outcomes are
/// `Invalid("...")` when the batch cannot be committed.
fn apply_put_batch(
    store: &Store,
    thread_errors: &Arc<std::sync::atomic::AtomicU64>,
    mut pending: Option<heed::RwTxn>,
    puts: &[(Event, u64)],
) -> Vec<PutOutcome> {
    if puts.is_empty() {
        if let Some(txn) = pending
            && let Err(e) = txn.commit()
        {
            db_error(thread_errors, &e.into());
        }
        return Vec::new();
    }
    // Disk-full guard: writing to the memory map of a file on a full disk
    // raises SIGBUS and kills the process, so refuse to commit while the
    // free space is below the margin. Reads keep working.
    if let Some(free) = store.free_space()
        && free < DISK_FREE_MARGIN
    {
        log::error!(
            "disk is full: refusing to commit {} events ({} bytes free)",
            puts.len(),
            free
        );
        return vec![PutOutcome::Invalid("error: disk is full".into()); puts.len()];
    }
    loop {
        // LMDB allows a single writer: reuse the pending transaction if one
        // is open, otherwise open a fresh one.
        let mut txn = match pending.take() {
            Some(t) => t,
            None => match store.env.write_txn() {
                Ok(t) => t,
                Err(e) => {
                    db_error(thread_errors, &e.into());
                    return vec![PutOutcome::Invalid("database error".into()); puts.len()];
                }
            },
        };
        let mut outcomes = Vec::with_capacity(puts.len());
        let mut poisoned = false;
        for (event, now) in puts {
            match store.put_event_in(&mut txn, event, *now) {
                Ok(out) => outcomes.push(out),
                Err(e) => {
                    db_error(thread_errors, &e);
                    poisoned = true;
                    break;
                }
            }
        }
        if poisoned {
            // The transaction is unusable: abort it and revoke every reply
            // queued for it, because the applied puts were rolled back with
            // it and their OK would be a lie.
            return vec![PutOutcome::Invalid("database error".into()); puts.len()];
        }
        match txn.commit() {
            Ok(()) => {
                store.grow_map_if_needed();
                return outcomes;
            }
            Err(heed::Error::Mdb(heed::MdbError::MapFull)) => {
                if !store.grow_map() {
                    // The map cannot grow further: the batch cannot be
                    // committed, so every reply is revoked.
                    return vec![PutOutcome::Invalid("database error".into()); puts.len()];
                }
                // Retry the whole batch in the larger map.
            }
            Err(e) => {
                db_error(thread_errors, &e.into());
                return vec![PutOutcome::Invalid("database error".into()); puts.len()];
            }
        }
    }
}

/// A batch of events to store in one transaction, with its reply.
type PutBatchMsg = (Vec<(Event, u64)>, oneshot::Sender<Vec<PutOutcome>>);

/// Commits the pending single-put batch together with every queued
/// `PutBatch`, merging them all into one write transaction (one commit for
/// events arriving from many connections). Replies are only sent after a
/// successful commit, so an OK implies durability.
#[allow(clippy::too_many_arguments)]
fn flush_everything(
    store: &Store,
    thread_errors: &Arc<std::sync::atomic::AtomicU64>,
    pending: &mut Option<heed::RwTxn>,
    batch_puts: &mut Vec<(Event, u64)>,
    senders: &mut Vec<oneshot::Sender<PutOutcome>>,
    pending_batches: &mut Vec<PutBatchMsg>,
) {
    if batch_puts.is_empty() && pending_batches.is_empty() {
        if let Some(wtxn) = pending.take()
            && let Err(e) = wtxn.commit()
        {
            db_error(thread_errors, &e.into());
        }
        return;
    }
    // Merge the singles and every queued batch into one list; the split
    // points let the outcomes be distributed back in order.
    let mut all: Vec<(Event, u64)> = std::mem::take(batch_puts);
    let mut splits: Vec<usize> = vec![all.len()];
    for (events, _) in pending_batches.iter_mut() {
        all.append(events);
        splits.push(all.len());
    }
    let outcomes = apply_put_batch(store, thread_errors, pending.take(), &all);
    for (s, out) in senders
        .drain(..)
        .zip(outcomes.iter().take(splits[0]).cloned())
    {
        let _ = s.send(out);
    }
    for (i, (_, reply)) in pending_batches.drain(..).enumerate() {
        let range = splits[i]..splits[i + 1];
        let _ = reply.send(outcomes[range].to_vec());
    }
}

struct Store {
    env: Env,
    events: Database<Bytes, Bytes>,
    by_created: Database<Bytes, Bytes>,
    by_pubkey: Database<Bytes, Bytes>,
    by_kind: Database<Bytes, Bytes>,
    by_tag: Database<Bytes, Bytes>,
    by_word: Option<Database<Bytes, Bytes>>,
    deleted: Database<Bytes, Bytes>,
    expiry: Database<Bytes, Bytes>,
    replaceable: Database<Bytes, Bytes>,
    vanish: Database<Bytes, Bytes>,
    banned: Database<Bytes, Bytes>,
    /// NIP-40 expiration handling is only active when the NIP is enabled.
    /// Shared with the relay so that a config reload can toggle it at runtime.
    expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Ceiling for the automatic map growth (bytes).
    map_max_size: u64,
    /// System page size in bytes (LMDB uses it for its pages).
    page_size: usize,
}

/// `(created_at, id)` records returned by the NIP-77 negentropy query.
type NegItems = Vec<(u64, [u8; 32])>;

/// Output collector for a scan: either full events (REQ/COUNT) or
/// `(created_at, id)` records (NIP-77 negentropy, memory-efficient).
trait ScanCollector {
    fn len(&self) -> usize;
    /// Pushes a matched event; must return `false` when the per-filter
    /// limit is reached so the scan stops.
    fn push(&mut self, event: Event, id: [u8; 32], limit: usize) -> bool;
    /// Sorts the collected records by the NIP-01 ordering (newest first).
    fn sort_key(&mut self);
}

struct EventCollector(Vec<Event>);

impl ScanCollector for EventCollector {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn push(&mut self, event: Event, _id: [u8; 32], limit: usize) -> bool {
        self.0.push(event);
        self.0.len() < limit
    }
    fn sort_key(&mut self) {
        self.0.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
    }
}

struct ItemCollector(NegItems);

impl ScanCollector for ItemCollector {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn push(&mut self, event: Event, id: [u8; 32], limit: usize) -> bool {
        self.0.push((event.created_at, id));
        self.0.len() < limit
    }
    fn sort_key(&mut self) {
        self.0
            .sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    }
}

impl Store {
    fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Store> {
        std::fs::create_dir_all(&cfg.path)?;
        // SAFETY: the returned `Env` is owned by `Store` and outlives every
        // transaction created from it within this process.
        // The map is virtual address space: on 64-bit systems the growth
        // ceiling can be huge; on 32-bit systems LMDB is limited to ~2 GiB.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let page_size = page_size.max(4096);
        let mut map_size = (cfg.map_size as u64).max(16 * 1024 * 1024);
        let mut map_max_size = (cfg.map_max_size as u64).max(map_size);
        if usize::BITS < 64 {
            let cap = 2u64 * 1024 * 1024 * 1024;
            map_size = map_size.min(cap);
            map_max_size = map_max_size.min(cap);
        }
        let env = unsafe {
            EnvOpenOptions::new()
                .max_dbs(cfg.max_dbs.max(16))
                .max_readers(cfg.max_readers.max(8))
                .map_size(map_size as usize)
                .open(&cfg.path)?
        };

        let mut wtxn = env.write_txn()?;
        let events = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(EVENTS))?;
        let by_created = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_CREATED))?;
        let by_pubkey = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_PUBKEY))?;
        let by_kind = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_KIND))?;
        let by_tag = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_TAG))?;
        let by_word = if cfg.search_index {
            Some(env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_WORD))?)
        } else {
            None
        };
        let deleted = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(DELETED))?;
        let expiry = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(EXPIRY))?;
        let replaceable = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(REPLACEABLE))?;
        let vanish = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(VANISH))?;
        let banned = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BANNED))?;
        wtxn.commit()?;

        Ok(Store {
            env,
            events,
            by_created,
            by_pubkey,
            by_kind,
            by_tag,
            by_word,
            deleted,
            expiry,
            replaceable,
            vanish,
            banned,
            expiry_enabled,
            map_max_size,
            page_size,
        })
    }

    /// Grows the memory map (doubling it, at least covering the current
    /// usage) up to `map_max_size`. Returns `false` when the map cannot
    /// grow further, meaning the database is full for good.
    ///
    /// Must be called with no transactions active: the DB thread is the only
    /// user of the environment and calls this between messages, after a
    /// failed commit has consumed its transaction.
    fn grow_map(&self) -> bool {
        let info = self.env.info();
        let current = info.map_size as u64;
        let used = info.last_page_number as u64 * self.page_size as u64;
        let target = current
            .saturating_mul(2)
            .max(used.saturating_mul(2))
            .min(self.map_max_size);
        if target <= current {
            log::error!(
                "database map is full and cannot grow beyond {} bytes (map_max_size)",
                self.map_max_size
            );
            return false;
        }
        let target = target.div_ceil(self.page_size as u64) * self.page_size as u64;
        // SAFETY: the environment is only used by this thread and no
        // transaction is active at this point.
        match unsafe { self.env.resize(target as usize) } {
            Ok(()) => {
                log::info!("database map resized to {target} bytes");
                true
            }
            Err(e) => {
                // A failed resize must be reported so the caller does not
                // retry into an infinite loop.
                log::error!("database map resize to {target} bytes failed: {e}");
                false
            }
        }
    }

    /// Grows the map proactively when it is more than 90% used, so that
    /// subsequent commits do not pay the grow-and-retry cost.
    fn grow_map_if_needed(&self) {
        let info = self.env.info();
        let used = info.last_page_number as u64 * self.page_size as u64;
        let current = info.map_size as u64;
        if used > current.saturating_mul(9) / 10 {
            self.grow_map();
        }
    }

    /// Free bytes on the filesystem hosting the data directory, when
    /// statvfs succeeds.
    fn free_space(&self) -> Option<u64> {
        let path = self.env.path();
        let dir = if path.is_file() {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        let c_path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok()?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `stat` points at a valid buffer and the path is a valid
        // NUL-terminated string.
        if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } == 0 {
            let stat = unsafe { stat.assume_init() };
            Some(stat.f_bavail * stat.f_frsize)
        } else {
            None
        }
    }

    fn size_on_disk(&self) -> u64 {
        self.env.real_disk_size().unwrap_or(0)
    }
}

/// Minimum free space required before a batch of writes is committed.
/// Writing to the memory map of a file on a completely full disk raises
/// SIGBUS (killing the process), so the relay refuses to commit while the
/// free space is below this margin and keeps serving reads.
const DISK_FREE_MARGIN: u64 = 32 * 1024 * 1024;

// ----- key builders -----

fn created_key(created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN + ID_LEN);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

fn pubkey_key(pubkey: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ID_LEN + CREATED_LEN + ID_LEN);
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

fn kind_key(kind: u64, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN * 2 + ID_LEN);
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

fn tag_key(name: u8, value: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 1 + 4 + value.len() + CREATED_LEN + ID_LEN);
    key.push(name);
    key.push(0x00);
    key.extend_from_slice(&(value.len() as u32).to_be_bytes());
    key.extend_from_slice(value);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

fn tag_range(name: u8, value: &[u8], since: u64, until: u64) -> (Vec<u8>, Vec<u8>) {
    let prefix_len = 1 + 1 + 4 + value.len();
    let mut start = Vec::with_capacity(prefix_len + CREATED_LEN + ID_LEN);
    start.push(name);
    start.push(0x00);
    start.extend_from_slice(&(value.len() as u32).to_be_bytes());
    start.extend_from_slice(value);
    start.extend_from_slice(&since.to_be_bytes());
    start.extend_from_slice(&[0u8; ID_LEN]);

    let mut end = Vec::with_capacity(prefix_len + CREATED_LEN + ID_LEN);
    end.extend_from_slice(&start[..prefix_len]);
    end.extend_from_slice(&until.to_be_bytes());
    end.extend_from_slice(&[0xffu8; ID_LEN]);
    (start, end)
}

fn word_key(word: &str, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(word.len() + 1 + CREATED_LEN + ID_LEN);
    key.extend_from_slice(word.as_bytes());
    key.push(0x00);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

fn replaceable_key(kind: u64, pubkey: &[u8], dtag: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN + ID_LEN + 4 + dtag.len());
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&(dtag.len() as u32).to_be_bytes());
    key.extend_from_slice(dtag.as_bytes());
    key
}

impl Store {
    // ----- event persistence -----

    /// Applies a put inside the given write transaction. Used by the DB
    /// thread to batch consecutive puts into one commit; the transaction
    /// must be dropped (aborted) by the caller when this returns an error.
    fn put_event_in(&self, wtxn: &mut heed::RwTxn, event: &Event, now: u64) -> Result<PutOutcome> {
        let id = match event.id_bytes() {
            Some(id) => id,
            None => return Ok(PutOutcome::Invalid("invalid id".into())),
        };
        let pubkey = match event.pubkey_bytes() {
            Some(pk) => pk,
            None => return Ok(PutOutcome::Invalid("invalid pubkey".into())),
        };

        if self.vanish.get(wtxn, &pubkey)?.is_some() {
            return Ok(PutOutcome::Invalid(
                "blocked: this pubkey has requested to vanish".into(),
            ));
        }
        if self.banned.get(wtxn, &id)?.is_some() {
            return Ok(PutOutcome::Invalid("blocked: event has been banned".into()));
        }
        if self.deleted.get(wtxn, &id)?.is_some() {
            return Ok(PutOutcome::PreviouslyDeleted);
        }
        if self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(exp) = nip40::expiry(event)
            && exp < now
        {
            return Ok(PutOutcome::Expired);
        }

        // NIP-01: kinds 20000-29999 are ephemeral: they are delivered to
        // currently connected subscribers but never stored or indexed.
        if (20000..30000).contains(&event.kind) {
            return Ok(PutOutcome::Ephemeral);
        }

        let outcome = if is_replaceable(event) {
            let dtag = nip33::dtag(event);
            let rkey = replaceable_key(event.kind, &pubkey, &dtag);
            let old = self.replaceable.get(wtxn, &rkey)?;
            let had_old = old.is_some();
            if let Some(old) = old
                && old.len() >= CREATED_LEN + ID_LEN
            {
                let old_created = u64::from_be_bytes(old[..CREATED_LEN].try_into().unwrap());
                let old_id = old[CREATED_LEN..CREATED_LEN + ID_LEN].to_vec();
                // NIP-01: on equal timestamps the event with the lowest id
                // (first in lexical order) is retained.
                let newer = event.created_at > old_created
                    || (event.created_at == old_created && id.as_slice() < old_id.as_slice());
                if !newer {
                    return Ok(PutOutcome::Duplicate);
                }
                self.remove_event(wtxn, &old_id)?;
            }
            let mut value = Vec::with_capacity(CREATED_LEN + ID_LEN);
            value.extend_from_slice(&event.created_at.to_be_bytes());
            value.extend_from_slice(&id);
            self.replaceable.put(wtxn, &rkey, &value)?;
            if had_old {
                PutOutcome::Replaced
            } else {
                PutOutcome::Stored
            }
        } else {
            if self.events.get(wtxn, &id)?.is_some() {
                return Ok(PutOutcome::Duplicate);
            }
            PutOutcome::Stored
        };

        let raw = serde_json::to_vec(event)?;
        self.events.put(wtxn, &id, &raw)?;
        self.put_indexes(wtxn, event, &id, &pubkey)?;
        Ok(outcome)
    }

    fn put_indexes(
        &self,
        wtxn: &mut heed::RwTxn,
        event: &Event,
        id: &[u8],
        pubkey: &[u8],
    ) -> Result<()> {
        let created = event.created_at;
        self.by_created.put(wtxn, &created_key(created, id), b"")?;
        self.by_pubkey
            .put(wtxn, &pubkey_key(pubkey, created, id), b"")?;
        self.by_kind
            .put(wtxn, &kind_key(event.kind, created, id), b"")?;
        for tag in &event.tags {
            if indexable_tag(tag) {
                self.by_tag.put(
                    wtxn,
                    &tag_key(tag[0].as_bytes()[0], tag[1].as_bytes(), created, id),
                    b"",
                )?;
            }
        }
        if self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(exp) = nip40::expiry(event)
        {
            self.expiry.put(wtxn, &created_key(exp, id), b"")?;
        }
        if let Some(by_word) = self.by_word {
            for word in nip50::tokenize(&event.content)
                .iter()
                .take(nip50::MAX_INDEXED_WORDS)
            {
                by_word.put(wtxn, &word_key(word, created, id), b"")?;
            }
        }
        Ok(())
    }

    /// Removes an event and every index entry pointing at it.
    fn remove_event(&self, wtxn: &mut heed::RwTxn, id: &[u8]) -> Result<()> {
        let Some(raw) = self.events.get(wtxn, id)? else {
            return Ok(());
        };
        let event: Event = serde_json::from_slice(raw)?;
        let Some(pubkey) = event.pubkey_bytes() else {
            return Ok(());
        };

        self.events.delete(wtxn, id)?;
        self.by_created
            .delete(wtxn, &created_key(event.created_at, id))?;
        self.by_pubkey
            .delete(wtxn, &pubkey_key(&pubkey, event.created_at, id))?;
        self.by_kind
            .delete(wtxn, &kind_key(event.kind, event.created_at, id))?;
        for tag in &event.tags {
            if indexable_tag(tag) {
                self.by_tag.delete(
                    wtxn,
                    &tag_key(
                        tag[0].as_bytes()[0],
                        tag[1].as_bytes(),
                        event.created_at,
                        id,
                    ),
                )?;
            }
        }
        if self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(exp) = nip40::expiry(&event)
        {
            self.expiry.delete(wtxn, &created_key(exp, id))?;
        }
        if let Some(by_word) = self.by_word {
            for word in nip50::tokenize(&event.content)
                .iter()
                .take(nip50::MAX_INDEXED_WORDS)
            {
                by_word.delete(wtxn, &word_key(word, event.created_at, id))?;
            }
        }
        Ok(())
    }

    /// Applies a deletion request.
    ///
    /// `request_pubkey` is the hex pubkey of the deletion event: only events
    /// authored by the same pubkey are removed (NIP-09). Deletion requests
    /// themselves are never removed. `request_created` limits how old the
    /// deleted events may be; `addresses` are NIP-09 `a` tags referencing
    /// addressable events, whose every version up to `request_created` is
    /// removed.
    fn apply_deletion(
        &self,
        targets: &[String],
        addresses: &[nip09::Address],
        request_pubkey: Option<&str>,
        request_created: u64,
    ) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut removed = 0usize;

        for target in targets {
            let Ok(id) = hex::decode(target) else {
                continue;
            };
            if id.len() != ID_LEN {
                continue;
            }
            let Some(raw) = self.events.get(&wtxn, &id)? else {
                continue;
            };
            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                continue;
            };
            // NIP-09: only events authored by the request's pubkey are
            // deleted, and deletion requests cannot be deleted. NIP-26:
            // the delegator may also delete events published by a
            // delegatee on their behalf.
            if event.kind == nip09::DELETION_KIND {
                continue;
            }
            if let Some(pubkey) = request_pubkey
                && event.pubkey != pubkey
                && !delegated_by(&event, pubkey)
            {
                continue;
            }
            self.deleted.put(&mut wtxn, &id, b"")?;
            self.remove_event(&mut wtxn, &id)?;
            removed += 1;
        }

        // NIP-09 `a` tags: remove every version of the referenced
        // addressable events published up to the deletion request.
        for address in addresses {
            // Only the author of the addressable event may delete it.
            if let Some(pubkey) = request_pubkey
                && address.pubkey != pubkey
            {
                continue;
            }
            let Ok(pubkey) = hex::decode(&address.pubkey) else {
                continue;
            };
            if pubkey.len() != ID_LEN {
                continue;
            }
            let start = replaceable_key(address.kind, &pubkey, "");
            let end = replaceable_key(address.kind.saturating_add(1), &pubkey, "");
            let range = (
                std::ops::Bound::Included(start.as_slice()),
                std::ops::Bound::Excluded(end.as_slice()),
            );
            let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .replaceable
                .range(&wtxn, &range)?
                .filter_map(|item| item.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
                .collect();
            for (key, value) in entries {
                // key = kind(8) + pubkey(32) + dlen(4) + d
                if key.len() < CREATED_LEN * 2 + ID_LEN {
                    continue;
                }
                if key[CREATED_LEN..CREATED_LEN + ID_LEN] != pubkey {
                    continue;
                }
                let dlen = u32::from_be_bytes(
                    key[CREATED_LEN + ID_LEN..CREATED_LEN + ID_LEN + 4]
                        .try_into()
                        .unwrap(),
                ) as usize;
                if key.len() != CREATED_LEN + ID_LEN + 4 + dlen {
                    continue;
                }
                let d = &key[CREATED_LEN + ID_LEN + 4..];
                if d != address.d.as_bytes() {
                    continue;
                }
                if value.len() < CREATED_LEN + ID_LEN {
                    continue;
                }
                let created = u64::from_be_bytes(value[..CREATED_LEN].try_into().unwrap());
                if created > request_created {
                    continue;
                }
                let id = &value[CREATED_LEN..CREATED_LEN + ID_LEN];
                self.deleted.put(&mut wtxn, id, b"")?;
                self.remove_event(&mut wtxn, id)?;
                removed += 1;
            }
        }

        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-86 banevent: marks the event as banned, removes it from storage
    /// and rejects future re-publication.
    fn apply_ban(&self, id: &[u8], reason: &str) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        self.banned.put(&mut wtxn, id, reason.as_bytes())?;
        let removed = if self.events.get(&wtxn, id)?.is_some() {
            self.remove_event(&mut wtxn, id)?;
            true
        } else {
            false
        };
        wtxn.commit()?;
        Ok(removed)
    }

    fn apply_unban(&self, id: &[u8]) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let removed = self.banned.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(removed)
    }

    fn list_banned(&self) -> Result<Vec<(String, String)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.banned.iter(&rtxn)? {
            let (id, reason) = item?;
            out.push((
                hex::encode(id),
                String::from_utf8_lossy(reason).into_owned(),
            ));
        }
        Ok(out)
    }

    /// NIP-62: deletes every event authored by `pubkey` (including NIP-09
    /// deletion requests and NIP-59 gift wraps that p-tag it) and records the
    /// pubkey so that no future event from it is accepted.
    fn apply_vanish(&self, pubkey: &[u8]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        self.vanish.put(&mut wtxn, pubkey, b"")?;

        let mut removed = 0usize;
        let start = pubkey_key(pubkey, 0, &[0u8; ID_LEN]);
        let end = pubkey_key(pubkey, u64::MAX, &[0xffu8; ID_LEN]);
        let range = (
            std::ops::Bound::Included(start.as_slice()),
            std::ops::Bound::Excluded(end.as_slice()),
        );
        let ids: Vec<Vec<u8>> = self
            .by_pubkey
            .range(&wtxn, &range)?
            .filter_map(|item| item.ok().map(|(k, _)| k[k.len() - ID_LEN..].to_vec()))
            .collect();
        for id in ids {
            if self.events.get(&wtxn, &id)?.is_some() {
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
        }

        // NIP-59 gift wraps addressed to the vanished pubkey. The by_tag
        // index stores the tag value verbatim (the 64-char hex string), not
        // the decoded bytes.
        let pubkey_hex = hex::encode(pubkey).into_bytes();
        let start = tag_key(b'p', &pubkey_hex, 0, &[0u8; ID_LEN]);
        let end = tag_key(b'p', &pubkey_hex, u64::MAX, &[0xffu8; ID_LEN]);
        let range = (
            std::ops::Bound::Included(start.as_slice()),
            std::ops::Bound::Excluded(end.as_slice()),
        );
        let ids: Vec<Vec<u8>> = self
            .by_tag
            .range(&wtxn, &range)?
            .filter_map(|item| item.ok().map(|(k, _)| k[k.len() - ID_LEN..].to_vec()))
            .collect();
        for id in ids {
            let Some(raw) = self.events.get(&wtxn, &id)? else {
                continue;
            };
            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                continue;
            };
            if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
        }

        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-59: relays SHOULD delete `kind:1059` gift wraps addressed to a
    /// pubkey when that pubkey signs a NIP-09 deletion request. Wraps are
    /// signed by random keys, so they cannot be deleted by their recipient
    /// through the normal deletion flow.
    fn delete_gift_wraps_to(&self, pubkey: &[u8]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        // The by_tag index stores the tag value verbatim (the 64-char hex
        // string), not the decoded bytes.
        let pubkey_hex = hex::encode(pubkey).into_bytes();
        let start = tag_key(b'p', &pubkey_hex, 0, &[0u8; ID_LEN]);
        let end = tag_key(b'p', &pubkey_hex, u64::MAX, &[0xffu8; ID_LEN]);
        let range = (
            std::ops::Bound::Included(start.as_slice()),
            std::ops::Bound::Excluded(end.as_slice()),
        );
        let ids: Vec<Vec<u8>> = self
            .by_tag
            .range(&wtxn, &range)?
            .filter_map(|item| item.ok().map(|(k, _)| k[k.len() - ID_LEN..].to_vec()))
            .collect();
        let mut removed = 0usize;
        for id in ids {
            let Some(raw) = self.events.get(&wtxn, &id)? else {
                continue;
            };
            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                continue;
            };
            if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
        }
        wtxn.commit()?;
        Ok(removed)
    }

    fn replaceable_created_at(&self, kind: u64, pubkey: &str, d: &str) -> Result<Option<u64>> {
        let Ok(pubkey) = hex::decode(pubkey) else {
            return Ok(None);
        };
        if pubkey.len() != ID_LEN {
            return Ok(None);
        }
        let rtxn = self.env.read_txn()?;
        let key = replaceable_key(kind, &pubkey, d);
        let Some(value) = self.replaceable.get(&rtxn, &key)? else {
            return Ok(None);
        };
        if value.len() < CREATED_LEN {
            return Ok(None);
        }
        Ok(Some(u64::from_be_bytes(
            value[..CREATED_LEN].try_into().unwrap(),
        )))
    }

    /// Returns `true` when an event whose id starts with `prefix` is stored.
    /// Used by NIP-29 `previous` tag validation.
    pub fn event_id_prefix_exists(&self, prefix: &[u8]) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        let range = (
            std::ops::Bound::Included(prefix),
            std::ops::Bound::Unbounded,
        );
        Ok(self
            .events
            .range(&rtxn, &range)?
            .next()
            .transpose()?
            .map(|(key, _)| key.starts_with(prefix))
            .unwrap_or(false))
    }

    fn purge_expired(&self, now: u64) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let since_key = created_key(0, &[0u8; ID_LEN]);
        let until_key = created_key(now, &[0xffu8; ID_LEN]);
        let range = (
            std::ops::Bound::Included(since_key.as_slice()),
            std::ops::Bound::Excluded(until_key.as_slice()),
        );
        let to_delete: Vec<Vec<u8>> = self
            .expiry
            .range(&wtxn, &range)?
            .filter_map(|item| item.ok().map(|(k, _)| k[k.len() - ID_LEN..].to_vec()))
            .collect();
        let mut removed = 0usize;
        for id in to_delete {
            if self.events.get(&wtxn, &id)?.is_some() {
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
        }
        wtxn.commit()?;
        Ok(removed)
    }

    /// Collects events that match the filters, most recent first.
    fn scan(
        &self,
        filters: &[Filter],
        now: u64,
        max_limit: usize,
        count_mode: bool,
    ) -> Result<(Vec<Event>, bool)> {
        let mut out = EventCollector(Vec::new());
        let more = self.scan_collect(filters, now, max_limit, count_mode, &mut out)?;
        Ok((out.0, more))
    }

    /// Collects only `(created_at, id)` records of the matching events
    /// (NIP-77 negentropy). Keeps the memory footprint at a few bytes per
    /// record instead of materializing every full event.
    fn scan_neg(&self, filter: &Filter, now: u64, max_items: usize) -> Result<(NegItems, bool)> {
        let mut out = ItemCollector(Vec::new());
        let more = self.scan_collect(
            std::slice::from_ref(filter),
            now,
            max_items,
            false,
            &mut out,
        )?;
        Ok((out.0, more))
    }

    /// Shared scan core: applies the filters through the index-selected
    /// candidate walks and collects into `out`. Returns `true` when the
    /// scan stopped at the limit instead of exhausting the matches
    /// (NIP-67 EOSE completeness hint).
    #[allow(clippy::too_many_arguments)]
    fn scan_collect<C: ScanCollector>(
        &self,
        filters: &[Filter],
        now: u64,
        max_limit: usize,
        count_mode: bool,
        out: &mut C,
    ) -> Result<bool> {
        if max_limit == 0 {
            return Ok(false);
        }
        let rtxn = self.env.read_txn()?;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        // `more` is true when a scan stopped because of a limit instead of
        // exhausting the matching records (NIP-67 EOSE completeness hint).
        let mut more = false;

        for filter in filters {
            if out.len() >= max_limit {
                more = true;
                break;
            }
            let limit = if count_mode {
                max_limit
            } else {
                filter.limit.unwrap_or(max_limit).min(max_limit)
            };
            let terms = if filter.has_search() {
                nip50::terms(filter.search.as_deref().unwrap_or(""))
            } else {
                Vec::new()
            };
            let stop = self.scan_filter(
                &rtxn, filter, &terms, now, limit, max_limit, &mut seen, out, &mut more,
            )?;
            if stop {
                break;
            }
        }
        if !count_mode {
            // NIP-01: newest events first; on equal created_at the event
            // with the lowest id comes first.
            ScanCollector::sort_key(out);
        }
        Ok(more)
    }

    /// Returns `true` when the global limit was reached.
    #[allow(clippy::too_many_arguments)]
    fn scan_filter<C: ScanCollector>(
        &self,
        rtxn: &RoTxn,
        filter: &Filter,
        terms: &[String],
        now: u64,
        limit: usize,
        max_limit: usize,
        seen: &mut HashSet<Vec<u8>>,
        out: &mut C,
        more: &mut bool,
    ) -> Result<bool> {
        let mut consider = |id: &[u8]| -> Result<bool> {
            consider_event(
                self.events,
                self.deleted,
                self.banned,
                self.expiry,
                self.expiry_enabled
                    .load(std::sync::atomic::Ordering::Relaxed),
                rtxn,
                id,
                filter,
                terms,
                now,
                seen,
                out,
                limit,
                max_limit,
            )
        };

        if let Some(ids) = &filter.ids {
            for id in ids.iter().take(max_limit) {
                if let Ok(id) = hex::decode(id)
                    && !consider(&id)?
                {
                    *more = true;
                    return Ok(false);
                }
            }
            return Ok(out.len() >= max_limit);
        }

        if filter.has_search() {
            // With the word index available, scan it for the first term and
            // let `deliverable` verify the remaining terms against the
            // content. Without the index, fall through to the time-range
            // scans, where the terms are still checked per event.
            if let Some(by_word) = self.by_word {
                let Some(word) = terms.first() else {
                    return Ok(false);
                };
                let start = {
                    let mut v = word.as_bytes().to_vec();
                    v.push(0x00);
                    v
                };
                let end = {
                    let mut v = word.as_bytes().to_vec();
                    v.push(0x01);
                    v
                };
                let _ = self.for_each(rtxn, by_word, &start, &end, &mut consider, more)?;
                return Ok(out.len() >= max_limit);
            }
        }

        let since = filter.since.unwrap_or(0);
        let until = filter.until.unwrap_or(u64::MAX);

        if let Some(authors) = &filter.authors {
            for author in authors {
                let Ok(pk) = hex::decode(author) else {
                    continue;
                };
                if pk.len() != ID_LEN {
                    continue;
                }
                let start = pubkey_key(&pk, since, &[0u8; ID_LEN]);
                let end = pubkey_key(&pk, until, &[0xffu8; ID_LEN]);
                if !self.for_each(rtxn, self.by_pubkey, &start, &end, &mut consider, more)? {
                    return Ok(false);
                }
            }
            return Ok(out.len() >= max_limit);
        }

        if let Some((name, values)) = filter.tags.iter().next() {
            let tag_name = name.strip_prefix('#').unwrap_or(name);
            if tag_name.len() == 1 {
                let name_byte = tag_name.as_bytes()[0];
                for value in string_values(values) {
                    if value.len() > TAG_VALUE_MAX {
                        continue;
                    }
                    let (start, end) = tag_range(name_byte, value.as_bytes(), since, until);
                    if !self.for_each(rtxn, self.by_tag, &start, &end, &mut consider, more)? {
                        return Ok(false);
                    }
                }
                return Ok(out.len() >= max_limit);
            }
            // Multi-letter tag names are not indexed (NIP-01 only requires
            // single-letter tags to be indexed): fall through to the
            // time-range scan, where the final in-memory match enforces the
            // tag filter.
        }

        if let Some(kinds) = &filter.kinds {
            for kind in kinds {
                let start = kind_key(*kind, since, &[0u8; ID_LEN]);
                let end = kind_key(*kind, until, &[0xffu8; ID_LEN]);
                if !self.for_each(rtxn, self.by_kind, &start, &end, &mut consider, more)? {
                    return Ok(false);
                }
            }
            return Ok(out.len() >= max_limit);
        }

        let start = created_key(since, &[0u8; ID_LEN]);
        let end = created_key(until, &[0xffu8; ID_LEN]);
        Ok(!self.for_each(rtxn, self.by_created, &start, &end, &mut consider, more)?)
    }

    fn for_each(
        &self,
        rtxn: &RoTxn,
        db: Database<Bytes, Bytes>,
        start: &[u8],
        end: &[u8],
        mut consider: impl FnMut(&[u8]) -> Result<bool>,
        more: &mut bool,
    ) -> Result<bool> {
        let range = (
            std::ops::Bound::Included(start),
            std::ops::Bound::Excluded(end),
        );
        let iter = db.rev_range(rtxn, &range)?;
        for item in iter {
            let (key, _) = item?;
            let id = &key[key.len() - ID_LEN..];
            if !consider(id)? {
                *more = true;
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[allow(clippy::too_many_arguments)]
fn consider_event<C: ScanCollector>(
    events: Database<Bytes, Bytes>,
    deleted: Database<Bytes, Bytes>,
    banned: Database<Bytes, Bytes>,
    _expiry: Database<Bytes, Bytes>,
    expiry_enabled: bool,
    rtxn: &RoTxn,
    id: &[u8],
    filter: &Filter,
    terms: &[String],
    now: u64,
    seen: &mut HashSet<Vec<u8>>,
    out: &mut C,
    limit: usize,
    max_limit: usize,
) -> Result<bool> {
    if out.len() >= max_limit {
        // The global limit is reached: stop the scan (and any remaining
        // ranges of this filter) instead of walking them to completion.
        return Ok(false);
    }
    if seen.contains(id) {
        return Ok(true);
    }
    let Some(raw) = events.get(rtxn, id)? else {
        return Ok(true);
    };
    let Ok(event) = serde_json::from_slice::<Event>(raw) else {
        return Ok(true);
    };
    if !deliverable(
        deleted,
        banned,
        expiry_enabled,
        rtxn,
        &event,
        filter,
        terms,
        now,
    )? {
        return Ok(true);
    }
    seen.insert(id.to_vec());
    let id = id.try_into().unwrap_or([0u8; 32]);
    Ok(out.push(event, id, limit))
}

#[allow(clippy::too_many_arguments)]
fn deliverable(
    deleted: Database<Bytes, Bytes>,
    banned: Database<Bytes, Bytes>,
    expiry_enabled: bool,
    rtxn: &RoTxn,
    event: &Event,
    filter: &Filter,
    terms: &[String],
    now: u64,
) -> Result<bool> {
    let Some(id) = event.id_bytes() else {
        return Ok(false);
    };
    if deleted.get(rtxn, &id)?.is_some() {
        return Ok(false);
    }
    if banned.get(rtxn, &id)?.is_some() {
        return Ok(false);
    }
    if expiry_enabled
        && let Some(exp) = nip40::expiry(event)
        && exp < now
    {
        return Ok(false);
    }
    if !terms.is_empty() {
        let content = event.content.to_lowercase();
        if terms.iter().any(|t| !content.contains(t.as_str())) {
            return Ok(false);
        }
    }
    Ok(filter.matches(event))
}

fn indexable_tag(tag: &[String]) -> bool {
    tag.len() >= 2
        && tag[0].len() == 1
        && tag[0].as_bytes()[0].is_ascii_alphanumeric()
        && tag[1].len() <= TAG_VALUE_MAX
}

/// Returns `true` when the event was published under a NIP-26 delegation
/// granted by `delegator`.
fn delegated_by(event: &Event, delegator: &str) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.len() == 4 && t[0] == "delegation" && t[1] == delegator)
}

fn string_values(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Returns `true` for regular (NIP-01) or parameterized (NIP-33) replaceable
/// kinds.
fn is_replaceable(event: &Event) -> bool {
    crate::nips::nip01::is_replaceable_kind(event.kind)
        || nip33::is_param_replaceable_kind(event.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nips::nip01;
    use crate::stats::unix_now;

    fn config() -> DatabaseConfig {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrd-db-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        DatabaseConfig {
            path,
            ..Default::default()
        }
    }

    fn event(kind: u64, content: &str, created: u64, tags: Vec<Vec<String>>) -> Event {
        let mut ev = Event {
            id: String::new(),
            pubkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            created_at: created,
            kind,
            tags,
            content: content.to_string(),
            sig: "00".repeat(64),
        };
        ev.id = nip01::compute_id(&ev);
        ev
    }

    #[test]
    fn insert_and_query() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let e1 = event(1, "hello world", now, vec![]);
            let e2 = event(1, "foo bar", now, vec![vec!["t".into(), "rust".into()]]);
            let e3 = event(2, "another", now - 10, vec![]);

            assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Duplicate);
            assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(e3, now).await, PutOutcome::Stored);

            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 2);

            let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["rust"]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, e2.id);

            let f: Filter = serde_json::from_value(serde_json::json!({"search": "foo"})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, e2.id);
        });
    }

    #[test]
    fn replaceable_and_deletion() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let d = vec![vec!["d".to_string(), "post-1".to_string()]];
            let e1 = event(30023, "v1", now, d.clone());
            let e2 = event(30023, "v2", now + 5, d.clone());

            assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Replaced);
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].content, "v2");

            let targets = vec![e2.id.clone()];
            assert_eq!(db.apply_deletion(targets, vec![], None, u64::MAX).await, 1);
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert!(res.is_empty());
        });
    }

    #[test]
    fn expired_events_are_filtered() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut e = event(1, "ephemeral", now - 100, vec![]);
            e.tags = vec![vec!["expiration".into(), (now - 50).to_string()]];
            assert_eq!(db.put(e, now).await, PutOutcome::Expired);
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert!(res.is_empty());
        });
    }

    #[test]
    fn deletion_by_address_and_author() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let d = vec![vec!["d".to_string(), "post-1".to_string()]];
            let e1 = event(30023, "v1", now, d.clone());
            let e2 = event(30023, "v2", now + 5, d.clone());
            // A third event by a different author must survive.
            let mut e3 = event(30023, "other", now + 6, d.clone());
            e3.pubkey = "1111111111111111111111111111111111111111111111111111111111111111".into();
            e3.id = nip01::compute_id(&e3);

            assert_eq!(db.put(e1.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(e2.clone(), now).await, PutOutcome::Replaced);
            assert_eq!(db.put(e3.clone(), now).await, PutOutcome::Stored);

            let address = crate::nips::nip09::Address {
                kind: 30023,
                pubkey: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                d: "post-1".into(),
            };
            // Only the current version of an addressable event is stored (the
            // older one was removed by replacement), and it is only deleted
            // when its created_at is up to the request's timestamp.
            assert_eq!(
                db.apply_deletion(
                    vec![],
                    vec![address.clone()],
                    Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                    now + 4,
                )
                .await,
                0,
                "the current version is newer than the deletion request"
            );
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 2, "v2 and the other author's event remain");

            // A deletion with a later timestamp removes the remaining version.
            assert_eq!(
                db.apply_deletion(
                    vec![],
                    vec![address],
                    Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                    u64::MAX,
                )
                .await,
                1
            );
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [30023]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, e3.id, "other author's event is untouched");
        });
    }

    #[test]
    fn deletion_requests_are_never_deleted() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let target = event(1, "note", now, vec![]);
            let deletion = event(5, "del", now, vec![vec!["e".into(), target.id.clone()]]);
            assert_eq!(db.put(target.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(deletion.clone(), now).await, PutOutcome::Stored);

            let pk = "0000000000000000000000000000000000000000000000000000000000000000";
            // A deletion of the deletion request must not remove it.
            assert_eq!(
                db.apply_deletion(vec![deletion.id.clone()], vec![], Some(pk.into()), u64::MAX)
                    .await,
                0,
                "deletion requests cannot be deleted"
            );
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [5]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            // ...and the original deletion still works.
            assert_eq!(
                db.apply_deletion(vec![target.id.clone()], vec![], Some(pk.into()), u64::MAX)
                    .await,
                1
            );
        });
    }

    #[test]
    fn is_replaceable() {
        assert!(super::is_replaceable(&event(10000, "", 1, vec![])));
        assert!(super::is_replaceable(&event(30023, "", 1, vec![])));
        assert!(!super::is_replaceable(&event(1, "", 1, vec![])));
    }

    #[test]
    fn metadata_and_follows_are_replaceable() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let older = event(0, "{\"name\":\"old\"}", now, vec![]);
            let newer = event(0, "{\"name\":\"new\"}", now + 10, vec![]);
            assert_eq!(db.put(older, now).await, PutOutcome::Stored);
            assert_eq!(db.put(newer.clone(), now).await, PutOutcome::Replaced);
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [0]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].content, "{\"name\":\"new\"}");
            assert_eq!(res[0].id, newer.id);
        });
    }

    #[test]
    fn equal_timestamp_replaceable_keeps_lowest_id() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Two kind-1... no — two replaceable events with the SAME
            // created_at: NIP-01 keeps the one with the lowest id.
            let mut high = event(10000, "high-id", now, vec![]);
            let mut low = event(10000, "low-id", now, vec![]);
            // Force a known id ordering by flipping the last content char
            // (the id is a hash, so instead craft ids directly).
            low.id = "00".repeat(32);
            high.id = "ff".repeat(32);
            // compute_id would overwrite; emulate by using valid-length ids
            // (the db only checks length and hex).
            assert_eq!(db.put(low.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(high.clone(), now).await, PutOutcome::Duplicate);
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [10000]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, low.id, "lowest id must be retained");
        });
    }

    #[test]
    fn banned_events_are_removed_and_rejected() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ev = event(1, "to be banned", now, vec![]);
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
            let id = ev.id_bytes().unwrap();
            assert!(db.ban_event(id, "spam").await);
            // Removed from queries.
            let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert!(res.is_empty());
            // Re-publication is rejected.
            assert!(matches!(db.put(ev, now).await, PutOutcome::Invalid(_)));
            // Listed with the reason.
            let banned = db.list_banned_events().await;
            assert_eq!(banned, vec![(hex::encode(id), "spam".to_string())]);
            // Unbanning restores publication.
            assert!(db.unban_event(id).await);
            let (res, _) = db.query(vec![Filter::default()], 500, now).await;
            assert!(res.is_empty(), "the event itself was removed");
        });
    }

    #[test]
    fn ephemeral_events_are_not_stored() {
        // NIP-01: kinds 20000-29999 must not be stored (NIP-59 requires
        // kind 21059 in particular to never be stored).
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ev = event(
                21059,
                "gift wrap",
                now,
                vec![vec!["p".into(), "a".repeat(64)]],
            );
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Ephemeral);
            // Nothing was stored: queries return nothing and re-publication
            // is not a duplicate.
            let (res, _) = db.query(vec![Filter::default()], 500, now).await;
            assert!(res.is_empty());
            assert_eq!(db.put(ev, now).await, PutOutcome::Ephemeral);
        });
    }

    #[test]
    fn gift_wraps_to_are_deleted() {
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let recipient = "b83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
            let other = "c83130de0d1386592fe7b9f407f5f1ae8f1db91d772e484b3d81df0fa2e88f24";
            let wrap = event(
                1059,
                "encrypted",
                now,
                vec![vec!["p".into(), recipient.into()]],
            );
            let other_wrap = event(
                1059,
                "encrypted2",
                now,
                vec![vec!["p".into(), other.into()]],
            );
            assert_eq!(db.put(wrap.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(other_wrap.clone(), now).await, PutOutcome::Stored);
            let recipient_bytes = hex::decode(recipient).unwrap();
            let removed = db
                .delete_gift_wraps_to(recipient_bytes.try_into().unwrap())
                .await;
            assert_eq!(removed, 1, "only the wrap addressed to the recipient");
            let (res, _) = db
                .query(
                    vec![serde_json::from_value(serde_json::json!({"kinds": [1059]})).unwrap()],
                    500,
                    now,
                )
                .await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, other_wrap.id, "the other wrap survives");
        });
    }

    #[test]
    fn map_grows_beyond_initial_size() {
        // The database must keep accepting writes once it outgrows the
        // initial map size: the map is grown automatically up to
        // map_max_size, without degrading reads or writes.
        let cfg = DatabaseConfig {
            map_size: 256 * 1024,
            map_max_size: 32 * 1024 * 1024,
            ..config()
        };
        let db = DbClient::open(&cfg, true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let n = 3000;
            for i in 0..n {
                let ev = event(
                    1,
                    &format!("bulk-{i}"),
                    now - i as u64,
                    vec![vec!["t".into(), format!("tag-{i}")]],
                );
                let out = db.put(ev.clone(), now).await;
                assert!(
                    matches!(out, PutOutcome::Stored | PutOutcome::Duplicate),
                    "event {i} failed: {out:?}"
                );
            }
            // Every event is readable back.
            let f: Filter =
                serde_json::from_value(serde_json::json!({"kinds": [1], "limit": n})).unwrap();
            let (res, _) = db.query(vec![f], n, now).await;
            assert_eq!(res.len(), n, "all events must be queryable");
            // And the map grew beyond the initial size.
            assert!(db.map_size_now().await > 256 * 1024, "map must have grown");
        });
    }

    #[test]
    fn expiry_enabled_toggles_at_runtime() {
        // A config reload must be able to enable/disable NIP-40 handling.
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ev = event(
                1,
                "expiring",
                now,
                vec![vec!["expiration".into(), (now - 5).to_string()]],
            );
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Expired);

            // Disabled: the expired event is accepted and served.
            db.set_expiry_enabled(false);
            assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Stored);
            let (res, _) = db.query(vec![Filter::default()], 500, now).await;
            assert_eq!(res.len(), 1);

            // Re-enabled: a fresh expired event is rejected again.
            db.set_expiry_enabled(true);
            let ev2 = event(
                1,
                "expiring2",
                now,
                vec![vec!["expiration".into(), (now - 5).to_string()]],
            );
            assert_eq!(db.put(ev2, now).await, PutOutcome::Expired);
        });
    }

    #[test]
    fn multiletter_tag_filters_match() {
        // NIP-01 only requires single-letter tags to be indexed; filters on
        // longer tag names must still match via the full scan.
        let db = DbClient::open(&config(), true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let hit = event(1, "alt", now, vec![vec!["alt".into(), "reply".into()]]);
            let miss = event(1, "no alt", now, vec![]);
            assert_eq!(db.put(hit.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(miss, now).await, PutOutcome::Stored);

            let f: Filter = serde_json::from_value(serde_json::json!({"#alt": ["reply"]})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, hit.id);

            // Combined with another dimension.
            let f: Filter = serde_json::from_value(serde_json::json!({
                "#alt": ["reply"], "kinds": [1]
            }))
            .unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, hit.id);
        });
    }

    #[test]
    fn search_works_without_word_index() {
        // NIP-50 must work even when database.search_index is disabled: the
        // relay falls back to a full scan with content term checks.
        let cfg = DatabaseConfig {
            search_index: false,
            ..config()
        };
        let db = DbClient::open(&cfg, true, Arc::new(Default::default())).unwrap();
        let now = unix_now();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let hit = event(1, "rust is great", now, vec![]);
            let miss = event(1, "bitcoin only", now, vec![]);
            assert_eq!(db.put(hit.clone(), now).await, PutOutcome::Stored);
            assert_eq!(db.put(miss, now).await, PutOutcome::Stored);

            let f: Filter = serde_json::from_value(serde_json::json!({"search": "rust"})).unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
            assert_eq!(res[0].id, hit.id);

            // Combined with other filter dimensions.
            let f: Filter = serde_json::from_value(serde_json::json!({
                "search": "rust", "kinds": [1], "since": now
            }))
            .unwrap();
            let (res, _) = db.query(vec![f], 500, now).await;
            assert_eq!(res.len(), 1);
        });
    }
}
