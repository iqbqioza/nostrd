//! The dedicated writer and reader threads behind [`super::DbClient`].
//!
//! All LMDB access happens on these two threads: the writer batches event
//! puts into single write transactions (one fsync per batch) and the
//! reader serves queries without ever taking the write lock, so reads keep
//! working even when the writer is stalled.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::store::WriteBatch;
use super::store::{Store, flush_everything};
use super::{Msg, PutOutcome, db_error};
use crate::db::scan::SCAN_BUDGET;
use crate::error::Result;

/// Releases the writer thread's queued-work accounting for one drain. The
/// counters are decremented when the guard drops, so a panic anywhere in
/// the drain cannot leave the overload-protection counters elevated
/// (which would reject every new request afterwards).
struct PendingGuard {
    msgs: usize,
    events: usize,
    msgs_counter: Arc<std::sync::atomic::AtomicUsize>,
    events_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.msgs_counter
            .fetch_sub(self.msgs, std::sync::atomic::Ordering::Relaxed);
        self.events_counter
            .fetch_sub(self.events, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The channels, counters and flags handed to the [`super::DbClient`] by
/// [`spawn`].
pub(crate) struct DbThreads {
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
    pub(crate) read_tx: mpsc::UnboundedSender<Msg>,
    pub(crate) api_read_tx: mpsc::UnboundedSender<Msg>,
    pub(crate) errors: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) expiry: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) timeout_secs: u64,
    pub(crate) pending_msgs: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) pending_events: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) api_pending: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) max_pending_msgs: usize,
    pub(crate) max_pending_events: usize,
    pub(crate) max_api_pending: usize,
}

/// Serves one read-only message on a dedicated reader thread. Returns
/// `true` when the thread must shut down.
fn handle_read_msg(store: &Store, errors: &Arc<std::sync::atomic::AtomicU64>, msg: Msg) -> bool {
    match msg {
        Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget,
            reply,
        } => {
            let out = match store.scan(&filters, now, limit, false, ascending, budget) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        } => {
            let out = match store.scan_neg(&filter, now, limit, SCAN_BUDGET) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::Count {
            filters,
            limit,
            now,
            reply,
        } => {
            let out = match store.scan(&filters, now, limit, true, false, SCAN_BUDGET) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::PrefixExists { prefix, reply } => {
            let exists = match store.event_id_prefix_exists(&prefix) {
                Ok(exists) => exists,
                Err(e) => {
                    db_error(errors, &e);
                    false
                }
            };
            let _ = reply.send(exists);
            false
        }
        Msg::PrefixesExist { prefixes, reply } => {
            let out = match store.prefixes_exist(&prefixes) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    vec![false; prefixes.len()]
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::ReplaceableCreatedAt {
            kind,
            pubkey,
            d,
            reply,
        } => {
            let created = match store.replaceable_created_at(kind, &pubkey, &d) {
                Ok(created) => created,
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(created);
            false
        }
        Msg::ListBanned { reply } => {
            let banned = match store.list_banned() {
                Ok(banned) => banned,
                Err(e) => {
                    db_error(errors, &e);
                    Vec::new()
                }
            };
            let _ = reply.send(banned);
            false
        }
        Msg::LoadAccess { reply } => {
            let access = match store.load_access() {
                Ok(access) => access,
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(access);
            false
        }
        Msg::DatabaseSize { reply } => {
            let _ = reply.send(store.size_on_disk());
            false
        }
        #[cfg(test)]
        Msg::MapSize { reply } => {
            let _ = reply.send(store.env.info().map_size as u64);
            false
        }
        Msg::Shutdown => true,
        _ => unreachable!("read channel received a write message"),
    }
}

pub(crate) fn spawn(
    store: Store,
    expiry: Arc<std::sync::atomic::AtomicBool>,
    errors: Arc<std::sync::atomic::AtomicU64>,
    request_timeout_secs: u64,
    max_pending_msgs: usize,
    max_pending_events: usize,
) -> Result<DbThreads> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (read_tx, mut read_rx) = mpsc::unbounded_channel();
    let (api_read_tx, mut api_read_rx) = mpsc::unbounded_channel();
    let thread_errors = Arc::clone(&errors);
    let pending_msgs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending_events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_pending_msgs = Arc::clone(&pending_msgs);
    let thread_pending_events = Arc::clone(&pending_events);
    let read_pending = Arc::clone(&pending_msgs);
    let api_pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let api_thread_pending = Arc::clone(&api_pending);
    // Dedicated reader thread: serves Query/Count/NEG and the small
    // lookups without ever taking the LMDB write lock.
    {
        let read_store = store.clone_for_reader();
        let read_errors = Arc::clone(&errors);
        std::thread::spawn(move || {
            'reader: loop {
                let Some(msg) = read_rx.blocking_recv() else {
                    break;
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let shutdown = handle_read_msg(&read_store, &read_errors, msg);
                    // `Msg::Shutdown` is sent directly (never through
                    // `request_read`), so it was not counted; decrementing
                    // for it would underflow the pending counter.
                    if !shutdown {
                        read_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    shutdown
                }));
                match result {
                    Ok(true) => break 'reader,
                    Ok(false) => {}
                    Err(_) => {
                        log::error!("reader thread recovered from a panic");
                        read_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
    // Dedicated REST API reader thread: serves `/api/v1` queries on its own
    // queue so an API flood can never queue behind (or in front of)
    // WebSocket queries on the shared reader thread. LMDB allows many
    // concurrent readers, so both threads read the same data safely.
    {
        let api_store = store.clone_for_reader();
        let api_errors = Arc::clone(&errors);
        std::thread::spawn(move || {
            'api_reader: loop {
                let Some(msg) = api_read_rx.blocking_recv() else {
                    break;
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let shutdown = handle_read_msg(&api_store, &api_errors, msg);
                    // `Msg::Shutdown` is not counted (see the reader thread).
                    if !shutdown {
                        api_thread_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    shutdown
                }));
                match result {
                    Ok(true) => break 'api_reader,
                    Ok(false) => {}
                    Err(_) => {
                        log::error!("api reader thread recovered from a panic");
                        api_thread_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
    std::thread::spawn(move || {
        // Puts are applied in batches sharing one write transaction so
        // that the LMDB commit cost (a full fsync by default) is paid
        // once per batch instead of once per event. Replies are only
        // sent after the commit, so an OK implies durability.
        const BATCH: usize = 64;
        // Put batches received within the current message drain are merged
        // into a single commit at flush time.
        let mut batch = WriteBatch::default();
        'outer: loop {
            let Some(msg) = rx.blocking_recv() else {
                // The channel is closed (every DbClient was dropped
                // without a shutdown): flush any pending batch so that
                // awaiting requests are not left hanging.
                flush_everything(&store, &thread_errors, &mut batch);
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
                let drained_msgs: usize = msgs
                    .iter()
                    // `Msg::Shutdown` is sent directly (never through
                    // `request`), so it was not counted in `pending_msgs`;
                    // counting it here would underflow the counter.
                    .filter(|m| !matches!(m, Msg::Shutdown))
                    .count();
                let drained_events: usize = msgs
                    .iter()
                    .map(|m| match m {
                        Msg::PutBatch { events, .. } => events.len(),
                        Msg::Put { .. } => 1,
                        _ => 0,
                    })
                    .sum();
                // Release the queued-work accounting of everything the
                // drain processed. The guard drops on every exit path of
                // the drain (including a panic mid-drain), so the
                // overload-protection counters can never be left elevated.
                let _pending = PendingGuard {
                    msgs: drained_msgs,
                    events: drained_events,
                    msgs_counter: Arc::clone(&thread_pending_msgs),
                    events_counter: Arc::clone(&thread_pending_events),
                };
                for msg in msgs {
                    match msg {
                        Msg::Put { event, now, reply } => {
                            if batch.pending.is_none() {
                                match store.env.write_txn() {
                                    Ok(txn) => batch.pending = Some(txn),
                                    Err(e) => {
                                        db_error(&thread_errors, &e.into());
                                        let _ = reply
                                            .send(PutOutcome::Invalid("database error".into()));
                                        continue;
                                    }
                                }
                            }
                            batch.puts.push((event, now));
                            batch.senders.push(reply);
                        }
                        Msg::PutBatch { events, reply } => {
                            batch.pending_batches.push((events, reply));
                        }
                        Msg::Shutdown => {
                            flush_everything(&store, &thread_errors, &mut batch);
                            let _ = store.env.force_sync();
                            return true;
                        }
                        other => {
                            // Work that is not a plain put commits the
                            // batch first so that ordering is preserved.
                            flush_everything(&store, &thread_errors, &mut batch);
                            match other {
                                Msg::Query {
                                    filters,
                                    limit,
                                    now,
                                    ascending,
                                    budget,
                                    reply,
                                } => {
                                    let out = match store
                                        .scan(&filters, now, limit, false, ascending, budget)
                                    {
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
                                    let out = match store.scan_neg(&filter, now, limit, SCAN_BUDGET)
                                    {
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
                                    let out = match store.scan(
                                        &filters,
                                        now,
                                        limit,
                                        true,
                                        false,
                                        SCAN_BUDGET,
                                    ) {
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
                                    group,
                                    reply,
                                } => {
                                    let n = match store.apply_deletion_group(
                                        &targets,
                                        &addresses,
                                        request_pubkey.as_deref(),
                                        request_created,
                                        group.as_deref(),
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
                                Msg::PrefixesExist { prefixes, reply } => {
                                    let mut out = Vec::with_capacity(prefixes.len());
                                    for prefix in &prefixes {
                                        let exists = match store.event_id_prefix_exists(prefix) {
                                            Ok(exists) => exists,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        out.push(exists);
                                    }
                                    let _ = reply.send(out);
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
                                Msg::SaveAccess { access, reply } => {
                                    if let Err(e) = store.save_access(&access) {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
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
                                Msg::TouchFirstSeen { entries, reply } => {
                                    let mut wtxn = match store.env.write_txn() {
                                        Ok(t) => t,
                                        Err(e) => {
                                            db_error(&thread_errors, &e.into());
                                            let _ =
                                                reply.send(vec![(false, u64::MAX); entries.len()]);
                                            continue;
                                        }
                                    };
                                    let mut out = Vec::with_capacity(entries.len());
                                    for (pubkey, now) in entries {
                                        match store.touch_first_seen(&mut wtxn, &pubkey, now) {
                                            Ok((created, ts)) => out.push((created, ts)),
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                // Fail closed: treat the
                                                // pubkey as too young.
                                                out.push((false, u64::MAX));
                                            }
                                        }
                                    }
                                    match wtxn.commit() {
                                        Ok(()) => {}
                                        Err(e) => db_error(&thread_errors, &e.into()),
                                    }
                                    let _ = reply.send(out);
                                }
                                Msg::PutBatch { .. }
                                | Msg::Put { .. }
                                | Msg::Shutdown
                                | Msg::LoadAccess { .. } => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                }
                // Flush the batch before blocking again: clients await
                // their replies, so a pending batch must not wait for the
                // next message or every requestor deadlocks. The queued-work
                // accounting is released by the `PendingGuard` when this
                // closure returns.
                flush_everything(&store, &thread_errors, &mut batch);
                false
            }));
            match result {
                Ok(false) => {}
                Ok(true) => break 'outer,
                Err(_) => {
                    log::error!("database thread recovered from a panic");
                    // Revoke every reply queued for the rolled-back batch:
                    // the pending writes were aborted with the transaction,
                    // so their OK would be a lie. Drain the OLD batch before
                    // resetting it (a fresh batch has nothing to drain).
                    for s in batch.senders.drain(..) {
                        let _ = s.send(PutOutcome::Invalid("database error".into()));
                    }
                    for (events, reply) in batch.pending_batches.drain(..) {
                        let _ = reply.send(vec![
                            PutOutcome::Invalid("database error".into());
                            events.len()
                        ]);
                    }
                    batch = WriteBatch::default();
                }
            }
        }
    });
    Ok(DbThreads {
        tx,
        read_tx,
        api_read_tx,
        errors,
        expiry,
        timeout_secs: request_timeout_secs,
        pending_msgs,
        pending_events,
        api_pending,
        max_pending_msgs: max_pending_msgs.max(1),
        max_pending_events: max_pending_events.max(1),
        max_api_pending: max_pending_msgs.max(1),
    })
}
