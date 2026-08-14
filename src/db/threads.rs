//! The dedicated writer and reader threads behind [`super::DbClient`].
//!
//! All LMDB access happens on these two threads: the writer batches event
//! puts into single write transactions (one fsync per batch) and the
//! reader serves queries without ever taking the write lock, so reads keep
//! working even when the writer is stalled.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::store::PutBatchMsg;
use super::store::{Store, flush_everything};
use super::{Msg, PutOutcome, db_error};

use crate::error::Result;
use crate::event::Event;

/// The channels, counters and flags handed to the [`super::DbClient`] by
/// [`spawn`].
pub(crate) struct DbThreads {
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
    pub(crate) read_tx: mpsc::UnboundedSender<Msg>,
    pub(crate) errors: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) expiry: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) timeout_secs: u64,
    pub(crate) pending_msgs: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) pending_events: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) max_pending_msgs: usize,
    pub(crate) max_pending_events: usize,
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
    let thread_errors = Arc::clone(&errors);
    let pending_msgs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending_events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_pending_msgs = Arc::clone(&pending_msgs);
    let thread_pending_events = Arc::clone(&pending_events);
    let read_pending = Arc::clone(&pending_msgs);
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
                    let shutdown = match msg {
                        Msg::Query {
                            filters,
                            limit,
                            now,
                            reply,
                        } => {
                            let out = match read_store.scan(&filters, now, limit, false) {
                                Ok(out) => out,
                                Err(e) => {
                                    db_error(&read_errors, &e);
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
                            let out = match read_store.scan_neg(&filter, now, limit) {
                                Ok(out) => out,
                                Err(e) => {
                                    db_error(&read_errors, &e);
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
                            let out = match read_store.scan(&filters, now, limit, true) {
                                Ok(out) => out,
                                Err(e) => {
                                    db_error(&read_errors, &e);
                                    (Vec::new(), false)
                                }
                            };
                            let _ = reply.send(out);
                            false
                        }
                        Msg::PrefixExists { prefix, reply } => {
                            let exists = match read_store.event_id_prefix_exists(&prefix) {
                                Ok(exists) => exists,
                                Err(e) => {
                                    db_error(&read_errors, &e);
                                    false
                                }
                            };
                            let _ = reply.send(exists);
                            false
                        }
                        Msg::PrefixesExist { prefixes, reply } => {
                            let mut out = Vec::with_capacity(prefixes.len());
                            for prefix in &prefixes {
                                let exists = match read_store.event_id_prefix_exists(prefix) {
                                    Ok(exists) => exists,
                                    Err(e) => {
                                        db_error(&read_errors, &e);
                                        false
                                    }
                                };
                                out.push(exists);
                            }
                            let _ = reply.send(out);
                            false
                        }
                        Msg::ReplaceableCreatedAt {
                            kind,
                            pubkey,
                            d,
                            reply,
                        } => {
                            let created = match read_store.replaceable_created_at(kind, &pubkey, &d)
                            {
                                Ok(created) => created,
                                Err(e) => {
                                    db_error(&read_errors, &e);
                                    None
                                }
                            };
                            let _ = reply.send(created);
                            false
                        }
                        Msg::ListBanned { reply } => {
                            let banned = match read_store.list_banned() {
                                Ok(banned) => banned,
                                Err(e) => {
                                    db_error(&read_errors, &e);
                                    Vec::new()
                                }
                            };
                            let _ = reply.send(banned);
                            false
                        }
                        Msg::DatabaseSize { reply } => {
                            let _ = reply.send(read_store.size_on_disk());
                            false
                        }
                        #[cfg(test)]
                        Msg::MapSize { reply } => {
                            let _ = reply.send(read_store.env.info().map_size as u64);
                            false
                        }
                        Msg::Shutdown => true,
                        _ => unreachable!("read channel received a write message"),
                    };
                    read_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
                let drained_msgs = msgs.len();
                let drained_events: usize = msgs
                    .iter()
                    .map(|m| match m {
                        Msg::PutBatch { events, .. } => events.len(),
                        Msg::Put { .. } => 1,
                        _ => 0,
                    })
                    .sum();
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
                                Msg::PutBatch { .. } | Msg::Put { .. } | Msg::Shutdown => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                }
                // Release the queued-work accounting of everything the
                // drain processed (the batch counters are approximate:
                // messages in the middle of the drain still count).
                thread_pending_msgs.fetch_sub(drained_msgs, std::sync::atomic::Ordering::Relaxed);
                thread_pending_events
                    .fetch_sub(drained_events, std::sync::atomic::Ordering::Relaxed);
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
                    for (events, reply) in pending_batches.drain(..) {
                        let _ = reply.send(vec![
                            PutOutcome::Invalid("database error".into());
                            events.len()
                        ]);
                    }
                    batch_puts.clear();
                }
            }
        }
    });
    Ok(DbThreads {
        tx,
        read_tx,
        errors,
        expiry,
        timeout_secs: request_timeout_secs,
        pending_msgs,
        pending_events,
        max_pending_msgs: max_pending_msgs.max(1),
        max_pending_events: max_pending_events.max(1),
    })
}
