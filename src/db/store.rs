//! LMDB persistence layer.
//!
//! [`Store`] owns the database environment and implements the write path:
//! event puts with replaceable/ephemeral/expiry semantics, the index
//! maintenance, NIP-09 deletion, NIP-62 vanish, NIP-86 bans and the
//! NIP-40 expiration purge.

use std::sync::Arc;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use tokio::sync::oneshot;

use super::{PutOutcome, db_error};
use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::nips::{nip33, nip40, nip50};

pub(crate) const EVENTS: &str = "events";
pub(crate) const BY_CREATED: &str = "by_created";
pub(crate) const BY_PUBKEY: &str = "by_pubkey";
pub(crate) const BY_KIND: &str = "by_kind";
pub(crate) const BY_TAG: &str = "by_tag";
pub(crate) const BY_WORD: &str = "by_word";
pub(crate) const DELETED: &str = "deleted";
pub(crate) const EXPIRY: &str = "expiry";
pub(crate) const REPLACEABLE: &str = "replaceable";
pub(crate) const VANISH: &str = "vanish";
pub(crate) const BANNED: &str = "banned";
pub(crate) const FIRST_SEEN: &str = "first_seen";
pub(crate) const CREATED_LEN: usize = 8;
pub(crate) const ID_LEN: usize = 32;
pub(crate) const TAG_VALUE_MAX: usize = 1024;

/// Minimum free space required before a batch of writes is committed.
/// Writing to the memory map of a file on a completely full disk raises
/// SIGBUS (killing the process), so the relay refuses to commit while the
/// free space is below this margin and keeps serving reads.
pub(crate) const DISK_FREE_MARGIN: u64 = 32 * 1024 * 1024;

/// Applies `puts` in one write transaction and commits. When the commit
/// fails because the memory map is full, the map is grown (up to
/// `map_max_size`) and the whole batch is re-applied in a fresh
/// transaction. Returns one outcome per put; all outcomes are
/// `Invalid("...")` when the batch cannot be committed.
pub(crate) fn apply_put_batch(
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
pub(crate) type PutBatchMsg = (Vec<(Event, u64)>, oneshot::Sender<Vec<PutOutcome>>);

/// The writer thread's pending write state: the open transaction, the
/// queued single puts with their reply channels and the queued put
/// batches.
#[derive(Default)]
pub(crate) struct WriteBatch<'tx> {
    pub(crate) pending: Option<heed::RwTxn<'tx>>,
    pub(crate) puts: Vec<(Event, u64)>,
    pub(crate) senders: Vec<oneshot::Sender<PutOutcome>>,
    pub(crate) pending_batches: Vec<PutBatchMsg>,
}

/// Commits the pending single-put batch together with every queued
/// `PutBatch`, merging them all into one write transaction (one commit for
/// events arriving from many connections). Replies are only sent after a
/// successful commit, so an OK implies durability.
pub(crate) fn flush_everything(
    store: &Store,
    thread_errors: &Arc<std::sync::atomic::AtomicU64>,
    batch: &mut WriteBatch<'_>,
) {
    if batch.puts.is_empty() && batch.pending_batches.is_empty() {
        if let Some(wtxn) = batch.pending.take()
            && let Err(e) = wtxn.commit()
        {
            db_error(thread_errors, &e.into());
        }
        return;
    }
    // Merge the singles and every queued batch into one list; the split
    // points let the outcomes be distributed back in order.
    let mut all: Vec<(Event, u64)> = std::mem::take(&mut batch.puts);
    let mut splits: Vec<usize> = vec![all.len()];
    for (events, _) in batch.pending_batches.iter_mut() {
        all.append(events);
        splits.push(all.len());
    }
    let outcomes = apply_put_batch(store, thread_errors, batch.pending.take(), &all);
    for (s, out) in batch
        .senders
        .drain(..)
        .zip(outcomes.iter().take(splits[0]).cloned())
    {
        let _ = s.send(out);
    }
    for (i, (_, reply)) in batch.pending_batches.drain(..).enumerate() {
        let range = splits[i]..splits[i + 1];
        let _ = reply.send(outcomes[range].to_vec());
    }
}

pub(crate) struct Store {
    pub(crate) env: Env,
    pub(crate) events: Database<Bytes, Bytes>,
    pub(crate) by_created: Database<Bytes, Bytes>,
    pub(crate) by_pubkey: Database<Bytes, Bytes>,
    pub(crate) by_kind: Database<Bytes, Bytes>,
    pub(crate) by_tag: Database<Bytes, Bytes>,
    pub(crate) by_word: Option<Database<Bytes, Bytes>>,
    pub(crate) deleted: Database<Bytes, Bytes>,
    pub(crate) expiry: Database<Bytes, Bytes>,
    pub(crate) replaceable: Database<Bytes, Bytes>,
    pub(crate) vanish: Database<Bytes, Bytes>,
    pub(crate) banned: Database<Bytes, Bytes>,
    /// pubkey (32 bytes) -> unix timestamp of the first accepted event.
    pub(crate) first_seen: Database<Bytes, Bytes>,
    /// NIP-40 expiration handling is only active when the NIP is enabled.
    /// Shared with the relay so that a config reload can toggle it at runtime.
    pub(crate) expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// NIP-50 word index: maximum number of words indexed per event.
    pub(crate) max_indexed_words: usize,
    /// Ceiling for the memory map (bytes): the map is opened at this size
    /// and never resized at runtime.
    pub(crate) map_max_size: u64,
}

/// `(created_at, id, protected, group_id, is_meta)` records returned by the
/// NIP-77 negentropy query. The visibility flags let the connection layer
/// withhold NIP-70 protected events from unauthenticated peers and NIP-29
impl Store {
    pub(crate) fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
        max_indexed_words: usize,
    ) -> Result<Store> {
        std::fs::create_dir_all(&cfg.path)?;
        // SAFETY: the returned `Env` is owned by `Store` and outlives every
        // transaction created from it within this process.
        // The map is virtual address space: on 64-bit systems the growth
        // ceiling can be huge; on 32-bit systems LMDB is limited to ~2 GiB.
        let mut map_max_size = (cfg.map_max_size as u64)
            .max(cfg.map_size as u64)
            .max(16 * 1024 * 1024);
        if usize::BITS < 64 {
            let cap = 2u64 * 1024 * 1024 * 1024;
            map_max_size = map_max_size.min(cap);
        }
        // The map is opened at `map_max_size` from the start (a sparse
        // virtual reservation: physical memory is only consumed by the
        // pages actually touched) and never resized at runtime. Runtime
        // growth would call `mdb_env_set_mapsize`, which requires that no
        // transactions are active — impossible while the shared reader and
        // the dedicated API reader threads hold concurrent read
        // transactions — and would risk unmapping memory the readers are
        // still using.
        let map_size = map_max_size as usize;
        let env = unsafe {
            EnvOpenOptions::new()
                .max_dbs(cfg.max_dbs.max(16))
                .max_readers(cfg.max_readers.max(8))
                .map_size(map_size)
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
        let first_seen = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(FIRST_SEEN))?;
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
            first_seen,
            expiry_enabled,
            max_indexed_words: max_indexed_words.max(1),
            map_max_size,
        })
    }

    /// The map is opened at its maximum size and never resized at runtime:
    /// LMDB's `mdb_env_set_mapsize` requires that no transactions are
    /// active, which cannot be guaranteed now that the shared reader and
    /// the dedicated API reader threads hold concurrent read transactions.
    /// Returns `false` (the map cannot grow), so a commit that fills the
    /// map fails with `MapFull` and the caller revokes the batch.
    pub(crate) fn grow_map(&self) -> bool {
        log::error!(
            "database map is full ({} bytes, map_max_size)",
            self.map_max_size
        );
        false
    }

    /// Free bytes on the filesystem hosting the data directory, when
    /// statvfs succeeds.
    pub(crate) fn free_space(&self) -> Option<u64> {
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

    pub(crate) fn size_on_disk(&self) -> u64 {
        self.env.real_disk_size().unwrap_or(0)
    }

    /// A copy of the store for the dedicated reader thread: the heed `Env`
    /// handle is reference-counted and the database handles are plain ids,
    /// so both threads share the same underlying environment.
    pub(crate) fn clone_for_reader(&self) -> Store {
        Store {
            env: self.env.clone(),
            events: self.events,
            by_created: self.by_created,
            by_pubkey: self.by_pubkey,
            by_kind: self.by_kind,
            by_tag: self.by_tag,
            by_word: self.by_word,
            deleted: self.deleted,
            expiry: self.expiry,
            replaceable: self.replaceable,
            vanish: self.vanish,
            banned: self.banned,
            first_seen: self.first_seen,
            expiry_enabled: Arc::clone(&self.expiry_enabled),
            max_indexed_words: self.max_indexed_words,
            map_max_size: self.map_max_size,
        }
    }
}

// ----- key builders -----

pub(crate) fn created_key(created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN + ID_LEN);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn pubkey_key(pubkey: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ID_LEN + CREATED_LEN + ID_LEN);
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn kind_key(kind: u64, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN * 2 + ID_LEN);
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn tag_key(name: u8, value: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 1 + 4 + value.len() + CREATED_LEN + ID_LEN);
    key.push(name);
    key.push(0x00);
    key.extend_from_slice(&(value.len() as u32).to_be_bytes());
    key.extend_from_slice(value);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn tag_range(name: u8, value: &[u8], since: u64, until: u64) -> (Vec<u8>, Vec<u8>) {
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

pub(crate) fn word_key(word: &str, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(word.len() + 1 + CREATED_LEN + ID_LEN);
    key.extend_from_slice(word.as_bytes());
    key.push(0x00);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn replaceable_key(kind: u64, pubkey: &[u8], dtag: &str) -> Vec<u8> {
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
    pub(crate) fn put_event_in(
        &self,
        wtxn: &mut heed::RwTxn,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome> {
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
        // NIP-01: kinds 20000-29999 are ephemeral: they are delivered to
        // currently connected subscribers but never stored or indexed.
        if (20000..30000).contains(&event.kind) {
            return Ok(PutOutcome::Ephemeral);
        }
        // NIP-40: events whose expiration already passed are dropped. The
        // check comes after the ephemeral range because "an expiration
        // timestamp does not affect storage of ephemeral events".
        if self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(exp) = nip40::expiry(event)
            && exp < now
        {
            return Ok(PutOutcome::Expired);
        }

        let outcome = if is_replaceable(event) {
            // NIP-01: normal replaceable kinds (0, 3, 10000-19999) are
            // replaced per (pubkey, kind) — their `d` tag must not create
            // separate slots. Only addressable kinds (30000-39999, NIP-33)
            // key on the `d` tag value.
            let dtag = if nip33::is_param_replaceable_kind(event.kind) {
                nip33::dtag(event)
            } else {
                String::new()
            };
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
        // NIP-26: the delegator's pubkey is indexed alongside the author's,
        // so a REQ with `authors: [<delegator>]` also finds events published
        // by a delegatee on the delegator's behalf.
        if let Some(delegator) = crate::nips::nip26::delegation(event)
            && let Ok(delegator_bytes) = hex::decode(delegator[0])
            && delegator_bytes.len() == ID_LEN
        {
            self.by_pubkey
                .put(wtxn, &pubkey_key(&delegator_bytes, created, id), b"")?;
        }
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
                .take(self.max_indexed_words)
            {
                by_word.put(wtxn, &word_key(word, created, id), b"")?;
            }
        }
        Ok(())
    }

    /// Removes an event and every index entry pointing at it.
    pub(crate) fn remove_event(&self, wtxn: &mut heed::RwTxn, id: &[u8]) -> Result<()> {
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
        // NIP-01/33: clear the replaceable/addressable slot so a later
        // re-publication (e.g. after the event was expired or deleted) is
        // judged against the current state instead of a stale entry.
        if is_replaceable(&event) {
            let dtag = if nip33::is_param_replaceable_kind(event.kind) {
                nip33::dtag(&event)
            } else {
                String::new()
            };
            self.replaceable
                .delete(wtxn, &replaceable_key(event.kind, &pubkey, &dtag))?;
        }
        self.by_pubkey
            .delete(wtxn, &pubkey_key(&pubkey, event.created_at, id))?;
        // NIP-26: drop the delegator's index entry as well.
        if let Some(delegator) = crate::nips::nip26::delegation(&event)
            && let Ok(delegator_bytes) = hex::decode(delegator[0])
            && delegator_bytes.len() == ID_LEN
        {
            self.by_pubkey
                .delete(wtxn, &pubkey_key(&delegator_bytes, event.created_at, id))?;
        }
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
                .take(self.max_indexed_words)
            {
                by_word.delete(wtxn, &word_key(word, event.created_at, id))?;
            }
        }
        Ok(())
    }
    /// Records `now` as the first-seen time of `pubkey` when the pubkey is
    /// unknown, and returns `(created, first_seen)`: `created` is true when
    /// the entry was just written (the pubkey's first accepted event).
    pub(crate) fn touch_first_seen(
        &self,
        wtxn: &mut heed::RwTxn,
        pubkey: &[u8],
        now: u64,
    ) -> Result<(bool, u64)> {
        match self.first_seen.get(wtxn, pubkey)? {
            Some(raw) if raw.len() >= 8 => {
                let ts = u64::from_be_bytes(raw[..8].try_into().unwrap());
                Ok((false, ts))
            }
            _ => {
                self.first_seen.put(wtxn, pubkey, &now.to_be_bytes())?;
                Ok((true, now))
            }
        }
    }

    pub(crate) fn replaceable_created_at(
        &self,
        kind: u64,
        pubkey: &str,
        d: &str,
    ) -> Result<Option<u64>> {
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

    /// Batched variant of [`Self::event_id_prefix_exists`]: answers many
    /// prefix lookups in a single read transaction instead of opening one
    /// transaction per prefix (a batch of NIP-29 `previous` tags can reach
    /// tens of thousands of entries).
    pub fn prefixes_exist(&self, prefixes: &[Vec<u8>]) -> Result<Vec<bool>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let range = (
                std::ops::Bound::Included(prefix.as_slice()),
                std::ops::Bound::Unbounded,
            );
            let exists = self
                .events
                .range(&rtxn, &range)?
                .next()
                .transpose()?
                .map(|(key, _)| key.starts_with(prefix))
                .unwrap_or(false);
            out.push(exists);
        }
        Ok(out)
    }
}

fn indexable_tag(tag: &[String]) -> bool {
    tag.len() >= 2
        && tag[0].len() == 1
        && tag[0].as_bytes()[0].is_ascii_alphanumeric()
        && tag[1].len() <= TAG_VALUE_MAX
}

pub(crate) fn is_replaceable(event: &Event) -> bool {
    crate::nips::nip01::is_replaceable_kind(event.kind)
        || nip33::is_param_replaceable_kind(event.kind)
}

/// Returns `true` when the event was published under a NIP-26 delegation
/// granted by `delegator`.
pub(crate) fn delegated_by(event: &Event, delegator: &str) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.len() == 4 && t[0] == "delegation" && t[1] == delegator)
}
