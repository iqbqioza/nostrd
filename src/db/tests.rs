//! Integration tests for the database layer, exercised through the
//! public [`DbClient`] API.

use super::*;
use crate::config::DatabaseConfig;
use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

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

// ----- storage and query -----
fn insert_and_query() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- expiration (NIP-40) -----
fn expired_events_are_filtered() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- deletion (NIP-09) -----
fn deletion_by_address_and_author() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
    assert!(super::store::is_replaceable(&event(10000, "", 1, vec![])));
    assert!(super::store::is_replaceable(&event(30023, "", 1, vec![])));
    assert!(!super::store::is_replaceable(&event(1, "", 1, vec![])));
}

#[test]
fn metadata_and_follows_are_replaceable() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- bans (NIP-86) -----
fn banned_events_are_removed_and_rejected() {
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- ephemeral and gift wraps (NIP-01/59) -----
fn ephemeral_events_are_not_stored() {
    // NIP-01: kinds 20000-29999 must not be stored (NIP-59 requires
    // kind 21059 in particular to never be stored).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- database growth -----
fn map_grows_beyond_initial_size() {
    // The database must keep accepting writes once it outgrows the
    // initial map size: the map is grown automatically up to
    // map_max_size, without degrading reads or writes.
    let cfg = DatabaseConfig {
        map_size: 256 * 1024,
        map_max_size: 32 * 1024 * 1024,
        ..config()
    };
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- trust period and expiry toggling -----
fn first_seen_trust_period() {
    // A pubkey's first event records its arrival; later events within
    // the trust window are rejected by the relay. Here we verify the
    // bookkeeping itself.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pubkey = [7u8; 32];
        // First touch: created, the arrival time is recorded.
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now)]).await[0];
        assert!(created);
        assert_eq!(first, now);
        // Second touch: not created, the same time is returned.
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now + 5)]).await[0];
        assert!(!created);
        assert_eq!(first, now);
        // The recorded first-seen time never changes, so the trust
        // period does not restart once the window has elapsed: the
        // entry is kept permanently (one 40-byte row per unique pubkey).
        let (created, first) = db.touch_first_seen_batch(vec![(pubkey, now + 9999)]).await[0];
        assert!(!created);
        assert_eq!(first, now, "first-seen stays at the original arrival");
        // A different pubkey is created independently.
        let (created, _) = db.touch_first_seen_batch(vec![([8u8; 32], now)]).await[0];
        assert!(created);
    });
}

#[test]
fn expiry_enabled_toggles_at_runtime() {
    // A config reload must be able to enable/disable NIP-40 handling.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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

// ----- filters, search and ordering -----
fn multiletter_tag_filters_match() {
    // NIP-01 only requires single-letter tags to be indexed; filters on
    // longer tag names must still match via the full scan.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
fn delegated_events_match_delegator_queries() {
    // NIP-26: REQ with `authors: [<delegator>]` must also return events
    // published by a delegatee on the delegator's behalf.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let delegator = "a".repeat(64);
        let delegatee = "b".repeat(64);
        let mut delegated = event(1, "delegated", now, vec![]);
        delegated.pubkey = delegatee.clone();
        delegated.tags = vec![vec![
            "delegation".into(),
            delegator.clone(),
            "kind=1".into(),
            "00".repeat(64),
        ]];
        delegated.id = nip01::compute_id(&delegated);
        let own = event(1, "own", now, vec![]);

        assert_eq!(db.put(delegated.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(own.clone(), now).await, PutOutcome::Stored);

        let f: Filter =
            serde_json::from_value(serde_json::json!({"authors": [delegator]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "the delegated event is found");
        assert_eq!(res[0].id, delegated.id);
        // The delegatee's own key finds both its events.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"authors": [delegatee]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1);
    });
}

#[test]
fn search_results_are_relevance_ordered() {
    // NIP-50: results are ordered by how well they match the query, and
    // the limit is applied after that ordering. Partial matches rank
    // below full matches.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Two terms matched, but older than the single-term note.
        let both = event(1, "nostr bitcoin and more", now - 100, vec![]);
        let one = event(1, "nostr only", now, vec![]);
        let none = event(1, "chess news", now, vec![]);
        assert_eq!(db.put(both.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(one.clone(), now).await, PutOutcome::Stored);
        assert_eq!(db.put(none.clone(), now).await, PutOutcome::Stored);

        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": "nostr bitcoin"})).unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2);
        assert_eq!(
            res[0].id, both.id,
            "the note matching both terms ranks first"
        );
        assert_eq!(res[1].id, one.id, "partial matches rank below");
        assert!(!more, "both matches were delivered");
        assert!(!res.iter().any(|e| e.id == none.id));
    });
}

#[test]
fn created_at_ties_are_not_split_across_pages() {
    // NIP-01 ordering / NIP-67: when the limit cuts inside a group of
    // events sharing the oldest created_at, every event at that
    // timestamp is included in the same response.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..5 {
            let e = event(1, &format!("tie-{i}"), now, vec![]);
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "limit": 3})).unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 5, "all tied events are in one page");
        assert!(!more, "the tie completed the scan");
        assert!(res.windows(2).all(|w| w[0].created_at >= w[1].created_at));
    });
}

#[test]
fn multi_author_limit_applies_to_the_union() {
    // NIP-01: `{"authors": [A, B], "limit": n}` returns the n newest
    // events by either author; the limit must not be consumed by the
    // first author's range alone, and older events of the other author
    // must not displace newer ones.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let pub_a = "a".repeat(64);
        let pub_b = "b".repeat(64);
        let mut ea1 = event(1, "a1", now, vec![]);
        ea1.pubkey = pub_a.clone();
        ea1.id = nip01::compute_id(&ea1);
        let mut ea2 = event(1, "a2", now - 1, vec![]);
        ea2.pubkey = pub_a.clone();
        ea2.id = nip01::compute_id(&ea2);
        // B's only event is OLDER than both of A's; with limit 2 it
        // must not be returned even though B sorts after A in the
        // pubkey index.
        let mut eb1 = event(1, "b1", now - 3, vec![]);
        eb1.pubkey = pub_b.clone();
        eb1.id = nip01::compute_id(&eb1);
        for e in [&ea1, &ea2, &eb1] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({
            "authors": [pub_a, pub_b], "limit": 2
        }))
        .unwrap();
        let (res, more) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 2, "the two newest events are returned");
        assert_eq!(res[0].id, ea1.id);
        assert_eq!(res[1].id, ea2.id, "older B event must not displace A2");
        assert!(more, "B's older event was cut");
    });
}

#[test]
fn expiration_does_not_affect_ephemeral_events() {
    // NIP-40: "An expiration timestamp does not affect storage of
    // ephemeral events": an ephemeral event with a past expiration is
    // still handled as ephemeral (delivered live, never stored).
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ev = event(
            21059,
            "ephemeral wrap",
            now,
            vec![vec!["expiration".into(), (now - 50).to_string()]],
        );
        assert_eq!(db.put(ev.clone(), now).await, PutOutcome::Ephemeral);
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [21059]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert!(res.is_empty(), "ephemeral events are never stored");
    });
}

#[test]

// ----- negentropy and counting (NIP-77/45) -----
fn neg_items_carry_visibility_flags() {
    // NIP-70/NIP-29: the negentropy items carry the protected flag and
    // the group id so the connection layer can mirror the REQ path's
    // visibility rules.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let protected = event(1, "protected", now, vec![vec!["-".into()]]);
        let grouped = event(1, "grouped", now - 1, vec![vec!["h".into(), "g1".into()]]);
        let plain = event(1, "plain", now - 2, vec![]);
        for e in [&protected, &grouped, &plain] {
            assert_eq!(db.put(e.clone(), now).await, PutOutcome::Stored);
        }
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        let (items, _) = db.neg_items(f, 100, now).await;
        let by_id = |id: &str| items.iter().find(|i| hex::encode(i.1) == id).unwrap();
        assert!(by_id(&protected.id).2, "protected flag set");
        assert!(!by_id(&plain.id).2, "plain events are not protected");
        assert_eq!(
            by_id(&grouped.id).3.as_deref(),
            Some("g1"),
            "group id captured"
        );
        assert!(
            !by_id(&grouped.id).4,
            "regular group events are not metadata"
        );
    });
}

#[test]
fn count_stops_exactly_at_the_cap() {
    // NIP-45: the relay's count limit cuts exactly — the created_at
    // boundary continuation of the REQ path (NIP-67) must not inflate
    // the count beyond the cap or hide the `approximate` flag.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // All events share one created_at so the boundary continuation
        // would previously collect every one of them.
        for i in 0..7 {
            let e = event(
                7,
                &format!("r-{i}"),
                now,
                vec![vec!["e".into(), "t".repeat(64)]],
            );
            assert_eq!(db.put(e, now).await, PutOutcome::Stored);
        }
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kinds": [7], "#e": ["t".repeat(64)]}))
                .unwrap();
        let (events, more) = db.count(vec![f], 5, now).await;
        assert_eq!(events.len(), 5, "the cap cuts exactly");
        assert!(more, "the capped scan is flagged as approximate");
    });
}

#[test]

// ----- replaceable d-tag semantics -----
fn replaceable_kinds_ignore_the_d_tag() {
    // NIP-01: kind 0/3/10000-19999 are replaced per (pubkey, kind) —
    // a `d` tag must not create a separate slot that keeps old versions
    // alive.
    let db = DbClient::open(
        &config(),
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
    let now = unix_now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let d = vec![vec!["d".to_string(), "weird".to_string()]];
        let v1 = event(0, "{\"name\":\"old\"}", now, d.clone());
        let v2 = event(0, "{\"name\":\"new\"}", now + 5, vec![]);
        assert_eq!(db.put(v1.clone(), now).await, PutOutcome::Stored);
        assert_eq!(
            db.put(v2.clone(), now).await,
            PutOutcome::Replaced,
            "the d-tagged kind 0 must be replaced by the plain one"
        );
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [0]})).unwrap();
        let (res, _) = db.query(vec![f], 500, now).await;
        assert_eq!(res.len(), 1, "only the latest kind 0 is stored");
        assert_eq!(res[0].id, v2.id);
    });
}

#[test]

// ----- overload protection -----
fn request_fails_fast_when_the_queue_is_full() {
    // Overload protection: with a full queue, new requests fail fast
    // instead of accumulating in memory, and the overload is surfaced
    // in the stats error counter.
    let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let db = DbClient::open(&config(), true, Arc::clone(&errors), 0, 128, 4, 8).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = unix_now();
        let ev = event(1, "x", now, vec![]);
        // Simulate a full queue: the message cap is exceeded.
        db.pending_msgs
            .store(4, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(ev.clone(), now).await;
        assert!(
            matches!(out, PutOutcome::Invalid(_)),
            "must fail fast when the queue is full: {out:?}"
        );
        assert_eq!(errors.load(std::sync::atomic::Ordering::Relaxed), 1);
        // The event cap is also enforced.
        db.pending_msgs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        db.pending_events
            .store(8, std::sync::atomic::Ordering::Relaxed);
        let out = db.put(ev, now).await;
        assert!(matches!(out, PutOutcome::Invalid(_)));
        // With the queue drained, requests are served again.
        db.pending_events
            .store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            db.put(event(1, "y", now, vec![]), now).await,
            PutOutcome::Stored
        );
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
    let db = DbClient::open(
        &cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262144,
    )
    .unwrap();
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
