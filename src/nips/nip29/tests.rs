//! Tests of the group state machine.

use super::*;

fn event(kind: u64, pubkey: &str, h: Option<&str>, tags: Vec<Vec<String>>) -> Event {
    let mut tags = tags;
    if let Some(h) = h {
        tags.insert(0, vec![H.to_string(), h.to_string()]);
    }
    Event {
        id: String::new(),
        pubkey: pubkey.to_string(),
        created_at: 1_600_000_000,
        kind,
        tags,
        content: String::new(),
        sig: String::new(),
    }
}

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OTHER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn seeded() -> GroupStore {
    let mut store = GroupStore::default();
    let create = event(CREATE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&create, "", 1, false);
    let put_user = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
    store.apply(&put_user, "", 1, false);
    store
}

#[test]
fn create_and_admin() {
    let store = seeded();
    let g = store.group("g1").unwrap();
    assert!(g.is_admin(ADMIN));
    // put-user adds a member; without roles they are not an admin.
    assert!(g.is_member(OTHER));
    assert!(!g.is_admin(OTHER));
}

#[test]
fn moderation_requires_admin() {
    let store = seeded();
    let bad = event(9001, OTHER, Some("g1"), vec![vec![P.into(), ADMIN.into()]]);
    assert!(store.validate_write(&bad).is_err());
    let good = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]);
    assert!(store.validate_write(&good).is_ok());
}

#[test]
fn put_user_roles_from_p_tag_extras() {
    // NIP-29: a kind:9000 carries the roles as the elements after the
    // pubkey inside the `p` tag.
    let mut store = seeded();
    let put = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![
            P.into(),
            USER.into(),
            "ceo".into(),
            "secretary".into(),
        ]],
    );
    store.apply(&put, "", 1, false);
    let group = store.group("g1").unwrap();
    assert_eq!(
        group.members.get(USER).unwrap(),
        &["ceo".into(), "secretary".into()].into_iter().collect()
    );
    assert!(group.is_admin(USER));
}

#[test]
fn restricted_groups() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["restricted".into()]]);
    store.apply(&edit, "", 1, false);
    let msg_by_user = event(1, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&msg_by_user).is_err());
    // Join requests to an open group (not `closed`) are honored: the
    // user is admitted without privileges.
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&join).is_ok());
    store.apply(&join, "", 1, false);
    assert!(store.group("g1").unwrap().is_member(USER));
    assert!(!store.group("g1").unwrap().is_admin(USER));
    // A member of a restricted group may post.
    assert!(store.validate_write(&msg_by_user).is_ok());
    // A duplicate join request is rejected with the `duplicate:` prefix.
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert_eq!(
        store.validate_write(&join).unwrap_err(),
        "duplicate: you are already a member of this group"
    );
    // Removing the user restores the restriction.
    let remove = event(9001, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
    store.apply(&remove, "", 1, false);
    assert!(store.validate_write(&msg_by_user).is_err());
}

#[test]
fn invite_code_admits() {
    let mut store = seeded();
    let invite = event(
        9009,
        ADMIN,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    store.apply(&invite, "", 1, false);
    let join = event(
        JOIN,
        USER,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    assert!(store.validate_write(&join).is_ok());
    store.apply(&join, "", 1, false);
    assert!(store.group("g1").unwrap().is_member(USER));
}

#[test]
fn invalid_invite_code_is_final() {
    let mut store = seeded();
    let invite = event(
        9009,
        ADMIN,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    store.apply(&invite, "", 1, false);
    // A wrong code is rejected even on an otherwise open group.
    let join = event(
        JOIN,
        USER,
        Some("g1"),
        vec![vec![CODE.into(), "wrong".into()]],
    );
    assert_eq!(
        store.validate_write(&join).unwrap_err(),
        "restricted: invalid invite code"
    );
    // A closed group honors a valid invite code.
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]);
    store.apply(&edit, "", 1, false);
    let join = event(
        JOIN,
        USER,
        Some("g1"),
        vec![vec![CODE.into(), "abc".into()]],
    );
    assert!(store.validate_write(&join).is_ok());
}

#[test]
fn put_user_roles_replace_previous_roles() {
    // NIP-29: "the user roles must just be updated": a new kind:9000
    // replaces the previous role set instead of extending it.
    let mut store = seeded();
    let put = event(
        9000,
        ADMIN,
        Some("g1"),
        vec![vec![P.into(), USER.into(), "ceo".into()]],
    );
    store.apply(&put, "", 1, false);
    assert!(store.group("g1").unwrap().is_admin(USER));
    let demote = event(9000, ADMIN, Some("g1"), vec![vec![P.into(), USER.into()]]);
    store.apply(&demote, "", 1, false);
    let group = store.group("g1").unwrap();
    assert!(group.is_member(USER));
    assert!(
        !group.is_admin(USER),
        "roles without privilege elements are not admins"
    );
}

#[test]
fn closed_group_rejects_joins() {
    // NIP-29: `closed` means join requests are ignored — rejected and
    // not stored; admission happens via an invite code or an admin's
    // kind:9000.
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["closed".into()]]);
    store.apply(&edit, "", 1, false);
    let join = event(JOIN, USER, Some("g1"), vec![]);
    assert!(store.validate_write(&join).is_err());
}

#[test]
fn subgroups() {
    let mut store = seeded();
    // Create a second group and move g1 under it.
    let create2 = event(CREATE_GROUP, ADMIN, Some("g2"), vec![]);
    store.apply(&create2, "", 1, false);
    let adopt = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["parent".into(), "g2".into()]],
    );
    assert!(store.validate_write(&adopt).is_ok());
    store.apply(&adopt, "", 1, false);
    assert_eq!(store.group("g1").unwrap().parent.as_deref(), Some("g2"));
    assert_eq!(store.group("g2").unwrap().children, vec!["g1"]);

    // Self-parenting and cycles are rejected.
    let self_cycle = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g2".into()]],
    );
    assert!(store.validate_write(&self_cycle).is_err());
    let cycle = event(
        9002,
        ADMIN,
        Some("g2"),
        vec![vec!["parent".into(), "g1".into()]],
    );
    assert!(store.validate_write(&cycle).is_err());
    // Unknown parent is rejected.
    let ghost = event(
        9002,
        ADMIN,
        Some("g1"),
        vec![vec!["parent".into(), "ghost".into()]],
    );
    assert!(store.validate_write(&ghost).is_err());

    // Deleting a child removes it from the parent's child list.
    let delete_child = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&delete_child, "", 1, false);
    assert!(store.group("g1").is_none());
    assert!(store.group("g2").unwrap().children.is_empty());
}

#[test]
fn deleted_group_content_is_hidden() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
    store.apply(&edit, "", 1, false);
    let msg = event(1, ADMIN, Some("g1"), vec![]);
    let meta = store.apply(&msg, "", 1, true);
    // Before deletion: hidden from outsiders, visible to members.
    assert!(!store.visible_to(&msg, None));
    assert!(store.visible_to(&msg, Some(ADMIN)));
    // After deletion: the history must not become public.
    let delete = event(DELETE_GROUP, ADMIN, Some("g1"), vec![]);
    store.apply(&delete, "", 1, false);
    assert!(!store.visible_to(&msg, None));
    assert!(!store.visible_to(&msg, Some(ADMIN)));
    for m in &meta {
        assert!(!store.visible_to(m, Some(ADMIN)));
    }
}

#[test]
fn private_groups_hide_from_non_members() {
    let mut store = seeded();
    let edit = event(9002, ADMIN, Some("g1"), vec![vec!["private".into()]]);
    store.apply(&edit, "", 1, false);
    let msg = event(1, ADMIN, Some("g1"), vec![]);
    let outsider = "d".repeat(64);
    assert!(!store.visible_to(&msg, Some(&outsider)));
    assert!(store.visible_to(&msg, Some(ADMIN)));
    // OTHER is a member and may read private groups.
    assert!(store.visible_to(&msg, Some(OTHER)));
    let meta = store.apply(&msg, "", 1, true);
    for m in &meta {
        assert!(!store.visible_to(m, Some(&outsider)));
    }
}

#[test]
fn rebuild_order_applies_create_before_member_ops() {
    // Within the same second the create (9007) must be applied before member
    // operations (9000) and joins (9021), or the member/join ops are dropped
    // for a not-yet-existing group.
    assert!(group_rank(9007) < group_rank(9000));
    assert!(group_rank(9000) < group_rank(9021));
    assert!(group_rank(9008) < group_rank(9022));

    let mut events = vec![
        event(9000, ADMIN, Some("g1"), vec![vec![P.into(), OTHER.into()]]),
        event(CREATE_GROUP, ADMIN, Some("g1"), vec![]),
        event(JOIN, OTHER, Some("g1"), vec![]),
    ];
    for e in &mut events {
        e.created_at = 1_700_000_000;
    }
    events.sort_by(|a, b| {
        (a.created_at, group_rank(a.kind), a.kind, &a.id).cmp(&(
            b.created_at,
            group_rank(b.kind),
            b.kind,
            &b.id,
        ))
    });
    assert_eq!(events[0].kind, CREATE_GROUP, "create applies first");
    assert_eq!(events[1].kind, 9000, "member op applies second");
    assert_eq!(events[2].kind, JOIN, "join applies last");

    let mut store = GroupStore::default();
    for e in &events {
        store.apply(e, "", 1, false);
    }
    let g = store.group("g1").unwrap();
    assert!(g.is_member(OTHER), "the member op and join must both apply");
}
