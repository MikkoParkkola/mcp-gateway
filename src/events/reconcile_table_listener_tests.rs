// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6), snapshot rows:
//! a catalogue snapshot answers `authorize_uri` only for the backend instance
//! and the URI interest it was read for (L4, finding #15). Red on base.

use super::*;

/// A complete snapshot of `b` listing only `file:///a`.
fn read_only_a(listeners: &UpstreamListeners) {
    let set: HashSet<String> = ["file:///a".to_owned()].into();
    listeners
        .backends
        .lock()
        .get("b")
        .expect("listener")
        .snapshot
        .lock()
        .read(set, true);
}

/// T05 (MIK-7897 LIFE.3b): after `b` is replaced by a new instance, the old
/// instance's snapshot no longer refuses a URI; the URI is judged live (an
/// unreadable backend admits, design section 7).
#[tokio::test]
async fn t05_a_replaced_backend_is_not_judged_by_the_old_snapshot() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    let listeners = UpstreamListeners::new(
        Arc::clone(&registry),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    );
    listeners.add("b", &watched("file:///a")).expect("room");
    read_only_a(&listeners);
    assert!(
        listeners
            .authorize_uri("b", "file:///new", None)
            .await
            .is_err(),
        "premise: the snapshot refuses an absent URI"
    );
    assert!(registry.remove("b"));
    assert!(registry.register(offline("b")));
    assert!(
        listeners
            .authorize_uri("b", "file:///new", None)
            .await
            .is_ok(),
        "the replaced instance is read live, not by the old snapshot"
    );
}

/// T06 (MIK-7897 LIFE.3b): once the last URI interest leaves, the snapshot
/// stops being read, so it no longer answers for a new URI.
#[tokio::test]
async fn t06_a_snapshot_left_by_the_last_uri_interest_does_not_answer() {
    let hub = listeners();
    hub.add("b", &watched("file:///a")).expect("room");
    hub.add("b", &Interest::PromptsChanged).expect("room");
    read_only_a(&hub);
    hub.remove("b", &watched("file:///a"));
    assert!(
        hub.backends.lock().contains_key("b"),
        "premise: prompts keep the listener"
    );
    assert!(
        hub.authorize_uri("b", "file:///new", None).await.is_ok(),
        "a stale snapshot does not refuse a new URI"
    );
}

/// T05, ledger-swap half (R1a review HIGH): once the running session takes
/// the replacing instance's ledger, the old instance's snapshot is gone.
#[tokio::test]
async fn t05_a_ledger_swap_drops_the_old_snapshot() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    let listeners = UpstreamListeners::new(
        Arc::clone(&registry),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    );
    listeners.add("b", &watched("file:///a")).expect("room");
    read_only_a(&listeners);
    assert!(registry.remove("b"));
    assert!(registry.register(offline("b")));
    let shared = listeners.backends.lock()["b"].clone();
    shared.refresh_ledger();
    assert!(
        listeners
            .authorize_uri("b", "file:///new", None)
            .await
            .is_ok(),
        "the new instance is judged live after the swap"
    );
}

/// T06, in-flight half (R1a review HIGH): a catalogue read begun before the
/// last URI interest left cannot refill the cleared snapshot.
#[test]
fn t06_a_read_begun_before_a_clear_is_dropped() {
    let mut snapshot = Snapshot::default();
    let begun = snapshot.epoch();
    snapshot.read(["file:///a".to_owned()].into(), true);
    snapshot.clear();
    assert!(
        !snapshot.read_at(begun, (["file:///a".to_owned()].into(), true), u64::MAX),
        "the stale read is dropped"
    );
    assert!(!snapshot.is_known(), "the snapshot stays empty");
}

/// T34 (MIK-8194 SNAPAUTH.1): a snapshot whose read began at generation 5
/// revokes an absent URI only for a grant it covered; a renewal granted at
/// 6, after the read began, is admitted until a newer read judges it.
#[tokio::test]
async fn t34_a_snapshot_does_not_revoke_a_later_grant() {
    let hub = listeners();
    hub.add("b", &watched("file:///a")).expect("room");
    let epoch = hub.backends.lock()["b"].snapshot.lock().epoch();
    assert!(
        hub.backends.lock()["b"].snapshot.lock().read_at(
            epoch,
            (["file:///a".to_owned()].into(), true),
            5
        ),
        "premise: the read is applied"
    );
    assert!(
        hub.authorize_uri("b", "file:///x", Some(6)).await.is_ok(),
        "a grant after the read began is not revoked by it"
    );
    assert!(
        hub.authorize_uri("b", "file:///x", Some(5)).await.is_err(),
        "a grant the read covered is"
    );
    assert!(
        hub.authorize_uri("b", "file:///x", None).await.is_err(),
        "a subscribe (no grant yet) is judged by the snapshot as before"
    );
}

/// MIK-8194 bound (lead ruling on #3625): at most one confirming catalogue
/// read per backend per `CONFIRM_EVERY`, so a backend answering "absent"
/// cannot drive a read per delivery.
#[test]
fn a_backend_gets_one_confirming_read_per_window() {
    let hub = listeners();
    assert!(hub.may_confirm("b"), "the first confirm runs");
    assert!(!hub.may_confirm("b"), "a second within the window does not");
    assert!(hub.may_confirm("c"), "another backend has its own window");
}
