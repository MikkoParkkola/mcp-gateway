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
        listeners.authorize_uri("b", "file:///new").await.is_err(),
        "premise: the snapshot refuses an absent URI"
    );
    assert!(registry.remove("b"));
    assert!(registry.register(offline("b")));
    assert!(
        listeners.authorize_uri("b", "file:///new").await.is_ok(),
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
        hub.authorize_uri("b", "file:///new").await.is_ok(),
        "a stale snapshot does not refuse a new URI"
    );
}
