// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows of I5 design §10: `Need` refcount algebra, the URI budget and
//! the coalescer window.

use std::time::{Duration, Instant};

use super::*;

fn uri(u: &str) -> Interest {
    Interest::ResourceUpdated(u.to_owned())
}

#[test]
fn two_keys_sharing_a_uri_keep_it_until_the_last_goes() {
    let mut need = Need::default();
    assert_eq!(need.add(&uri("a")), Ok(true));
    assert_eq!(need.add(&uri("a")), Ok(false), "same filter");
    assert!(!need.remove(&uri("a")), "one key still names a");
    assert_eq!(need.filter().1, vec!["a".to_owned()]);
    assert!(need.remove(&uri("a")));
    assert!(need.is_empty());
    assert!(!need.remove(&uri("a")), "a replayed last is ignored");
    assert!(need.is_empty());
}

#[test]
fn uri_interest_asks_for_resource_list_changes_but_does_not_emit_them() {
    let mut need = Need::default();
    need.add(&uri("a")).unwrap();
    assert!(need.filter().0.resources_changed);
    assert!(!need.emits(NoteKind::ResourcesChanged, None));
    assert_eq!(
        need.add(&Interest::ResourcesChanged),
        Ok(false),
        "already asked"
    );
    assert!(need.emits(NoteKind::ResourcesChanged, None));
    assert!(need.emits(NoteKind::ResourceUpdated, Some("a")));
    assert!(!need.emits(NoteKind::ResourceUpdated, Some("b")));
    assert!(!need.emits(NoteKind::ResourceUpdated, None));
    assert_eq!(need.add(&Interest::PromptsChanged), Ok(true));
    assert!(need.remove(&Interest::PromptsChanged));
    assert!(
        !need.remove(&Interest::ResourcesChanged),
        "uri a still asks"
    );
    assert!(need.remove(&uri("a")));
    assert!(need.is_empty());
}

#[test]
fn the_uri_budget_refuses_a_new_uri_only() {
    let mut need = Need::default();
    for i in 0..MAX_URIS {
        need.add(&uri(&format!("u{i}"))).unwrap();
    }
    assert_eq!(need.add(&uri("one-more")), Err(Full));
    assert_eq!(
        need.add(&uri("u0")),
        Ok(false),
        "an existing uri is no new cost"
    );
    assert!(!need.filter().1.contains(&"one-more".to_owned()));

    let mut bytes = Need::default();
    let big = "x".repeat(2000);
    let mut n = 0;
    while bytes.add(&uri(&format!("{n}{big}"))).is_ok() {
        n += 1;
    }
    assert!(n < MAX_URIS && n * 2000 <= MAX_URI_BUDGET_BYTES, "{n}");
    bytes.remove(&uri(&format!("0{big}")));
    assert_eq!(
        bytes.add(&uri(&format!("again{big}"))),
        Ok(true),
        "a removal frees its bytes"
    );
}

#[test]
fn a_burst_is_one_event_after_the_window() {
    let t0 = Instant::now();
    let mut c = Coalescer::default();
    for i in 0..5 {
        c.offer(
            NoteKind::ResourceUpdated,
            Some("a".into()),
            t0 + Duration::from_millis(40 * i),
        );
    }
    c.offer(
        NoteKind::PromptsChanged,
        None,
        t0 + Duration::from_millis(100),
    );
    assert!(c.due(t0 + Duration::from_millis(999)).is_empty());
    assert_eq!(c.next(), Some(t0 + WINDOW));
    assert_eq!(
        c.due(t0 + WINDOW),
        vec![(NoteKind::ResourceUpdated, Some("a".into()))]
    );
    assert_eq!(c.due(t0 + Duration::from_millis(1100)).len(), 1);
    assert_eq!(c.next(), None);
    c.offer(NoteKind::ResourceUpdated, Some("a".into()), t0 + WINDOW * 2);
    assert_eq!(
        c.due(t0 + WINDOW * 3).len(),
        1,
        "a new window after the last"
    );
}

#[test]
fn the_snapshot_keeps_on_error_and_revokes_only_on_complete_absence() {
    let mut snap = Snapshot::default();
    assert_eq!(snap.verdict("a"), Verdict::Skip, "no snapshot yet");
    snap.read(["a".to_owned()].into(), false);
    assert_eq!(snap.verdict("a"), Verdict::Deliver);
    assert_eq!(
        snap.verdict("b"),
        Verdict::Skip,
        "a truncated read proves nothing"
    );
    snap.read(["a".to_owned()].into(), true);
    assert_eq!(snap.verdict("b"), Verdict::Revoke);
    assert_eq!(snap.verdict("a"), Verdict::Deliver);
}

/// A `tools_changed` subscription keeps the backend's listener alive and asks
/// upstream for tool-list changes; the last one releases both (I5b).
#[test]
fn tools_interest_is_counted_asked_for_and_emitted() {
    let mut need = Need::default();
    assert_eq!(need.add(&Interest::ToolsChanged), Ok(true));
    assert!(need.filter().0.tools_changed);
    assert!(need.emits(NoteKind::ToolsChanged, None));
    assert!(!need.emits(NoteKind::PromptsChanged, None));
    assert!(!need.is_empty());
    assert!(need.remove(&Interest::ToolsChanged));
    assert!(need.is_empty());
    assert!(!need.filter().0.tools_changed);
}
