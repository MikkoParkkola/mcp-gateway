// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what a session keeps of the views its streams open is bounded,
//! and a view's key is its identity, not a display label.

use super::*;
use crate::gateway::session_id::SessionOwner;

fn subject_labelled(subject: &str, label: Option<&str>) -> ViewSubject {
    ViewSubject {
        grant_subject: Some(crate::identity_grants::GrantSubject::new(
            "proxy",
            subject,
            label.map(str::to_owned),
        )),
        ..ViewSubject::default()
    }
}

#[test]
fn a_changed_display_label_is_the_same_view() {
    let plain = subject_labelled("alice", None);
    let relabelled = subject_labelled("alice", Some("Alice A."));
    assert_eq!(plain.key(), relabelled.key());
    assert_ne!(plain.key(), subject_labelled("bob", None).key());
}

#[test]
fn idle_records_are_dropped_at_the_bound() {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    let owner = SessionOwner::Anonymous;
    let (id, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, None);
    let session = multiplexer
        .sessions
        .read()
        .get(&id)
        .map(Arc::clone)
        .expect("the session exists");
    for n in 0..(MAX_IDLE_RECORDS * 4) {
        drop(session.record_for(&subject_labelled(&format!("user-{n}"), None)));
    }
    assert!(
        session.views().len() <= MAX_IDLE_RECORDS,
        "idle records stay bounded: {}",
        session.views().len()
    );
}

#[test]
fn a_record_an_open_stream_holds_is_kept() {
    let multiplexer = NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    );
    let owner = SessionOwner::Anonymous;
    let (id, _rx) = multiplexer.get_or_create_session_scoped(Some("s"), &owner, None);
    let session = multiplexer
        .sessions
        .read()
        .get(&id)
        .map(Arc::clone)
        .expect("the session exists");
    let held = session.record_for(&subject_labelled("held", None));
    for n in 0..(MAX_IDLE_RECORDS * 4) {
        drop(session.record_for(&subject_labelled(&format!("user-{n}"), None)));
    }
    let again = session.record_for(&subject_labelled("held", None));
    assert!(
        Arc::ptr_eq(&held, &again),
        "a held record is never replaced"
    );
}
