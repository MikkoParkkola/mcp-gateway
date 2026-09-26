// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session resume and mint under concurrency (NFR.WORKLOAD.1 session lock).

use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use axum::http::HeaderMap;

use crate::config::StreamingConfig;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::streaming::{NotificationMultiplexer, TaggedNotification};

fn mux() -> Arc<NotificationMultiplexer> {
    Arc::new(NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        StreamingConfig::default(),
    ))
}

fn cred(principal: &str) -> SessionOwner {
    SessionOwner::Credential(principal.to_string())
}

fn note() -> TaggedNotification {
    TaggedNotification {
        source: "b".to_string(),
        event_type: "notification".to_string(),
        data: serde_json::json!({}),
        event_id: None,
    }
}

/// L1: resuming a live session takes only the read lock, so it completes
/// while another reader holds the map.
#[test]
fn l1_a_resume_proceeds_while_the_map_is_read() {
    let m = mux();
    let (id, _rx) = m.get_or_create_session_for(None, &cred("alice"));
    let guard = m.sessions.read();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = {
        let m = Arc::clone(&m);
        let id = id.clone();
        std::thread::spawn(move || {
            let (again, _rx) = m.get_or_create_session_for(Some(&id), &cred("alice"));
            let _ = done_tx.send(again);
        })
    };
    let resumed = done_rx.recv_timeout(Duration::from_secs(2));
    // Released before joining, so a blocked worker finishes and the join
    // cannot hang the suite.
    drop(guard);
    worker.join().expect("worker");
    assert_eq!(
        resumed.expect("a resume must not wait for the write lock"),
        id
    );
}

/// L2: concurrent resumes of one session all land on it, and every returned
/// receiver is live.
#[test]
fn l2_concurrent_resumes_share_one_session() {
    let m = mux();
    let (id, _rx) = m.get_or_create_session_for(None, &cred("alice"));
    let start = Barrier::new(32);
    let receivers: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..32)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    m.get_or_create_session_for(Some(&id), &cred("alice"))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("resume"))
            .collect()
    });
    let session = m.sessions.read().get(id.as_str()).cloned().expect("live");
    session.tx.send(note()).expect("a receiver is live");
    for (got, mut rx) in receivers {
        assert_eq!(got, id);
        assert!(
            rx.try_recv().is_ok(),
            "each resumed receiver gets the broadcast"
        );
    }
}

/// L3: concurrent mints are all distinct and all stored.
#[test]
fn l3_concurrent_mints_are_distinct() {
    let m = mux();
    let before = m.sessions.read().len();
    let start = Barrier::new(32);
    let ids: std::collections::HashSet<String> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..32)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    m.get_or_create_session_for(None, &cred("alice"))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mint").0)
            .collect()
    });
    assert_eq!(ids.len(), 32);
    assert_eq!(m.sessions.read().len(), before + 32);
}

/// L4: presenting another owner's live id under concurrency mints fresh ids
/// and leaves the victim's session alone.
#[test]
fn l4_concurrent_owner_mismatch_never_joins() {
    let m = mux();
    let (victim, mut victim_rx) = m.get_or_create_session_for(None, &cred("alice"));
    let start = Barrier::new(16);
    let ids: std::collections::HashSet<String> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    m.get_or_create_session_for(Some(&victim), &cred("mallory"))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mint").0)
            .collect()
    });
    assert_eq!(ids.len(), 16);
    assert!(!ids.contains(&victim));
    let session = m
        .sessions
        .read()
        .get(victim.as_str())
        .cloned()
        .expect("live");
    assert_eq!(session.owner, cred("alice"));
    assert_eq!(session.tx.receiver_count(), 1, "nobody joined the victim");
    session.tx.send(note()).expect("send");
    assert!(victim_rx.try_recv().is_ok());
}

/// L5: the scoped call stores the credential it was given on the session it
/// returns, and the next call replaces it, with `None` too.
#[test]
fn l5_the_credential_lands_on_the_returned_session() {
    let m = mux();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer l5-token".parse().expect("header"),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);
    assert!(held.is_some(), "precondition: a bearer is held");
    let (id, _rx) = m.get_or_create_session_scoped(None, &cred("alice"), held);
    let credential = |id: &str| {
        let session = m.sessions.read().get(id).cloned().expect("live");
        session.credential.read().is_some()
    };
    assert!(credential(&id));
    let (again, _rx) = m.get_or_create_session_scoped(Some(&id), &cred("alice"), None);
    assert_eq!(again, id);
    assert!(!credential(&id), "a later call replaces the credential");
}
