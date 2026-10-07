// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session ownership: a session id resumes only its owner's session (F9).

use super::*;
use crate::config::StreamingConfig;

fn cred(principal: &str) -> SessionOwner {
    SessionOwner::Credential(principal.to_string())
}

fn mux() -> NotificationMultiplexer {
    NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        StreamingConfig::default(),
    )
}

#[test]
fn a_request_reaches_only_its_own_session() {
    // Sampling and elicitation went to every connected session, so one
    // client saw another's prompt and could answer on their behalf. The
    // destructive-action confirmation runs through this path.
    let m = mux();
    let (alice, mut alice_rx) = m.get_or_create_session_for(None, &cred("alice"));
    let (_bob, mut bob_rx) = m.get_or_create_session_for(None, &cred("bob"));

    let note = TaggedNotification {
        source: "gw".to_string(),
        event_type: "sampling/createMessage".to_string(),
        data: serde_json::json!({"jsonrpc": "2.0"}),
        event_id: None,
    };
    assert!(m.send_to_session(&alice, note));

    assert!(
        alice_rx.try_recv().is_ok(),
        "the originating session receives it"
    );
    assert!(
        bob_rx.try_recv().is_err(),
        "another session must not see another client's prompt"
    );

    // An unknown session is a refusal, not a broadcast.
    let note2 = TaggedNotification {
        source: "gw".to_string(),
        event_type: "sampling/createMessage".to_string(),
        data: serde_json::json!({"jsonrpc": "2.0"}),
        event_id: None,
    };
    assert!(!m.send_to_session("gw-not-a-session", note2));
}

#[test]
fn a_caller_cannot_join_another_identity_session() {
    // A session id travels in a header the caller controls. Without
    // ownership, a per-session check compares one caller-supplied value
    // against another, and one client can name another's session.
    let m = mux();
    let (alice_id, _rx) = m.get_or_create_session_for(None, &cred("alice"));

    let (given, _rx2) = m.get_or_create_session_for(Some(&alice_id), &cred("mallory"));
    assert_ne!(
        given, alice_id,
        "presenting another identity's session id must not join it"
    );
}

#[test]
fn two_keys_sharing_a_display_name_are_different_owners() {
    // `name` is operator-chosen and not unique. Keying ownership on it let
    // one API key attach to another's session.
    let m = mux();
    let (a, _rx) = m.get_or_create_session_for(None, &cred("aaa111"));
    let (given, _rx2) = m.get_or_create_session_for(Some(&a), &cred("bbb222"));
    assert_ne!(given, a, "a different credential is a different owner");
}

#[test]
fn the_owner_resumes_the_same_session() {
    // Resumption after a dropped stream is a real flow and must keep working.
    let m = mux();
    let (id, _rx) = m.get_or_create_session_for(None, &cred("alice"));
    let (again, _rx2) = m.get_or_create_session_for(Some(&id), &cred("alice"));
    assert_eq!(again, id, "the owner must resume its own session");
}

#[test]
fn an_anonymous_holder_resumes_by_its_minted_id() {
    // F9-T8. With authentication off the minted id is the only credential:
    // its holder resumes by presenting it.
    let m = mux();
    let (id, _rx) = m.get_or_create_session(None);
    let (again, _rx2) = m.get_or_create_session(Some(&id));
    assert_eq!(again, id);
}

/// NFR.WORKLOAD.1: a session opened for its id alone (every legacy POST) holds
/// no notification channel. A send to it is refused as a send with no
/// receiver is, the reaper sees it abandoned, and a later stream on the same
/// id still subscribes and receives.
#[test]
fn an_id_only_session_opens_its_channel_on_first_subscribe() {
    let m = mux();
    let id = m
        .get_or_create_session_id_scoped(None, &cred("alice"), None)
        .expose_secret()
        .to_owned();
    let session = Arc::clone(m.sessions.read().get(id.as_str()).expect("opened"));
    assert!(
        session.tx.get().is_none(),
        "an id-only open built a channel"
    );
    assert_eq!(session.receiver_count(), 0);
    assert!(
        !m.send_to_session(&id, note()),
        "a send with no receiver reported delivery"
    );
    assert!(session.tx.get().is_none(), "a refused send built a channel");
    m.broadcast(note());
    assert!(session.tx.get().is_none(), "a fan-out built a channel");
    assert_eq!(
        m.resume_session_id_scoped(Some(&id), &cred("alice"), None)
            .map(|resumed| resumed.expose_secret().to_owned()),
        Some(id.clone()),
        "the owner resumes by id"
    );
    assert!(
        session.tx.get().is_none(),
        "an id-only resume built a channel"
    );

    let (again, mut rx) = m.get_or_create_session_for(Some(&id), &cred("alice"));
    assert_eq!(again, id, "the owner resumes the id-only session");
    assert!(
        m.send_to_session(&id, note()),
        "a subscribed session missed a send"
    );
    assert_eq!(rx.try_recv().expect("delivered").event_type, "notification");
}

fn note() -> TaggedNotification {
    TaggedNotification {
        source: "b".to_string(),
        event_type: "notification".to_string(),
        data: serde_json::json!({}),
        event_id: None,
    }
}

/// An unopened session past its TTL is abandoned: the reaper removes it as it
/// removed a session whose only receiver was dropped.
#[test]
fn the_reaper_removes_an_unopened_session() {
    let m = mux();
    let id = m
        .get_or_create_session_id_scoped(None, &cred("alice"), None)
        .expose_secret()
        .to_owned();
    assert_eq!(
        m.reap_expired_sessions(std::time::Duration::ZERO),
        vec![id.clone()]
    );
    assert!(
        m.sessions.read().get(id.as_str()).is_none(),
        "an unopened session outlived its TTL"
    );
}

/// MIK-7853.RACE.1: a session is visible before its channel opens, so streams
/// may subscribe to it at once. Every one of them must join the one channel:
/// a subscriber left on a channel nobody sends to would never see a frame.
/// Every stream reaches the channel through `ClientSession::subscribe`; the
/// GET handler calls it under the store's shared read lock, so streams meet
/// there at once. The resume call used here subscribes after its lock is
/// released, which leaves the same contention.
#[test]
fn streams_subscribing_at_once_to_an_unopened_session_share_one_channel() {
    const STREAMS: usize = 8;
    for _ in 0..200 {
        let m = Arc::new(mux());
        let id = m
            .get_or_create_session_id_scoped(None, &cred("alice"), None)
            .expose_secret()
            .to_owned();
        let start = Arc::new(std::sync::Barrier::new(STREAMS));
        let streams: Vec<_> = (0..STREAMS)
            .map(|_| {
                let (m, id, start) = (Arc::clone(&m), id.clone(), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    m.get_or_create_session_for(Some(&id), &cred("alice"))
                })
            })
            .collect();
        let mut rxs: Vec<_> = streams
            .into_iter()
            .map(|t| {
                let (again, rx) = t.join().expect("subscriber panicked");
                assert_eq!(again, id, "a concurrent resume minted a new session");
                rx
            })
            .collect();
        assert!(m.send_to_session(&id, note()), "no stream was reached");
        for rx in &mut rxs {
            assert_eq!(
                rx.try_recv()
                    .expect("a concurrent subscriber missed the send")
                    .event_type,
                "notification"
            );
        }
    }
}

/// `MIK-8014.PERF.2a`: the fingerprint is held with the id it was made from.
/// A session that ended and was opened again under the same id is logged as
/// that id, and a second session of the same owner is never logged with the
/// first one's fingerprint.
#[test]
fn a_reused_id_is_fingerprinted_as_the_new_session() {
    use crate::gateway::session_id::session_fp;
    let m = mux();
    drop(m.seed_session("gw-reused"));
    m.remove_session("gw-reused");
    drop(m.seed_session("gw-reused"));
    drop(m.seed_session("gw-other"));
    for raw in ["gw-reused", "gw-other"] {
        let resumed = m.get_or_create_session_id_scoped(Some(raw), &SessionOwner::Anonymous, None);
        assert_eq!(resumed.expose_secret(), raw, "the named session resumed");
        assert_eq!(
            resumed.fp(),
            session_fp(raw),
            "{raw} carries another id's fingerprint"
        );
        assert_eq!(resumed.to_string(), session_fp(raw));
    }
    assert_ne!(session_fp("gw-reused"), session_fp("gw-other"));
}

/// `MIK-8014.PERF.2a`: removing a session logs the fingerprint its key already
/// holds; nothing is hashed again, with logging on.
#[test]
fn removing_a_session_does_not_fingerprint_it_again() {
    use crate::gateway::session_id::FINGERPRINTS;
    let m = mux();
    drop(m.seed_session("gw-gone"));
    let (_captured, _guard) = crate::gateway::session_id::log_capture::capture_debug();
    FINGERPRINTS.with(|n| n.set(0));
    m.remove_session("gw-gone");
    assert!(!m.has_session("gw-gone"), "the session was removed");
    assert_eq!(FINGERPRINTS.with(std::cell::Cell::get), 0);
}

/// Only the session's owner can remove it: another owner's DELETE leaves it in
/// place, and the owner's removes it and gets the removed id back.
#[test]
fn only_the_owner_removes_a_session() {
    let m = mux();
    let id = m
        .get_or_create_session_id_scoped(None, &cred("alice"), None)
        .expose_secret()
        .to_owned();
    assert!(m.remove_session_for(&id, &cred("mallory")).is_none());
    assert!(m.has_session(&id), "another owner removed the session");
    let removed = m.remove_session_for(&id, &cred("alice"));
    assert_eq!(
        removed.as_ref().map(SessionId::expose_secret),
        Some(id.as_str())
    );
    assert!(!m.has_session(&id), "the owner's DELETE left the session");
}
