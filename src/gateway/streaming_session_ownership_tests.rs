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
    let id = m.get_or_create_session_id_scoped(None, &cred("alice"), None);
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
