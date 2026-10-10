// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The registry's own rows (MIK-7642 PR.C, design r5 D3/D5, r4 R4.2).

use std::sync::Arc;

use futures::future::Abortable;
use serde_json::json;

use super::{CallKey, InFlightCalls};

fn key(owner: &str, session: Option<&str>, id: serde_json::Value) -> CallKey {
    CallKey::new("ledger", Some(owner), session, &id).expect("an owner is present")
}

/// A caller with no owner is never registered, so its cancels always drop.
#[test]
fn a_caller_without_an_owner_has_no_key() {
    assert!(CallKey::new("ledger", None, None, &json!(1)).is_none());
    assert!(CallKey::new("ledger", Some(""), None, &json!(1)).is_none());
}

/// The owner's cancel aborts its own call; another owner, another session or
/// another id with the same number aborts nothing. Mutants: any key field
/// dropped from the key.
#[tokio::test]
async fn a_cancel_reaches_only_the_call_registered_under_its_own_key() {
    let calls = Arc::new(InFlightCalls::default());
    let mine = key("alice", Some("s1"), json!(7));
    let (_held, registration) = calls.register(mine.clone()).expect("registered");
    let call = Abortable::new(std::future::pending::<()>(), registration);
    for other in [
        key("bob", Some("s1"), json!(7)),
        key("alice", Some("s2"), json!(7)),
        key("alice", None, json!(7)),
        key("alice", Some("s1"), json!("7")),
        CallKey::new("other-backend", Some("alice"), Some("s1"), &json!(7)).unwrap(),
    ] {
        assert!(
            !calls.cancel(&other),
            "{other:?} must not reach alice's call"
        );
    }
    assert!(calls.cancel(&mine));
    assert!(call.await.is_err(), "the call was aborted");
}

/// D5: a second call under a live key is not registered and leaves the first
/// untouched (the duplicate holds no registration, so its finish removes
/// nothing), and the first finishing frees the key.
#[test]
fn a_duplicate_key_is_refused_and_cannot_unregister_the_live_call() {
    let calls = Arc::new(InFlightCalls::default());
    let k = key("alice", None, json!(1));
    let first = calls.register(k.clone()).expect("the first registers");
    assert!(
        calls.register(k.clone()).is_none(),
        "a duplicate is refused"
    );
    assert_eq!(calls.len(), 1);
    drop(first);
    assert_eq!(calls.len(), 0, "the live call's own finish removes it");
    assert!(calls.register(k).is_some(), "the key is free again");
}
