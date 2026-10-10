// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The registry's own rows (MIK-7642 PR.C, design r5 D3/D5, r4 R4.2).

use std::sync::Arc;

use serde_json::json;

use super::{CallKey, InFlightCalls};

fn key(owner: &str, session: Option<&str>, id: &serde_json::Value) -> CallKey {
    CallKey::new("ledger", Some(owner), session, id).expect("an owner is present")
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
    let mine = key("alice", Some("s1"), &json!(7));
    let (_held, registration) = calls.register(mine.clone()).expect("registered");
    let call = registration.run(std::future::pending::<()>());
    for other in [
        key("bob", Some("s1"), &json!(7)),
        key("alice", Some("s2"), &json!(7)),
        key("alice", None, &json!(7)),
        key("alice", Some("s1"), &json!("7")),
        CallKey::new("other-backend", Some("alice"), Some("s1"), &json!(7)).unwrap(),
    ] {
        assert!(
            !calls.cancel(&other),
            "{other:?} must not reach alice's call"
        );
    }
    assert!(calls.cancel(&mine));
    assert!(call.await.is_none(), "the call was aborted");
}

/// D5: a second call under a live key is not registered and leaves the first
/// untouched (the duplicate holds no registration, so its finish removes
/// nothing), and the first finishing frees the key.
#[test]
fn a_duplicate_key_is_refused_and_cannot_unregister_the_live_call() {
    let calls = Arc::new(InFlightCalls::default());
    let k = key("alice", None, &json!(1));
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

/// A registration knows when its caller's own cancel aborted its dispatch,
/// and only then: a cancel that lands after the call finished aborts nothing.
/// Mutants: `cancelled` answering for any registration; the abort read from
/// the handle (set by a late cancel) instead of the dispatch's outcome.
#[tokio::test]
async fn a_registration_knows_whether_its_caller_cancelled_it() {
    let calls = Arc::new(InFlightCalls::default());
    let (cancelled, on_cancel) = calls.register(key("alice", None, &json!(1))).unwrap();
    let held = on_cancel.run(std::future::pending::<()>());
    assert!(calls.cancel(&key("alice", None, &json!(1))));
    assert!(held.await.is_none());
    assert!(cancelled.cancelled());
    // Finished first, cancelled after: the late cancel still finds the live
    // registration, but the dispatch was never aborted.
    let (finished, on_finish) = calls.register(key("alice", None, &json!(2))).unwrap();
    assert_eq!(on_finish.run(std::future::ready(7)).await, Some(7));
    assert!(calls.cancel(&key("alice", None, &json!(2))));
    assert!(!finished.cancelled(), "a late cancel aborted nothing");
}

/// The caller's cancel is told from a backend that returns the same error by
/// the registration, not by the error's fields. Mutant: either half of
/// `cancelled_by_caller` dropped.
#[tokio::test]
async fn only_an_aborted_registration_makes_a_failure_the_callers_cancel() {
    let calls = Arc::new(InFlightCalls::default());
    let (aborted, on_abort) = calls.register(key("alice", None, &json!(1))).unwrap();
    let (running, _) = calls.register(key("alice", None, &json!(2))).unwrap();
    assert!(calls.cancel(&key("alice", None, &json!(1))));
    assert!(
        calls.cancel(&key("alice", None, &json!(2))),
        "asked, never aborted"
    );
    let minted =
        super::explicitly_cancellable(Some(on_abort), std::future::pending::<crate::Result<()>>())
            .await
            .expect_err("the abort is an error");
    // A backend's own error, spelled exactly like the gateway's.
    let echoed = crate::Error::JsonRpc {
        code: super::CLIENT_CANCELLED_CODE,
        message: super::CLIENT_CANCELLED_MESSAGE.to_owned(),
        data: None,
    };
    let other = crate::Error::Protocol("backend failed".to_owned());
    assert!(super::cancelled_by_caller(Some(&aborted), Some(&minted)));
    assert!(
        !super::cancelled_by_caller(Some(&running), Some(&echoed)),
        "a backend echo on a live call"
    );
    assert!(
        !super::cancelled_by_caller(Some(&aborted), Some(&other)),
        "another failure"
    );
    assert!(
        !super::cancelled_by_caller(None, Some(&minted)),
        "an unregistered call"
    );
}
