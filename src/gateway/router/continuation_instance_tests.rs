// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8168`: a continuation is answered back only to the backend instance
//! that asked. A live reload that replaces a backend under the same name must
//! not receive the old backend's opaque `requestState` or the user's answers:
//! the retry is refused before any backend is reached, on `/mcp` and on both
//! arms of `/mcp/{name}`.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::direct_continuation_tests::{
    BACKENDS, answers, call, code, dispatched, meta_call, state_of,
};
use super::direct_guards_fixture::{Answer, fixture, replace_backend};

/// I1 (`/mcp`): asked by `backend`, answered after `backend` was replaced
/// under the same name: refused (-32602), and the replacement is never
/// reached. Mutant: the binding by name only.
#[tokio::test]
async fn i1_a_reload_refuses_the_old_round_on_the_meta_route() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let asked = meta_call(&fx, "k-std", backend, json!({})).await;
        let state = state_of(&asked);
        let replacement = replace_backend(&fx, backend);
        let retry = json!({"requestState": state, "inputResponses": answers()});
        let refused = meta_call(&fx, "k-std", backend, retry).await;
        assert!(refused.get("error").is_some(), "{backend}: {refused}");
        assert_eq!(code(&refused), Some(-32602), "{backend}: {refused}");
        assert_eq!(
            replacement.load(Ordering::SeqCst),
            0,
            "{backend}: the replacement received the old round"
        );
    }
}

/// I2 (`/mcp/{name}`, both arms): the same on the per-backend route.
/// Mutant: the binding by name only.
#[tokio::test]
async fn i2_a_reload_refuses_the_old_round_on_the_direct_route() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let state = state_of(&asked);
        let replacement = replace_backend(&fx, backend);
        let retry = json!({"requestState": state, "inputResponses": answers()});
        let (_, refused) = call(&fx, backend, Some("alice"), retry).await;
        assert_eq!(code(&refused), Some(-32602), "{backend}: {refused}");
        assert_eq!(
            replacement.load(Ordering::SeqCst),
            0,
            "{backend}: the replacement received the old round"
        );
    }
}

/// I3 (control, both routes): replacing ANOTHER backend leaves the round
/// redeemable; only the instance that asked matters.
#[tokio::test]
async fn i3_replacing_another_backend_keeps_the_round() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (_, asked) = call(&fx, "alpha", Some("alice"), json!({})).await;
    let _ = replace_backend(&fx, "alpha-pt");
    let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
    let (_, done) = call(&fx, "alpha", Some("alice"), retry).await;
    assert!(done.get("error").is_none(), "direct: {done}");
    assert_eq!(dispatched(&fx), 2, "direct");

    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let asked = meta_call(&fx, "k-std", "alpha", json!({})).await;
    let _ = replace_backend(&fx, "alpha-pt");
    let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
    let done = meta_call(&fx, "k-std", "alpha", retry).await;
    assert!(done.get("error").is_none(), "meta: {done}");
}
