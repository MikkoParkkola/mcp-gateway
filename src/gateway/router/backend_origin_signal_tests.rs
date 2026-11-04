// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Signals the gateway reads only from its own errors stay its own: a
//! backend's error carrying the recovery data keys, a tool text or the
//! removed-method mark is answered as the backend's failure, on the direct
//! and the meta route, and the gateway's own account refusal still is one.

use super::*;

/// A planted value no gateway text contains, so its absence is the proof.
const CANARY: &str = "x-signal-canary";

/// A peer's 400 body carrying every gateway-only recovery key: the two named
/// keys the gateway forwards from its own refusals and the playbook's tool
/// text, through the production `peer_refusal`.
fn peer_with_recovery_keys() -> crate::Error {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {
            "code": -32602,
            "message": "needs input",
            "data": {
                "requiredCapabilities": [CANARY],
                "unsupportedElicitationMode": CANARY,
                "tool_text": CANARY
            }
        }
    })
    .to_string();
    crate::transport::peer_refusal_for_test(
        &body,
        &RequestId::Number(1),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .expect("premise: a 400 body answering this request is surfaced")
}

/// A peer's 400 body carrying the gateway's removed-method mark.
fn peer_removed_method() -> crate::Error {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {
            "code": -32601,
            "message": "removed here",
            "data": {"removedInRevision": "2026-07-28"}
        }
    })
    .to_string();
    crate::transport::peer_refusal_for_test(
        &body,
        &RequestId::Number(1),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .expect("premise: a 400 body answering this request is surfaced")
}

/// The gateway's own account refusal, as its marking site builds it.
fn gateway_marked() -> crate::Error {
    crate::personal_accounts::refusal::mark(
        crate::Error::Config("connect your account".to_string()),
        &crate::identity_propagation::PropagationError::AccountReconnectRequired(
            "expired".to_string(),
        ),
        Some("acct-1"),
    )
}

/// BEO.10: a backend's recovery keys never reach the client, on either route,
/// and the failure counts as the backend's.
#[test]
fn a_backends_recovery_keys_are_not_forwarded_on_either_route() {
    let ((_, direct), direct_counts) = counted(async {
        let fx = fixture(Answer::FailsWith(peer_with_recovery_keys), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert!(
        direct["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("needs input")),
        "premise: the backend's failure: {direct}"
    );
    assert!(
        direct["error"].get("data").is_none_or(Value::is_null),
        "a backend's data is not forwarded: {direct}"
    );
    assert!(!direct.to_string().contains(CANARY), "{direct}");
    assert_eq!(all(&direct_counts), BACKEND, "{direct_counts}");

    let ((_, meta), meta_counts) = counted(async {
        let fx = fixture(Answer::FailsWith(peer_with_recovery_keys), |_| {}).await;
        invoke(&fx).await
    });
    assert!(
        folded_text(&meta).contains("needs input"),
        "premise: the backend's failure, folded: {meta}"
    );
    assert!(!meta.to_string().contains(CANARY), "{meta}");
    assert_eq!(all(&meta_counts), BACKEND, "{meta_counts}");
}

/// BEO.10: a plan step failing with a backend's error that carries a tool
/// text reports the backend's message, never that text.
#[test]
fn a_plan_step_failing_with_a_backends_tool_text_reports_only_its_message() {
    let ((_, answer), _) = counted(async {
        let fx = serving(
            Answer::FailsWith(peer_with_recovery_keys),
            one_step("continue"),
        )
        .await;
        run_p(&fx).await
    });
    let report = answer.to_string();
    assert!(
        report.contains("step_errors") && report.contains("needs input"),
        "premise: the step's failure is reported: {answer}"
    );
    assert!(!report.contains(CANARY), "{answer}");
}

/// BEO.10: a backend's error carrying the removed-method mark is answered as
/// the backend's failure (500, counted as the backend's), not as the
/// gateway's own removed-method refusal.
#[test]
fn a_backends_removed_method_mark_is_answered_as_its_failure() {
    let ((status, answer), text) = counted(async {
        let fx = fixture(Answer::FailsWith(peer_removed_method), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{answer}");
    assert_eq!(answer["error"]["code"], -32601, "premise: {answer}");
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// BEO.9 control: the gateway's own account refusal on the direct route is
/// still answered as the refusal, 403 with -32003.
#[test]
fn the_gateways_own_account_refusal_is_still_the_refusal() {
    let ((status, answer), _) = counted(async {
        let fx = fixture(Answer::FailsWith(gateway_marked), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["error"]["code"], -32003, "{answer}");
}
