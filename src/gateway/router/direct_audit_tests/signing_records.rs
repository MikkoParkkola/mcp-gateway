// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Signing refusals in the invocation record: a nonce refused on `/mcp`
//! leaves one record before it is answered, a replay named `replay_guard`
//! and a malformed nonce `syntax`. The chain check's own kind is pinned on
//! the both-routes row in `late_refusals`.

use super::counting::meta_invoke;
use super::*;

/// Signing on under `security.posture: hardened`: every `tools/call` on
/// either route must carry a nonce, and every caller a per-caller identity
/// (hardened_identity.rs), so the rows call as [`Caller::Oidc`].
async fn hardened_signing() -> Fixture {
    fixture(Setup {
        extras: &[Extra::Signing, Extra::Hardened],
        ..Setup::default()
    })
    .await
}

/// The fixture's own serialized `request`, renumbered `id` and carrying
/// `nonce` in its `_meta`, where a hardened call is signed.
pub(super) fn signed(request: &str, id: u64, nonce: &Value) -> String {
    let mut call: Value = serde_json::from_str(request).expect("the fixture's request parses");
    call["id"] = json!(id);
    call["params"]["_meta"] = json!({ (crate::gateway::meta_mcp::signing::NONCE_META): nonce });
    call.to_string()
}

/// Alpha's `t` through `/mcp`'s `gateway_invoke`, signed.
fn signed_on_mcp(id: u64, nonce: &Value) -> String {
    signed(&meta_invoke("alpha", "t", &json!({})), id, nonce)
}

/// Alpha's `t` on its own route, signed.
fn signed_direct(id: u64, nonce: &Value) -> String {
    signed(&tools_call("t"), id, nonce)
}

/// The invocation records, oldest first; none at all fails with `answer`.
fn records_after(fx: &Fixture, answer: &Value) -> Vec<Value> {
    let all = invocations(fx);
    assert!(!all.is_empty(), "no invocation record; answer {answer}");
    all
}

/// The assertions every recorded signing refusal on `/mcp` shares: the
/// target as the request names it, the meta route, a fresh decision.
fn assert_meta_refusal(record: &Value, outcome: &str, code: i64, kind: &str) {
    assert_eq!(record["route"], "meta", "{record}");
    assert_eq!(record["server"], "alpha", "{record}");
    assert_eq!(record["tool"], "t", "{record}");
    assert_eq!(record["outcome"], outcome, "{record}");
    assert_eq!(record["error_code"], code, "{record}");
    assert_eq!(record["decision"]["kind"], kind, "{record}");
    assert_eq!(record["decision"]["decided"], "fresh", "{record}");
    assert!(record["decision"].get("rule_id").is_none(), "{record}");
}

/// T1: the same nonce twice on `/mcp`. The first call is delivered and
/// recorded; the second is refused as a replay, answered as before, and
/// leaves its own record naming `replay_guard`.
#[tokio::test]
async fn t1_mcp_a_replayed_nonce_records_replay_guard() {
    let fx = hardened_signing().await;
    let nonce = json!("t1-nonce");
    let (_, first) = post_to(&fx, "/mcp", &signed_on_mcp(1, &nonce), &Caller::Oidc).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    assert_eq!(
        invocations(&fx).len(),
        1,
        "premise: the first call's record"
    );
    let (status, second) = post_to(&fx, "/mcp", &signed_on_mcp(2, &nonce), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{second}");
    assert_eq!(second["error"]["code"], -32001, "{second}");
    assert_eq!(
        second["error"]["message"], "Nonce replay detected",
        "{second}"
    );
    let all = records_after(&fx, &second);
    assert_eq!(all.len(), 2, "one record for each call: {all:?}");
    assert_meta_refusal(&all[1], "denied", -32001, "replay_guard");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the replay never sent");
}

/// T6: the same nonce twice on the direct route: the refused replay's
/// record names `replay_guard`.
#[tokio::test]
async fn t6_direct_a_replayed_nonce_records_replay_guard() {
    let fx = hardened_signing().await;
    let nonce = json!("t6-nonce");
    let (_, first) = post(&fx, "alpha", &signed_direct(1, &nonce), &Caller::Oidc).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let (status, second) = post(&fx, "alpha", &signed_direct(2, &nonce), &Caller::Oidc).await;
    assert_eq!(second["error"]["code"], -32001, "{status} {second}");
    assert_eq!(
        second["error"]["message"], "Nonce replay detected",
        "{second}"
    );
    let all = records_after(&fx, &second);
    assert_eq!(all.len(), 2, "one record for each call: {all:?}");
    let replay = &all[1];
    assert_eq!(replay["route"], "direct", "{replay}");
    assert_eq!(replay["error_code"], -32001, "{replay}");
    assert_eq!(replay["decision"]["kind"], "replay_guard", "{replay}");
}

/// S1: a nonce longer than the store accepts is the request's shape: one
/// `invalid` record naming `syntax`, answered as before.
#[tokio::test]
async fn s1_mcp_an_over_long_nonce_records_syntax() {
    let fx = hardened_signing().await;
    let nonce = json!("n".repeat(257));
    let (status, body) = post_to(&fx, "/mcp", &signed_on_mcp(1, &nonce), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["message"], "Invalid signing nonce", "{body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "invalid", -32602, "syntax");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}

/// S5: a nonce that is not a string is refused before the store sees it;
/// it notes `syntax` too, and leaves one record.
#[tokio::test]
async fn s5_mcp_a_number_nonce_records_syntax() {
    let fx = hardened_signing().await;
    let (status, body) = post_to(&fx, "/mcp", &signed_on_mcp(1, &json!(5)), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["message"], "Invalid signing nonce", "{body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "invalid", -32602, "syntax");
}

/// P1: under the invoke-only scope, the route stage passes alpha but the
/// signing check's invocation policy refuses it: the operator killed alpha,
/// which the route stage never reads (signing.rs `prepare_signing_invocation`
/// runs the visible policy first). The kill switch names no rule, so the
/// record carries the policy's own kind and no rule id.
#[tokio::test]
async fn p1_mcp_a_signing_time_policy_refusal_records_its_own_kind() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing],
        ..Setup::default()
    })
    .await;
    fx.state.meta_mcp.kill_switch().kill("alpha");
    let request = signed_on_mcp(1, &json!("p1-nonce"));
    let (status, body) = post_to(&fx, "/mcp", &request, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32000, "{body}");
    assert_eq!(
        body["error"]["message"], "Server 'alpha' is currently disabled by operator kill switch",
        "{body}"
    );
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "error", -32000, "kill_switch");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}
