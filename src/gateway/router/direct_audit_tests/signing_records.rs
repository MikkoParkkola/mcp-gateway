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
/// (`hardened_identity.rs`), so the rows call as [`Caller::ModernOidc`].
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
    // Modern era: hardened serves a legacy call only inside a session an
    // elicitation-declaring initialize opened (hardened_elicitation.rs).
    call["params"]["_meta"] = json!({
        (crate::gateway::meta_mcp::signing::NONCE_META): nonce,
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "SigningRecords", "version": "1.0.0"}
    });
    call.to_string()
}

/// [`signed`] with its `_meta` nonce taken out again: the era fields stay,
/// so the call differs from a signed one only by the missing nonce.
fn unsigned(request: &str, id: u64) -> Value {
    let mut call: Value =
        serde_json::from_str(&signed(request, id, &Value::Null)).expect("the call parses");
    if let Some(meta) = call["params"]["_meta"].as_object_mut() {
        meta.remove(crate::gateway::meta_mcp::signing::NONCE_META);
    }
    call
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
    let (_, first) = post_to(&fx, "/mcp", &signed_on_mcp(1, &nonce), &Caller::ModernOidc).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    assert_eq!(
        invocations(&fx).len(),
        1,
        "premise: the first call's record"
    );
    let (status, second) =
        post_to(&fx, "/mcp", &signed_on_mcp(2, &nonce), &Caller::ModernOidc).await;
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
    let (_, first) = post(&fx, "alpha", &signed_direct(1, &nonce), &Caller::ModernOidc).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let (status, second) = post(&fx, "alpha", &signed_direct(2, &nonce), &Caller::ModernOidc).await;
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
    let (status, body) = post_to(&fx, "/mcp", &signed_on_mcp(1, &nonce), &Caller::ModernOidc).await;
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
    let (status, body) = post_to(
        &fx,
        "/mcp",
        &signed_on_mcp(1, &json!(5)),
        &Caller::ModernOidc,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["message"], "Invalid signing nonce", "{body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "invalid", -32602, "syntax");
}

/// S3: S4 on `/mcp`. Signing required and a meta tool called by name with
/// no nonce: refused as the request's shape with the missing nonce's code,
/// and recorded under the name as called, with no server.
#[tokio::test]
async fn s3_mcp_a_missing_required_nonce_records_syntax() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing, Extra::Hardened, Extra::NonceRequired],
        ..Setup::default()
    })
    .await;
    let by_name = json!({"jsonrpc": "2.0", "method": "tools/call",
                         "params": {"name": "gateway_list_servers", "arguments": {}}});
    let call = unsigned(&by_name.to_string(), 4);
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(
        (status, body["error"]["code"].as_i64()),
        (StatusCode::BAD_REQUEST, Some(-32001)),
        "{body}"
    );
    let all = records_after(&fx, &body);
    let [only] = all.as_slice() else {
        panic!("one record expected: {all:?}");
    };
    let target = (
        only["route"].as_str(),
        only["server"].as_str().unwrap_or_default(),
        only["tool"].as_str(),
    );
    assert_eq!(
        target,
        (Some("meta"), "", Some("gateway_list_servers")),
        "{only}"
    );
    let decided = (
        only["outcome"].as_str(),
        only["error_code"].as_i64(),
        only["decision"]["kind"].as_str(),
    );
    assert_eq!(
        decided,
        (Some("denied"), Some(-32001), Some("syntax")),
        "{only}"
    );
}

/// S5i: S5 under the invoke-only scope, where no early site runs and only
/// the argument nonce counts. A number there reaches the signing check,
/// which notes `syntax` itself; the record carries that noted kind.
#[tokio::test]
async fn s5i_mcp_a_late_malformed_argument_nonce_records_syntax() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing],
        ..Setup::default()
    })
    .await;
    let mut call = unsigned(&meta_invoke("alpha", "t", &json!({})), 9);
    call["params"]["arguments"]["nonce"] = json!(42);
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(
        (status, body["error"]["code"].as_i64()),
        (StatusCode::BAD_REQUEST, Some(-32602)),
        "{body}"
    );
    let all = records_after(&fx, &body);
    let [only] = all.as_slice() else {
        panic!("one record expected: {all:?}");
    };
    assert_meta_refusal(only, "invalid", -32602, "syntax");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}

/// P1: under the invoke-only scope, the route stage passes alpha but the
/// signing check's invocation policy refuses it: the operator killed alpha,
/// which the route stage never reads (signing.rs `prepare_signing_invocation`
/// runs the visible policy first). A refusal the gateway noted records
/// `denied` with its own code, at signing time as at dispatch (one rule, the
/// meta writer's). The kill switch names no rule, so the record carries the
/// policy's own kind and no rule id.
#[tokio::test]
async fn p1_mcp_a_signing_time_policy_refusal_records_its_own_kind() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing],
        ..Setup::default()
    })
    .await;
    fx.state.meta_mcp.kill_switch().kill("alpha");
    let request = signed_on_mcp(1, &json!("p1-nonce"));
    let (status, body) = post_to(&fx, "/mcp", &request, &Caller::ModernOidc).await;
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
    assert_meta_refusal(record, "denied", -32000, "kill_switch");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}

/// S6m: S6 on `/mcp`. Under the every-call scope a `gateway_invoke` carrying
/// both an argument nonce and a `_meta` nonce is refused early, at intake,
/// for its shape: one `invalid` record naming `syntax`, answered as before.
#[tokio::test]
async fn s6m_mcp_two_nonces_record_syntax() {
    let fx = hardened_signing().await;
    let mut call: Value =
        serde_json::from_str(&signed_on_mcp(1, &json!("s6m-meta"))).expect("the request parses");
    call["params"]["arguments"]["nonce"] = json!("s6m-argument");
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["message"], "two signing nonces", "{body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "invalid", -32602, "syntax");
}

/// N2a: a request with no id at all reaches the early nonce refusal
/// (restore has no id to check, and `/mcp` asks for one only later, in
/// `parse_request_ref`): answered with no id and the nonce's own words, as
/// before, and recorded once.
#[tokio::test]
async fn n2a_mcp_an_id_less_early_refusal_is_recorded() {
    let fx = hardened_signing().await;
    let mut call: Value =
        serde_json::from_str(&signed_on_mcp(1, &json!(5))).expect("the request parses");
    call.as_object_mut().expect("an object").remove("id");
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(
        body["error"]["message"], "Invalid signing nonce",
        "premise: {body}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert!(body["id"].is_null(), "no id: {body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "invalid", -32602, "syntax");
}

/// N2b, a guard: an id of the wrong type never reaches the nonce check.
/// The signing envelope refuses it first, as before (restore, "Invalid
/// signing request ID"), so this row pins that answer and nothing about a
/// nonce record.
#[tokio::test]
async fn n2b_mcp_a_wrong_type_id_is_refused_by_the_envelope_first() {
    let fx = hardened_signing().await;
    let mut call: Value =
        serde_json::from_str(&signed_on_mcp(1, &json!(5))).expect("the request parses");
    call["id"] = json!(true);
    let (_, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(
        body["error"]["message"], "Invalid signing request ID",
        "{body}"
    );
    assert!(body["id"].is_null(), "no id: {body}");
}

/// [`signed_on_mcp`] parsed, for a row that changes the request before it
/// is sent.
fn signed_on_mcp_value(id: u64, nonce: &Value) -> Value {
    serde_json::from_str(&signed_on_mcp(id, nonce)).expect("the request parses")
}

/// E1: N2b's request, an id the signing envelope cannot carry,
/// is answered exactly as N2b pins, and the refusal now leaves one record:
/// the request's form (`syntax`), the target as the request names it.
#[tokio::test]
async fn e1_mcp_an_unusable_id_is_recorded_as_syntax() {
    let fx = hardened_signing().await;
    let mut call = signed_on_mcp_value(1, &json!(5));
    call["id"] = json!(true);
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(
        body["error"]["message"], "Invalid signing request ID",
        "{body}"
    );
    assert!(body["id"].is_null(), "no id: {body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "denied", -32600, "syntax");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}

/// E2: a name that becomes `gateway_invoke` only once the
/// sanitizer strips a control character (the BEL that
/// `mik8154_rows_tests::signed_order::s6_a_routing_alias_made_by_sanitization_is_refused`
/// uses) changes the request's origin. The answer has no id although the
/// request's id (1) was usable, as before, and the refusal is recorded once.
#[tokio::test]
async fn e2_mcp_a_changed_origin_is_recorded_as_syntax() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing, Extra::Hardened],
        sanitize: Sanitize::On,
        ..Setup::default()
    })
    .await;
    let mut call = signed_on_mcp_value(1, &json!("e2-nonce"));
    call["params"]["name"] = json!("gateway_\u{7}invoke");
    let (status, body) = post_to_named(
        &fx,
        "/mcp",
        &call.to_string(),
        &Caller::ModernOidc,
        "gateway_invoke",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(
        body["error"]["message"], "Invalid signing request origin",
        "{body}"
    );
    assert!(body["id"].is_null(), "no id although 1 was usable: {body}");
    let all = records_after(&fx, &body);
    let [record] = all.as_slice() else {
        panic!("exactly one record: {all:?}");
    };
    assert_meta_refusal(record, "denied", -32600, "syntax");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never sent");
}

/// E4: E1's request under a log that fails closed and
/// cannot be written (as `signing_records_log`'s F1n makes it): the
/// envelope refusal follows the signing refusal's policy, so the answer is
/// the log's unavailability, 503, with no id and no record.
#[tokio::test]
async fn e4_a_fail_closed_log_that_cannot_write_answers_unavailable() {
    let fx = fixture(Setup {
        extras: &[Extra::Signing, Extra::Hardened],
        log: Log::On,
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.set_append_failure_for_test(true);
    let mut call = signed_on_mcp_value(1, &json!(5));
    call["id"] = json!(true);
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::ModernOidc).await;
    assert_eq!(
        (status, body["error"]["code"].as_i64(), body["id"].is_null()),
        (StatusCode::SERVICE_UNAVAILABLE, Some(-32005), true),
        "{body}"
    );
    assert!(invocations(&fx).is_empty(), "no record: {body}");
}
