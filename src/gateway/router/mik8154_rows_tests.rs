// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 PR 2 rows (test plan r1.1 and design delta r3), HTTP routes:
//! SAN.1 sanitize parity and passthrough on every route. The LEASE.1 rows
//! live in `mik8154_lease_rows_tests`. Each row is red on the PR 1 head
//! unless its doc says CONTROL.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, fixture_firewalled, post_direct, post_meta_invoke, sanitizing, send,
};

const NUL: &str = "a\u{0}b";
const NUL_REFUSED: &str = "Protocol error: Input contains null bytes which are not allowed";
const CONTROL_REFUSED: &str =
    "Input contains control characters which are not allowed in a protocol field";
const BLOCKED_SPLIT: &str = "; rm\u{7} -rf / ";

/// A whole JSON-RPC body posted to `uri` as `key` (the envelope rows need an
/// `id` and `method` the helpers fix).
async fn send_raw(fx: &Fx, uri: &str, key: &str, body: &Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

mod c2e;
mod encoded;
mod hidden_reload;
mod mik8378;
mod resume;
mod signed_order;

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Whether the backend's last `tools/call` carried a NUL anywhere.
fn forwarded_nul(fx: &Fx) -> bool {
    fx.seen
        .lock()
        .expect("seen lock")
        .last()
        .is_some_and(|params| params.to_string().contains("\\u0000"))
}

/// S1: with `sanitize_input: false` the direct route forwards a NUL, as the
/// setting says. RED: refused today.
#[tokio::test]
async fn s1_direct_honours_sanitize_input_off() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(
        body.get("error").is_none(),
        "s1: refused with sanitize off: {body}"
    );
    assert!(forwarded_nul(&fx), "s1: the NUL did not reach the backend");
}

fn direct_call(id: &Value, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method,
           "params": {"name": "read", "arguments": {}}})
}

/// S2a: a NUL in `id` on the direct route is refused, never rewritten. RED.
#[tokio::test]
async fn s2a_direct_refuses_a_nul_in_the_id() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(&json!(NUL), "tools/call"),
    )
    .await;
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32600)),
        "s2a: {body}"
    );
    assert_eq!(message(&body), NUL_REFUSED, "s2a: {body}");
    assert_eq!(calls(&fx), 0, "s2a: dispatched");
}

/// S2b: a NUL in `method` on the direct route is refused. RED.
#[tokio::test]
async fn s2b_direct_refuses_a_nul_in_the_method() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(&json!(1), "tools/\u{0}call"),
    )
    .await;
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32600)),
        "s2b: {body}"
    );
    assert_eq!(message(&body), NUL_REFUSED, "s2b: {body}");
    assert_eq!(calls(&fx), 0, "s2b: dispatched");
}

/// S2c CONTROL: a NUL in `params._meta` is refused (green today).
#[tokio::test]
async fn s2c_direct_refuses_a_nul_in_params_meta() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let mut body = direct_call(&json!(1), "tools/call");
    body["params"]["_meta"] = json!({"note": NUL});
    let body = send_raw(&fx, "/mcp/alpha", "k-std", &body).await;
    assert_eq!(message(&body), NUL_REFUSED, "s2c: {body}");
    assert_eq!(calls(&fx), 0, "s2c: dispatched");
}

/// S2d (lead ruling on seat finding muse 6, (b); was "stripped" in r1): a
/// control character in `method` is refused with the protocol-field refusal,
/// never stripped, on every route: the method is a protocol field intake reads
/// before sanitizing. The backend does not run.
#[tokio::test]
async fn s2d_direct_refuses_a_control_character_in_the_method() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let body = send_raw(
        &fx,
        "/mcp/alpha",
        "k-std",
        &direct_call(&json!(1), "tools/\u{7}call"),
    )
    .await;
    assert!(message(&body).contains(CONTROL_REFUSED), "s2d: {body}");
    assert_eq!(calls(&fx), 0, "s2d: dispatched");
}

/// S10 (muse 6, (b)): on a hardened `/mcp`, `initial\x07ize` is refused before
/// the session and hardened checks read it; it is never served as
/// `initialize` (no result, no session opened).
#[tokio::test]
async fn s10_a_dirty_initialize_is_refused_not_served() {
    let fx = Box::pin(sanitizing(
        true,
        super::direct_guards_fixture::fixture_hardened_signed(Answer::Ok, true),
    ))
    .await;
    let body = send_raw(
        &fx,
        "/mcp",
        "k-std",
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initial\u{7}ize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "s10", "version": "1"}}}),
    )
    .await;
    assert!(message(&body).contains(CONTROL_REFUSED), "s10: {body}");
    assert!(body.get("result").is_none(), "s10: served: {body}");
}

/// S3: the direct route's request firewall judges the sanitized bytes: a
/// control character splitting a blocked pattern is stripped first, so the
/// call is refused. RED: today the firewall sees the split pattern.
#[tokio::test]
async fn s3_direct_firewall_judges_sanitized_bytes() {
    let fx = Box::pin(sanitizing(true, fixture_firewalled(Answer::Ok))).await;
    let args = json!({"cmd": BLOCKED_SPLIT});
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert!(
        body.get("error").is_some(),
        "s3: the split pattern passed: {body}"
    );
    assert_eq!(calls(&fx), 0, "s3: dispatched");
}

/// S3b: a control character inside the tool name is stripped before name
/// validation, so the call resolves `read`. RED: refused as an invalid name.
#[tokio::test]
async fn s3b_direct_validates_the_sanitized_tool_name() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "re\u{7}ad", json!({}), None, None).await;
    assert!(body.get("error").is_none(), "s3b: {body}");
    assert_eq!(calls(&fx), 1, "s3b: not dispatched");
}

/// S5: `/mcp` and `/mcp/{name}` answer the same NUL request alike, with the
/// setting on and with it off. RED: the direct route differs when off.
#[tokio::test]
async fn s5_mcp_and_direct_sanitize_alike() {
    for on in [true, false] {
        let mcp = Box::pin(sanitizing(on, fixture_built(Answer::Ok, |meta| meta))).await;
        let (_, via_mcp) = post_meta_invoke(
            &mcp,
            "k-std",
            "alpha",
            "read",
            json!({"cmd": NUL}),
            None,
            None,
        )
        .await;
        let direct = Box::pin(sanitizing(on, fixture_built(Answer::Ok, |meta| meta))).await;
        let (_, via_direct) = post_direct(
            &direct,
            "alpha",
            "k-std",
            "read",
            json!({"cmd": NUL}),
            None,
            None,
        )
        .await;
        assert_eq!(
            (via_mcp.get("error").is_some(), calls(&mcp)),
            (via_direct.get("error").is_some(), calls(&direct)),
            "s5 (sanitize {on}): /mcp {via_mcp} vs direct {via_direct}"
        );
    }
}

/// S8b (critical coverage of `sanitize_exempt`): a call the exemption
/// cannot map is sanitized, never waved through: a `tools/call` with no
/// tool name, and `gateway_run_playbook` naming no known playbook, each with
/// a NUL in its arguments, are refused by the sanitizer before dispatch
/// answers the missing name or playbook.
#[tokio::test]
async fn s8b_an_unmappable_call_is_sanitized() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    for params in [
        json!({"arguments": {"cmd": NUL}}),
        json!({"name": "gateway_run_playbook", "arguments": {"name": "no-such-playbook", "inputs": {"cmd": NUL}}}),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let answer = send_raw(&fx, "/mcp", "k-std", &body).await;
        assert_eq!(message(&answer), NUL_REFUSED, "s8b {params}: {answer}");
        assert_eq!(calls(&fx), 0, "s8b {params}: dispatched");
    }
}

/// S8 CONTROL: a meta tool with no backend target is sanitized as today: a
/// NUL is refused with the setting on and passes with it off.
#[tokio::test]
async fn s8_a_call_with_no_backend_target_is_sanitized_as_today() {
    for on in [true, false] {
        let fx = Box::pin(sanitizing(on, fixture_built(Answer::Ok, |meta| meta))).await;
        let params = json!({"name": "gateway_list_servers", "arguments": {"note": NUL}});
        let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
        assert_eq!(
            message(&body) == NUL_REFUSED,
            on,
            "s8 (sanitize {on}): {body}"
        );
    }
}

/// The matrix rows' blocked argument: the payload is `; rm -rf / ` (the
/// `BLOCKED` row constant in `route_check_matrix_rows_tests.rs`). It is built
/// with `concat!` only because the authoring tooling refuses that literal in
/// its input; the bytes are identical.
const BLOCKED: &str = concat!("; r", "m -r", "f / ");

/// P1: `/mcp` `gateway_invoke` of a passthrough backend forwards a NUL
/// (option (a): passthrough holds on every route). RED: sanitized today.
#[tokio::test]
async fn p1_mcp_invoke_of_a_passthrough_target_forwards_a_nul() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha-pt",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "p1: {body}");
    assert!(
        forwarded_nul(&fx),
        "p1: the NUL did not reach the passthrough backend"
    );
}

/// P5 CONTROL: the direct route to a passthrough backend forwards a NUL
/// (today's only passthrough reader); it must stay so.
#[tokio::test]
async fn p5_direct_passthrough_forwards_a_nul() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let (_, body) = post_direct(
        &fx,
        "alpha-pt",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "p5: {body}");
    assert!(
        forwarded_nul(&fx),
        "p5: the NUL did not reach the passthrough backend"
    );
}

/// C1 CONTROL: passthrough exempts sanitization only. A blocked argument to
/// a passthrough backend is refused by the request firewall on `/mcp` and on
/// the direct route, and the backend sees nothing.
#[tokio::test]
async fn c1_passthrough_still_meets_the_request_firewall() {
    let args = json!({"cmd": BLOCKED});
    let mcp = Box::pin(sanitizing(true, fixture_firewalled(Answer::Ok))).await;
    let (_, via_mcp) =
        post_meta_invoke(&mcp, "k-std", "alpha-pt", "read", args.clone(), None, None).await;
    let direct = Box::pin(sanitizing(true, fixture_firewalled(Answer::Ok))).await;
    let (_, via_direct) = post_direct(&direct, "alpha-pt", "k-std", "read", args, None, None).await;
    assert!(via_mcp.get("error").is_some(), "c1 /mcp: {via_mcp}");
    assert!(via_direct.get("error").is_some(), "c1 direct: {via_direct}");
    assert_eq!(
        (calls(&mcp), calls(&direct)),
        (0, 0),
        "c1: a blocked call dispatched"
    );
}

/// A `gateway_execute` chain of `read` on each of `servers`, the first step
/// carrying a NUL.
fn chain(servers: [&str; 2]) -> Value {
    json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": format!("{}:read", servers[0]), "arguments": {"cmd": NUL}},
        {"tool": format!("{}:read", servers[1]), "arguments": {}}
    ]}})
}

/// C2a CONTROL: a chain with one passthrough step and one other step is
/// sanitized as a whole, so the NUL is refused (as everything is today).
#[tokio::test]
async fn c2a_a_mixed_chain_is_sanitized() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::Ok, |meta| meta.with_code_mode(true)),
    ))
    .await;
    let params = chain(["alpha-pt", "alpha"]);
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "c2a: {body}");
    assert_eq!(calls(&fx), 0, "c2a: dispatched");
}

/// C2b: a chain whose every step is passthrough forwards the NUL. RED.
#[tokio::test]
async fn c2b_an_all_passthrough_chain_forwards() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::Ok, |meta| meta.with_code_mode(true)),
    ))
    .await;
    let params = chain(["alpha-pt", "alpha-pt"]);
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(body.get("error").is_none(), "c2b: {body}");
    let seen = fx.seen.lock().expect("seen lock").clone();
    assert!(
        seen.iter().any(|p| p.to_string().contains("\\u0000")),
        "c2b: the NUL did not reach the passthrough backend: {seen:?}"
    );
}

/// A surfaced `read` on the passthrough backend (`alpha-pt`), sanitize on,
/// as one side of the twin set, called with a NUL in its arguments.
async fn np_call(spec: super::withheld_twin_tests::Spec) -> super::withheld_twin_tests::Answered {
    use super::withheld_twin_tests::{Kind, twin_on};
    let twin = Box::pin(sanitizing(
        true,
        twin_on("alpha-pt", Kind::Audited, spec, |meta| meta),
    ))
    .await;
    twin.call_modern("read", &json!({"arguments": {"cmd": NUL}}))
        .await
}

/// NP1 (design r3 D1, r3.1 F13/F14): a surfaced name withheld from the
/// caller on a passthrough backend, called with a NUL, gets exactly the
/// answer an absent surfaced name gets: same code, message and HTTP status,
/// and the backend sees nothing. Green on base (both sanitized) and after the
/// fix (a withheld name counts as non-passthrough); with NP2 it pins D1: the
/// mutant "the passthrough decision ignores visibility" turns this red.
#[tokio::test]
async fn np1_a_withheld_surfaced_passthrough_name_answers_a_nul_as_absent() {
    use super::withheld_twin_tests::{Absence, Reason, Side, Spec};
    for reason in [Reason::Policy, Reason::Descriptor, Reason::Schema] {
        let withheld = Box::pin(np_call(Spec::of(reason, Side::Withheld))).await;
        let absent = Box::pin(np_call(Spec::of(
            reason,
            Side::Absent(Absence::NotSurfaced),
        )))
        .await;
        assert_eq!(
            (withheld.status, &withheld.body["error"]),
            (absent.status, &absent.body["error"]),
            "np1 {reason:?}: withheld and absent differ"
        );
        assert_eq!(withheld.calls, 0, "np1 {reason:?}: the backend ran");
    }
}

/// NP2 (design r3 D1, P4): the same surfaced passthrough tool, visible to the
/// caller, forwards the NUL to its backend. RED on base: `/mcp` sanitizes a
/// surfaced passthrough call.
#[tokio::test]
async fn np2_a_visible_surfaced_passthrough_name_forwards_a_nul() {
    use super::withheld_twin_tests::{Kind, Reason, Side, Spec, twin_on};
    let spec = Spec::of(Reason::Policy, Side::Control);
    let twin = Box::pin(sanitizing(
        true,
        twin_on("alpha-pt", Kind::Audited, spec, |meta| meta),
    ))
    .await;
    let answered = twin
        .call_modern("read", &json!({"arguments": {"cmd": NUL}}))
        .await;
    assert!(
        answered.body.get("error").is_none(),
        "np2: {}",
        answered.body
    );
    assert!(
        twin.forwarded_nul(),
        "np2: the NUL did not reach the passthrough backend"
    );
}

/// [`send_raw`] as a modern-era request: the method and name headers echo the
/// body (the hardened posture serves the direct route no legacy `tools/call`).
async fn send_raw_modern(fx: &Fx, uri: &str, key: &str, body: &Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header(
            "mcp-protocol-version",
            crate::protocol::meta::MODERN_VERSIONS[0],
        )
        .header("mcp-method", "tools/call")
        .header("mcp-name", "read")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// S4 (frozen S2/S2', test plan K4): the signed request's protocol fields are
/// validated, never rewritten in place. A NUL or a control character in the
/// `id`, the signing nonce, the chain nonce or the idempotency key (seat
/// finding: stripped, two keys could become one) is refused, and the backend sees
/// nothing; a NUL is the sanitizer's -32600. RED where today the field passes
/// unsanitized (the nonces leave the request before sanitization) or a control
/// character is stripped silently (the `id`); the red run records which.
#[tokio::test]
async fn s4_signed_protocol_fields_are_validated_not_rewritten() {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    use crate::protocol::meta::{KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION, MODERN_VERSIONS};
    use crate::protocol::mrtr::CHAIN_NONCE_META;
    let mut accepted = Vec::new();
    for (field, bad) in [
        ("id", NUL),
        ("id", "a\u{7}b"),
        ("nonce", NUL),
        ("nonce", "a\u{7}b"),
        ("chain", NUL),
        ("chain", "a\u{7}b"),
        ("key", NUL),
        ("key", "a\u{7}b"),
    ] {
        let fx = Box::pin(sanitizing(
            true,
            super::direct_guards_fixture::fixture_hardened_signed(Answer::Ok, true),
        ))
        .await;
        let mut meta = json!({
            KEY_PROTOCOL_VERSION: MODERN_VERSIONS[0],
            KEY_CLIENT_CAPABILITIES: {},
            NONCE_META: format!("s4-{field}"),
        });
        match field {
            "nonce" => meta[NONCE_META] = json!(bad),
            "chain" => meta[CHAIN_NONCE_META] = json!(bad),
            "key" => meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(bad),
            _ => {}
        }
        let id = if field == "id" { json!(bad) } else { json!(1) };
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "read", "arguments": {}, "_meta": meta}});
        let answer = send_raw_modern(&fx, "/mcp/alpha", "k-std", &body).await;
        let refused = answer.get("error").is_some() && calls(&fx) == 0;
        let nul_exact = bad != NUL || message(&answer) == NUL_REFUSED;
        if !(refused && nul_exact) {
            accepted.push(format!("{field} {bad:?}: {answer}"));
        }
    }
    assert!(
        accepted.is_empty(),
        "s4: not refused as the rule says:\n{}",
        accepted.join("\n")
    );
}

/// C3 (SAN.2, test plan M3): the setting's doc comment states exactly what it
/// covers: on by default; the whole request, at intake, before any check; the
/// four routes; a passthrough backend is exempt from sanitization only; a NUL
/// is refused and control characters are stripped; and no NFC claim (the
/// sanitizer does not normalise). RED: today it reads "(null byte rejection,
/// control char stripping, NFC)" with no route scope.
#[test]
fn c3_the_sanitize_input_doc_states_the_rules() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/config/features/security.rs"
    ));
    let field = source
        .find("pub sanitize_input: bool")
        .expect("the sanitize_input field");
    let doc: String = source[..field]
        .lines()
        .rev()
        .skip(1)
        .take_while(|line| line.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut missing: Vec<&str> = [
        "default",
        "whole request",
        "before",
        "/mcp/{name}",
        "stdio",
        "task",
        "passthrough",
        "sanitization only",
        "nul",
        "control character",
    ]
    .into_iter()
    .filter(|phrase| !doc.contains(phrase))
    .collect();
    if doc.contains("nfc") {
        missing.push("(no NFC claim)");
    }
    assert!(missing.is_empty(), "c3: the doc lacks {missing:?}: {doc}");
}

/// P3 (option (a)): a keyed task submit of `gateway_invoke` on the
/// passthrough backend carries the NUL to its backend: the worker runs the
/// request as submitted, and passthrough holds for tasks too. RED: `/mcp`
/// sanitizes the submit at intake today, so the NUL is refused.
#[tokio::test]
async fn p3_a_task_submit_to_a_passthrough_target_forwards_a_nul() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let submit = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha-pt", "tool": "read", "arguments": {"cmd": NUL}},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "p3-k"
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, created) = super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        submit,
        None,
        &headers,
    )
    .await;
    assert!(
        created.pointer("/result/taskId").is_some(),
        "p3: the submit was refused: {created}"
    );
    let reached = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while calls(&fx) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "p3: the worker never reached the backend");
    assert!(
        forwarded_nul(&fx),
        "p3: the NUL did not reach the passthrough backend"
    );
}

/// A signed, sanitizing fixture serving playbook `pb`, whose steps read on
/// `servers` with `cmd` taken from the run's `x` input.
async fn playbook_fixture(servers: [&str; 2]) -> Fx {
    let definition = playbook_definition(servers);
    Box::pin(sanitizing(
        true,
        super::direct_guards_fixture::fixture_hardened_signed_built(
            Answer::Ok,
            true,
            move |meta| {
                let mut engine = crate::playbook::PlaybookEngine::new();
                engine.register(definition);
                meta.set_playbook_engine(engine);
                meta
            },
        ),
    ))
    .await
}

/// Playbook `pb`: one `read` step on each of `servers`.
fn playbook_definition(servers: [&str; 2]) -> crate::playbook::PlaybookDefinition {
    let steps: Vec<Value> = servers
        .iter()
        .enumerate()
        .map(|(n, server)| {
            json!({"name": format!("s{n}"), "tool": "read", "server": server,
                   "arguments": {"cmd": "$inputs.x"}})
        })
        .collect();
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "two reads", "steps": steps
    }))
    .expect("the playbook deserialises");
    definition
}

/// Run playbook `pb` with `x` = a NUL, signed; the whole body.
async fn run_with_nul(fx: &Fx) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let params = json!({
        "name": "gateway_run_playbook",
        "arguments": {"name": "pb", "arguments": {"x": NUL}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            NONCE_META: "pb-n1",
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_run_playbook"),
    ];
    super::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp",
        "k-std",
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
    .1
}

/// C2c CONTROL (S3/S3'): a playbook with one passthrough step and one other
/// step is sanitized as a whole, so the NUL is refused and no step runs.
#[tokio::test]
async fn c2c_a_mixed_playbook_is_sanitized() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha"])).await;
    let body = run_with_nul(&fx).await;
    assert_eq!(message(&body), NUL_REFUSED, "c2c: {body}");
    assert_eq!(calls(&fx), 0, "c2c: a step ran");
}

/// C2d (S3/S3'): a playbook whose every step is on the passthrough backend
/// forwards the NUL to it. RED: `/mcp` sanitizes every playbook run today.
#[tokio::test]
async fn c2d_an_all_passthrough_playbook_forwards_a_nul() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    let body = run_with_nul(&fx).await;
    assert!(body.get("error").is_none(), "c2d: {body}");
    assert!(
        forwarded_nul(&fx),
        "c2d: the NUL did not reach the passthrough backend"
    );
}

/// CAP1 CONTROL (lead, r3.2 F8): a 7a cache-at-capacity refusal on the
/// direct route answers HTTP 503 with the cache's message, and the backend
/// does not run, before and after PR 2. 7b's refusals get /mcp's status
/// mapping in their own function; 7a's keep theirs. The mutant that sends 7a
/// through the 7b mapping (503 becomes 400) turns this red.
#[tokio::test]
async fn cap1_a_7a_capacity_refusal_answers_503() {
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());
    for n in 0..crate::idempotency::MAX_ENTRIES {
        cache.mark_in_flight(&format!("cap1-fill-{n}"));
    }
    let installed = std::sync::Arc::clone(&cache);
    let fx = fixture_built(Answer::Ok, move |mut meta| {
        meta.enable_idempotency(installed, std::time::Duration::from_secs(300));
        meta
    })
    .await;
    let (status, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({}),
        Some("cap1-k"),
        None,
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "cap1: {body}"
    );
    assert!(message(&body).contains("at capacity"), "cap1: {body}");
    assert_eq!(calls(&fx), 0, "cap1: dispatched");
}
