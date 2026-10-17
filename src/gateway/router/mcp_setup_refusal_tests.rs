// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3d-2 (NONCEFX.11, meta-tool setup on `/mcp`): a signed
//! meta-tool call refused while its arguments are parsed, before it collects
//! or sends anything, asks for its nonce back. REFUND rows use the four-send
//! oracle: sends 1 and 2 under one nonce both meet the parse refusal; send 3
//! with valid arguments is served; send 4 is a replay. The KEEP rows for these
//! kinds are in `meta_mcp/signing_refusal_kind_tests.rs`. The K5 pair (a
//! surfaced name withheld for its schema) closes the file.

use serde_json::{Value, json};

use super::super::direct_continuation_tests::dispatched;
use super::super::direct_guards_fixture::{
    Answer, Fx, fixture_hardened_signed, fixture_hardened_signed_built,
};

/// A signed `tools/call` of `name` on `/mcp` as `k-std` under `nonce` (in
/// `_meta`, as hardened signing reads it), carrying `alice`'s identity.
async fn call(fx: &Fx, name: &str, arguments: Value, nonce: &str) -> Value {
    let params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
            (crate::gateway::meta_mcp::signing::NONCE_META): nonce,
        },
    });
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .expect("request");
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: "alice".to_string(),
            email: "alice@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .expect("response");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json")
}

/// Whether `body` is a refusal whose text contains `needle`.
fn refused_with(body: &Value, needle: &str) -> bool {
    let refused = body.get("error").is_some() || body["result"]["isError"] == true;
    refused && body.to_string().contains(needle)
}

/// The accepted-once oracle for `name` on `fx`: `bad` is refused with
/// `needle` at sends 1 and 2 under one nonce (send 2 is not a replay: the
/// nonce came back) with nothing sent, `good` is served at send 3, and send 4
/// is a replay.
async fn assert_given_back(
    fx: &Fx,
    name: &str,
    (bad, good): (Value, Value),
    (needle, nonce): (&str, &str),
) {
    assert_given_back_to(fx, name, bad, (name, good), (needle, nonce)).await;
}

/// [`assert_given_back`] whose sends 3 and 4 are `good`'s call instead.
async fn assert_given_back_to(
    fx: &Fx,
    name: &str,
    bad: Value,
    (good_name, good): (&str, Value),
    (needle, nonce): (&str, &str),
) {
    let before = dispatched(fx);
    for send in 1..=2 {
        let refused = call(fx, name, bad.clone(), nonce).await;
        assert!(
            refused_with(&refused, needle),
            "{name} send {send}: the parse refusal (at send 2: the nonce was kept): {refused}"
        );
    }
    assert_eq!(dispatched(fx), before, "{name}: premise: nothing was sent");
    let third = call(fx, good_name, good.clone(), nonce).await;
    assert!(
        third.get("error").is_none() && third["result"]["isError"] != true,
        "{name}: send 3 was refused: {third}"
    );
    let fourth = call(fx, good_name, good, nonce).await;
    assert_eq!(
        fourth["error"]["message"], "Nonce replay detected",
        "{name}: the nonce was given back twice: {fourth}"
    );
}

/// K8-R search: `gateway_search` refuses a call with no `query` and one with
/// an unknown `detail` level before it collects anything. Red on base at send
/// 2. Mutant mK8-search: the asks at the two parses removed.
#[tokio::test]
async fn a_search_parse_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let good = json!({"query": "read"});
    let cases = [
        (json!({}), "Missing 'query' parameter", "k8s-n1"),
        (json!({"query": "read", "detail": "l9"}), "l9", "k8s-n2"),
    ];
    for (bad, needle, nonce) in cases {
        let pair = (bad, good.clone());
        assert_given_back(&fx, "gateway_search", pair, (needle, nonce)).await;
    }
}

/// K8-R search_tools: `gateway_search_tools` refuses a call with no `query`.
/// Red on base at send 2. Mutant mK8-tools.
#[tokio::test]
async fn a_search_tools_parse_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let pair = (json!({}), json!({"query": "read"}));
    let refused = ("Missing 'query'", "k8t-n1");
    assert_given_back(&fx, "gateway_search_tools", pair, refused).await;
}

/// K8-R list_tools: `gateway_list_tools` refuses an unknown role filter
/// before it lists anything. Red on base at send 2. Mutant mK8-role.
#[tokio::test]
async fn a_list_tools_role_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let pair = (json!({"role": "bogus"}), json!({}));
    let refused = ("Invalid role filter", "k8l-n1");
    assert_given_back(&fx, "gateway_list_tools", pair, refused).await;
}

/// K8-R empty chain: an unkeyed `gateway_execute` with an empty chain is
/// refused by `execute_chain` (admission checks the chain only for a keyed
/// call). Red on base at send 2. Mutant mK8-chain.
#[tokio::test]
async fn an_empty_chain_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let good = json!({"chain": [{"tool": "alpha:read", "arguments": {}}]});
    let pair = (json!({"chain": []}), good);
    let refused = ("Chain must not be empty", "k8c-n1");
    assert_given_back(&fx, "gateway_execute", pair, refused).await;
    assert_eq!(dispatched(&fx), 1, "send 3 reached the backend once");
}

const ONE_STEP: &str = r"
name: one
description: one step
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
";

/// K8-R playbook setup: an unkeyed `gateway_run_playbook` naming no known
/// playbook is refused before any step runs (admission looks the name up only
/// for a keyed call). Red on base at send 2. Mutant mK8-playbook.
#[tokio::test]
async fn a_playbook_setup_refusal_gives_the_nonce_back() {
    let definition = serde_yaml::from_str(ONE_STEP).expect("the playbook parses");
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        meta
    })
    .await;
    let pair = (json!({"name": "nosuch"}), json!({"name": "one"}));
    let refused = ("Playbook not found", "k8p-n1");
    assert_given_back(&fx, "gateway_run_playbook", pair, refused).await;
    assert_eq!(dispatched(&fx), 1, "send 3 ran the playbook's one step");
}

/// K8-R single-tool execute: `gateway_execute` refuses a call with no `tool`,
/// a tool reference with no server prefix and non-object arguments before it
/// invokes anything. Red on base at send 2. Mutant mK8-exec.
#[tokio::test]
async fn an_execute_parse_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.get_tools().await.expect("alpha lists"); // a cold target fills
    let good = json!({"tool": "alpha:read", "arguments": {}});
    let cases = [
        (json!({}), "Missing 'tool'", "k8e-n1"),
        (json!({"tool": "read"}), "missing server prefix", "k8e-n2"),
        (
            json!({"tool": "alpha:read", "arguments": 5}),
            "Invalid 'arguments'",
            "k8e-n3",
        ),
    ];
    for (bad, needle, nonce) in cases {
        let pair = (bad, good.clone());
        assert_given_back(&fx, "gateway_execute", pair, (needle, nonce)).await;
    }
}

/// The hardened fixture with plan attestation enforced.
async fn attested() -> Fx {
    use crate::attestation::{AttestationMode, AttestationValidator, BnautAttestationSigner};
    fixture_hardened_signed_built(Answer::Ok, true, |meta| {
        let signer = BnautAttestationSigner::new(b"plan-key".to_vec(), "plan");
        let validator = AttestationValidator::new(signer.with_audience("test-gateway"));
        meta.with_attestation(std::sync::Arc::new(validator), AttestationMode::Enforce)
    })
    .await
}

/// K8-R unattested plan: under enforced attestation an unkeyed plan is
/// refused before any step (admission refuses only a keyed one). The nonce
/// comes back; sends 3 and 4 are a `gateway_search` under it. Red on base at
/// send 2. Mutant mK8-attest.
#[tokio::test]
async fn an_unattested_plan_refusal_gives_the_nonce_back() {
    let fx = attested().await;
    // Warm: a cold step target is filled at the route stage, which keeps the
    // nonce spent (an effect, not this row's premise).
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.get_tools().await.expect("alpha lists");
    let search = ("gateway_search", json!({"query": "read"}));
    let plans = [
        ("gateway_execute", json!({"tool": "alpha:read"}), "k8a-n1"),
        ("gateway_run_playbook", json!({"name": "any"}), "k8a-n2"),
    ];
    for (name, bad, nonce) in plans {
        let refused = ("multi-step plans carry no attestation", nonce);
        assert_given_back_to(&fx, name, bad, search.clone(), refused).await;
    }
    assert_eq!(dispatched(&fx), 0, "nothing was sent");
}

/// The hardened fixture surfacing `alpha:read`, whose `tools/list` gives it a
/// structurally invalid input schema.
async fn surfacing_invalid_read() -> Fx {
    fixture_hardened_signed_built(Answer::InvalidRead, true, |meta| {
        meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "read".to_string(),
        }])
    })
    .await
}

/// K5-R (`/mcp`): with alpha's catalogue warm, the surfaced `read` is
/// withheld for its schema and answered as a name that matches no tool
/// (`call_dispatch.rs` `_ =>` arm), before anything acted. The nonce comes
/// back; sends 3 and 4 are a `gateway_search` under it. Green on base (the
/// arm already asks). Mutant mK5-ask: that ask removed.
#[tokio::test]
async fn a_withheld_surfaced_name_gives_the_nonce_back() {
    let fx = surfacing_invalid_read().await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.get_tools().await.expect("alpha lists");
    let fills = alpha.list_fills();
    let search = ("gateway_search", json!({"query": "read"}));
    let refused = ("Unknown tool", "k5-n1");
    assert_given_back_to(&fx, "read", json!({}), search, refused).await;
    assert_eq!(alpha.list_fills(), fills, "premise: no fill");
    assert_eq!(dispatched(&fx), 0, "nothing was sent");
}

/// K5-K (`/mcp`): the same name on a cold catalogue. A cold cache is no
/// verdict, so nothing withholds the name before dispatch; dispatch lists
/// alpha, which drops the witness, then refuses it. The nonce stays spent.
/// Green on base. (The `_ =>` arm's own unconditional give-back, mK5-uncond,
/// is killed by the dispatcher row in `meta_mcp/signing_refusal_kind_tests.rs`:
/// on a shared backend no may-effect step precedes that arm.)
#[tokio::test]
async fn a_withheld_surfaced_name_after_a_cold_fill_keeps_the_nonce() {
    let fx = surfacing_invalid_read().await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let first = call(&fx, "read", json!({}), "k5k-n1").await;
    assert!(
        first.get("error").is_some() || first["result"]["isError"] == true,
        "premise: refused: {first}"
    );
    assert!(alpha.list_fills() > 0, "premise: the call filled: {first}");
    let again = call(&fx, "gateway_search", json!({"query": "read"}), "k5k-n1").await;
    assert_eq!(
        again["error"]["message"], "Nonce replay detected",
        "the nonce was given back after a fill: {again} (first: {first})"
    );
    assert_eq!(dispatched(&fx), 0, "nothing was sent");
}

/// Disable `(server, read)` by its error rate, as enough failures do, at the
/// playbook step seam: after admission, before the next step meets its
/// dispatch-time policy (the gate does not read it, the policy does).
fn disable_before_step(fx: &Fx, server: &'static str) {
    let state = std::sync::Arc::clone(&fx.state);
    crate::gateway::meta_mcp::withheld_gate::seams::before_step(move || {
        let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
        let switch = state.meta_mcp.kill_switch();
        for _ in 0..cfg.min_samples.max(1) {
            switch.record_capability_failure(server, "read", &cfg);
        }
        assert!(
            switch.is_capability_disabled(server, "read"),
            "premise: disabled"
        );
    });
}

fn revive(fx: &Fx, server: &str) {
    fx.state
        .meta_mcp
        .kill_switch()
        .revive_capability(server, "read");
}

const TWO_STEPS: &str = r"
name: two
description: two steps
on_error: abort
steps:
  - name: first
    server: alpha
    tool: read
  - name: second
    server: alpha-pt
    tool: read
";

/// The hardened fixture with the `one` and `two` playbooks, both backends warm.
async fn with_playbooks() -> Fx {
    let one = serde_yaml::from_str(ONE_STEP).expect("one parses");
    let two = serde_yaml::from_str(TWO_STEPS).expect("two parses");
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(one);
        engine.register(two);
        meta.set_playbook_engine(engine);
        meta
    })
    .await;
    for backend in ["alpha", "alpha-pt"] {
        let warmed = fx.state.backends.get(backend).expect("backend");
        warmed.get_tools().await.expect("lists");
    }
    fx
}

fn refused(body: &Value) -> bool {
    body.get("error").is_some() || body["result"]["isError"] == true
}

/// PB-R: a playbook's first step is refused by its dispatch-time policy (its
/// error-rate disable lands after admission), before anything acted. The
/// step asks for the nonce back: send 2 meets the same refusal; with the
/// step revived, send 3 runs it; send 4 is a replay. Red on base at send 2
/// (`invoke/gate.rs` returned a playbook step's refusal before asking).
/// Mutant mPB-ask.
#[tokio::test]
async fn a_playbook_step_policy_refusal_gives_the_nonce_back() {
    let fx = with_playbooks().await;
    let one = json!({"name": "one"});
    for send in 1..=2 {
        disable_before_step(&fx, "alpha");
        let body = call(&fx, "gateway_run_playbook", one.clone(), "pb-n1").await;
        assert!(
            refused(&body) && body["error"]["message"] != "Nonce replay detected",
            "send {send}: the step's refusal (at send 2: the nonce was kept): {body}"
        );
        revive(&fx, "alpha");
    }
    assert_eq!(dispatched(&fx), 0, "premise: nothing was sent");
    let third = call(&fx, "gateway_run_playbook", one.clone(), "pb-n1").await;
    assert!(!refused(&third), "send 3 was refused: {third}");
    assert_eq!(dispatched(&fx), 1, "send 3 ran the step once");
    let fourth = call(&fx, "gateway_run_playbook", one, "pb-n1").await;
    assert_eq!(
        fourth["error"]["message"], "Nonce replay detected",
        "the nonce was given back twice: {fourth}"
    );
}

/// PB-K: the second step of `two` is refused by its dispatch-time policy
/// after the first step was sent. The send marked the call dispatched and
/// spent the witness, so the nonce stays spent. Green on base. Mutant
/// mPB-uncond: the step's refusal gives the nonce back past the witness.
#[tokio::test]
async fn a_playbook_step_policy_refusal_after_a_sent_step_keeps_the_nonce() {
    let fx = with_playbooks().await;
    disable_before_step(&fx, "alpha-pt");
    let two = json!({"name": "two"});
    let first = call(&fx, "gateway_run_playbook", two.clone(), "pbk-n1").await;
    assert!(refused(&first), "premise: step 2 was refused: {first}");
    assert_eq!(dispatched(&fx), 1, "premise: step 1 was sent");
    revive(&fx, "alpha-pt");
    let again = call(&fx, "gateway_run_playbook", two, "pbk-n1").await;
    assert_eq!(
        again["error"]["message"], "Nonce replay detected",
        "the nonce was given back after a sent step: {again}"
    );
}

/// K8-K (`/mcp`, a real effect): the same unattested `gateway_execute` with
/// alpha cold. The route stage fills alpha's catalogue for the step target,
/// which drops the witness, so the refusal keeps the nonce spent.
#[tokio::test]
async fn an_unattested_plan_refusal_after_a_cold_fill_keeps_the_nonce() {
    let fx = attested().await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let fills = alpha.list_fills();
    let plan = json!({"tool": "alpha:read"});
    let first = call(&fx, "gateway_execute", plan, "k8ak-n1").await;
    assert!(
        refused_with(&first, "multi-step plans carry no attestation"),
        "premise: the plan refusal: {first}"
    );
    assert!(alpha.list_fills() > fills, "premise: the call filled alpha");
    let again = call(&fx, "gateway_search", json!({"query": "read"}), "k8ak-n1").await;
    assert_eq!(
        again["error"]["message"], "Nonce replay detected",
        "the nonce was given back after a fill: {again}"
    );
    assert_eq!(dispatched(&fx), 0, "nothing was sent");
}
