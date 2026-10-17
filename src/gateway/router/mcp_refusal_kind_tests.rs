// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3d-1 (NONCEFX.11, invoke path): each remaining refusal kind
//! asks for the signing nonce back, and the settle gives it back only with the
//! refund witness. Per kind, a REFUND row on the effect-free path (send 1 and
//! send 2 under one nonce meet the kind's own refusal; the premise is cleared;
//! send 3 is served; send 4 is a replay) and a KEEP row where an effect came
//! first (the re-send is a replay).

use serde_json::{Value, json};

use super::direct_continuation_tests::dispatched;
use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed_built};
use super::mcp_nonce_witness_tests::seed_caller_slots;

/// A signed `tools/call` of `name` on `/mcp` as `k-std`, carrying `alice`'s
/// verified identity, with `meta` added to the modern `_meta`.
async fn call(fx: &Fx, name: &str, arguments: Value, meta: Value) -> Value {
    let mut params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        },
    });
    if let (Some(into), Some(extra)) = (params["_meta"].as_object_mut(), meta.as_object()) {
        into.extend(extra.clone());
    }
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

/// A signed `gateway_invoke` of `backend`'s `read` with `args` under `nonce`.
async fn invoke(fx: &Fx, backend: &str, args: Value, nonce: &str, meta: Value) -> Value {
    let arguments = json!({"server": backend, "tool": "read", "arguments": args, "nonce": nonce});
    call(fx, "gateway_invoke", arguments, meta).await
}

/// A signed `gateway_execute` of `chain` under `nonce` (hardened: in `_meta`).
async fn execute(fx: &Fx, chain: Value, nonce: &str) -> Value {
    let meta = json!({(crate::gateway::meta_mcp::signing::NONCE_META): nonce});
    call(fx, "gateway_execute", json!({"chain": chain}), meta).await
}

fn message(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn is_replay(body: &Value) -> bool {
    message(body) == "Nonce replay detected"
}

fn idem(key: &str) -> Value {
    json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key})
}

/// An idempotency cache one entry short of full, plus the `held` entry that
/// fills it, so a row can free one slot by removing `held`.
fn full_cache() -> std::sync::Arc<crate::idempotency::IdempotencyCache> {
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());
    for n in 1..crate::idempotency::MAX_ENTRIES {
        cache.mark_in_flight(&format!("k1-fill-{n}"));
    }
    cache.mark_in_flight("held");
    cache
}

fn with_cache(
    cache: &std::sync::Arc<crate::idempotency::IdempotencyCache>,
) -> impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp {
    let cache = std::sync::Arc::clone(cache);
    move |mut meta| {
        meta.enable_idempotency(cache, std::time::Duration::from_secs(300));
        meta
    }
}

fn at_capacity(body: &Value) -> bool {
    message(body).contains("at capacity")
}

/// K1-R: the inner idempotency guard refuses a keyed call because its cache
/// is full, before anything acted (the slot was warmed unkeyed). The nonce
/// comes back: send 2 meets the same refusal; once a slot frees, send 3 is
/// served; send 4 is a replay. Red on base at send 2 (the guard's refusal
/// never asked). Mutant mK1-ask: the ask removed.
#[tokio::test]
async fn an_idempotency_capacity_refusal_gives_the_nonce_back() {
    let cache = full_cache();
    let fx = fixture_hardened_signed_built(Answer::Ok, true, with_cache(&cache)).await;
    let warm = invoke(&fx, "alpha", json!({}), "k1-n0", json!({})).await;
    assert!(warm.get("error").is_none(), "premise: warm-up: {warm}");
    let before = dispatched(&fx);

    let first = invoke(&fx, "alpha", json!({}), "k1-n1", idem("k1-key")).await;
    assert!(at_capacity(&first), "premise: the guard's refusal: {first}");
    let second = invoke(&fx, "alpha", json!({}), "k1-n1", idem("k1-key")).await;
    assert!(
        at_capacity(&second),
        "the refused call kept its nonce: {second}"
    );
    assert_eq!(dispatched(&fx), before, "premise: nothing was sent");

    cache.remove("held");
    let third = invoke(&fx, "alpha", json!({}), "k1-n1", idem("k1-key")).await;
    assert!(third.get("error").is_none(), "send 3 was refused: {third}");
    assert_eq!(
        dispatched(&fx),
        before + 1,
        "send 3 reached the backend once"
    );
    let fourth = invoke(&fx, "alpha", json!({}), "k1-n1", idem("k1-key2")).await;
    assert!(
        is_replay(&fourth),
        "the nonce was given back twice: {fourth}"
    );
}

/// K1-K: the same capacity refusal after the call minted a credential (the
/// backend requires identity propagation). The mint dropped the witness, so
/// the nonce stays spent. Green on base. Mutant mK1-uncond: the guard's
/// refusal gives the nonce back without the witness.
#[tokio::test]
async fn an_idempotency_capacity_refusal_after_a_mint_keeps_the_nonce() {
    use super::direct_guards_fixture::fixture_propagating_signed;
    let cache = full_cache();
    let (fx, minting) = fixture_propagating_signed(Answer::Ok, false, with_cache(&cache)).await;
    seed_caller_slots(&fx);
    let warm = invoke(&fx, "alpha", json!({}), "k1k-n0", json!({})).await;
    assert!(warm.get("error").is_none(), "premise: warm-up: {warm}");

    let minted = minting.count();
    let first = invoke(&fx, "alpha", json!({}), "k1k-n1", idem("k1k-key")).await;
    assert!(at_capacity(&first), "premise: the guard's refusal: {first}");
    assert!(minting.count() > minted, "premise: the refused call minted");

    cache.remove("held");
    let again = invoke(&fx, "alpha", json!({}), "k1k-n1", idem("k1k-key")).await;
    assert!(
        is_replay(&again),
        "the nonce was given back after a mint: {again}"
    );
}

fn undeclared(body: &Value) -> bool {
    body["result"]["isError"] == true && body.to_string().contains("bogus")
}

/// K2-R: on a warm slot the undeclared-key check refuses an argument `read`
/// does not declare (`Ok(isError)`), having acted on nothing. The nonce comes
/// back: send 2 meets the same refusal; send 3 with the declared arguments is
/// served; send 4 is a replay. Red on base at send 2. Mutant mK2-ask.
#[tokio::test]
async fn an_undeclared_key_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| meta).await;
    let warm = invoke(&fx, "alpha", json!({}), "k2-n0", json!({})).await;
    assert!(warm.get("error").is_none(), "premise: warm-up: {warm}");
    let warmed = fx.state.backends.get("alpha").expect("alpha");
    let (before, fills) = (dispatched(&fx), warmed.list_fills());

    let bogus = json!({"bogus": "x"});
    let first = invoke(&fx, "alpha", bogus.clone(), "k2-n1", json!({})).await;
    assert!(undeclared(&first), "premise: the key refusal: {first}");
    let second = invoke(&fx, "alpha", bogus, "k2-n1", json!({})).await;
    assert!(
        undeclared(&second),
        "the refused call kept its nonce: {second}"
    );
    assert_eq!(warmed.list_fills(), fills, "premise: no fill");
    assert_eq!(dispatched(&fx), before, "premise: nothing was sent");

    let third = invoke(&fx, "alpha", json!({}), "k2-n1", json!({})).await;
    assert!(third.get("error").is_none(), "send 3 was refused: {third}");
    assert_eq!(
        dispatched(&fx),
        before + 1,
        "send 3 reached the backend once"
    );
    let fourth = invoke(&fx, "alpha", json!({}), "k2-n1", json!({})).await;
    assert!(
        is_replay(&fourth),
        "the nonce was given back twice: {fourth}"
    );
}

/// K2-K: the same refusal on a cold slot: the call filled `tools/list` from
/// the backend first, which dropped the witness, so the nonce stays spent.
/// Green on base. Mutant mK2-uncond: the refusal gives the nonce back
/// without the witness.
#[tokio::test]
async fn an_undeclared_key_refusal_after_a_cold_fill_keeps_the_nonce() {
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| meta).await;
    let cold = fx.state.backends.get("alpha-pt").expect("alpha-pt");
    assert!(!cold.has_cached_tools(), "premise: alpha-pt is cold");
    let fills = cold.list_fills();

    let bogus = json!({"bogus": "x"});
    let first = invoke(&fx, "alpha-pt", bogus, "k2k-n1", json!({})).await;
    assert!(undeclared(&first), "premise: the key refusal: {first}");
    assert!(
        cold.list_fills() > fills,
        "premise: the refused call filled"
    );

    let again = invoke(&fx, "alpha-pt", json!({}), "k2k-n1", json!({})).await;
    assert!(
        is_replay(&again),
        "the nonce was given back after a fill: {again}"
    );
    assert_eq!(dispatched(&fx), 0, "nothing reached the backend");
}

/// Disable `(server, read)` by its error rate, as enough failures do; the
/// gate does not read it, the dispatch-time policy does.
fn disable_read(meta: &crate::gateway::meta_mcp::MetaMcp, server: &str) {
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    let switch = meta.kill_switch();
    for _ in 0..cfg.min_samples.max(1) {
        switch.record_capability_failure(server, "read", &cfg);
    }
    assert!(
        switch.is_capability_disabled(server, "read"),
        "premise: {server}:read disabled"
    );
}

/// Run `disable_read(server)` at the chain seam: after nonce and execution
/// admission, before the first step meets its dispatch-time policy.
fn disable_at_seam(fx: &Fx, server: &'static str) {
    let state = std::sync::Arc::clone(&fx.state);
    crate::gateway::meta_mcp::withheld_gate::seams::before_resume(move || {
        disable_read(&state.meta_mcp, server);
    });
}

fn recheck_refused(body: &Value) -> bool {
    body.to_string().contains("temporarily disabled due to")
}

/// K4-R: a chain step's dispatch-time policy recheck refuses it (the step's
/// error-rate disable lands after admission), before anything acted. The
/// backstop's `None` arm asks for the nonce back: send 2 meets the same
/// refusal; with the step revived, send 3 is served; send 4 is a replay. Red
/// on base at send 2. Mutant mK4-ask.
#[tokio::test]
async fn a_policy_recheck_refusal_gives_the_nonce_back() {
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| meta).await;
    let warm = invoke(&fx, "alpha", json!({}), "k4-n0", json!({})).await;
    assert!(warm.get("error").is_none(), "premise: warm-up: {warm}");
    let before = dispatched(&fx);
    let chain = json!([{"tool": "alpha:read", "arguments": {}}]);
    let revive = || {
        fx.state
            .meta_mcp
            .kill_switch()
            .revive_capability("alpha", "read");
    };

    disable_at_seam(&fx, "alpha");
    let first = execute(&fx, chain.clone(), "k4-n1").await;
    assert!(recheck_refused(&first), "premise: the recheck: {first}");
    revive();
    disable_at_seam(&fx, "alpha");
    let second = execute(&fx, chain.clone(), "k4-n1").await;
    assert!(
        recheck_refused(&second),
        "the refused call kept its nonce: {second}"
    );
    revive();
    assert_eq!(dispatched(&fx), before, "premise: nothing was sent");

    let third = execute(&fx, chain.clone(), "k4-n1").await;
    assert!(third.get("error").is_none(), "send 3 was refused: {third}");
    assert_eq!(
        dispatched(&fx),
        before + 1,
        "send 3 reached the backend once"
    );
    let fourth = execute(&fx, chain, "k4-n1").await;
    assert!(
        is_replay(&fourth),
        "the nonce was given back twice: {fourth}"
    );
}

/// K4-K: a two-step chain whose first step was sent, then whose second step
/// the recheck refuses. The send spent the witness and marked the call
/// dispatched, so the nonce stays spent. Green on base. Mutant mK4-uncond:
/// the backstop gives the nonce back without the witness (the give-back
/// reads only the spent veto, which nothing set).
#[tokio::test]
async fn a_policy_recheck_refusal_after_a_sent_step_keeps_the_nonce() {
    let fx = fixture_hardened_signed_built(Answer::Ok, true, |meta| meta).await;
    for (backend, nonce) in [("alpha", "k4k-n0"), ("alpha-pt", "k4k-n00")] {
        let warm = invoke(&fx, backend, json!({}), nonce, json!({})).await;
        assert!(warm.get("error").is_none(), "premise: warm-up: {warm}");
    }
    let before = dispatched(&fx);
    let chain = json!([
        {"tool": "alpha:read", "arguments": {}},
        {"tool": "alpha-pt:read", "arguments": {}},
    ]);
    disable_at_seam(&fx, "alpha-pt");
    let first = execute(&fx, chain.clone(), "k4k-n1").await;
    assert!(recheck_refused(&first), "premise: the recheck: {first}");
    assert_eq!(dispatched(&fx), before + 1, "premise: step 1 was sent");
    fx.state
        .meta_mcp
        .kill_switch()
        .revive_capability("alpha-pt", "read");

    let again = execute(&fx, chain, "k4k-n1").await;
    assert!(
        is_replay(&again),
        "the nonce was given back after a send: {again}"
    );
}
