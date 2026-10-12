// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8351 (with MIK-8154 SAN.3 and MIK-8226 SCAN.4): the direct route
//! `/mcp/{name}` sends `tools/call` through the dispatch chokepoint, on the
//! bytes it sends, redeemed answers included; string-form `arguments` are the
//! object the backend receives. Test plan: lead-decisions scratch
//! secD-8351-t1.md (t1, t2).

#[cfg(feature = "firewall")]
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::dispatched;
#[cfg(feature = "firewall")]
use super::direct_continuation_tests::{BACKENDS, code, state_of};
use super::direct_guards_fixture::Answer;
#[cfg(feature = "firewall")]
use super::direct_guards_fixture::{Fx, send_with_headers};

/// A shell-injection argument the input scanner blocks (a High finding).
#[cfg(feature = "firewall")]
const BLOCKED: &str = "; rm -rf / ";

/// A modern `tools/call` of `read` on `/mcp/{backend}` as `key`, declaring
/// form elicitation, with `arguments` and `extra` in the params.
#[cfg(feature = "firewall")]
async fn direct(
    fx: &Fx,
    (key, backend): (&str, &str),
    arguments: Value,
    extra: Value,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "read",
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    // `_meta` is merged, not replaced, so an idempotency key rides beside the
    // protocol version and the declared capabilities.
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        for (name, value) in extra {
            if name == "_meta"
                && let (Some(Value::Object(meta)), Some(more)) =
                    (params.get_mut("_meta"), value.as_object())
            {
                meta.extend(more.clone());
                continue;
            }
            params.insert(name.clone(), value.clone());
        }
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "read"),
    ];
    let uri = format!("/mcp/{backend}");
    send_with_headers(fx, &uri, key, "tools/call", params, None, &headers).await
}

/// The answers to the fixture's one question, `k1`, accepting `account`.
#[cfg(feature = "firewall")]
fn answering(account: &str) -> Value {
    json!({"k1": {"action": "accept", "content": {"account": account}}})
}

/// F2d on both backend kinds (sanitized `alpha`, passthrough `alpha-pt`): an
/// honest redeemed direct retry is sent; a hostile one (clean arguments,
/// BLOCKED in the answers) is refused at the chokepoint and only the question
/// reached the backend. Red on base: the direct send skipped the chokepoint.
/// Mutants: the permit minted with `answers: None`; the answers rescan removed.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2d_a_redeemed_direct_retry_whose_answers_break_the_firewall_is_refused() {
    use super::direct_guards_fixture::fixture_firewalled;
    for backend in BACKENDS {
        let who = ("k-std", backend);
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
        let (_, honest) = direct(&fx, who, json!({}), retry).await;
        assert!(honest.get("error").is_none(), "{backend}: {honest}");
        assert_eq!(dispatched(&fx), 2, "{backend}: the honest retry was sent");

        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering(BLOCKED)});
        let (_, refused) = direct(&fx, who, json!({}), retry).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert_eq!(dispatched(&fx), 1, "{backend}: the hostile answer was sent");
        assert_eq!(
            super::direct_continuation_tests::held(&fx).await,
            0,
            "{backend}: the refused retry leaked its continuation slot"
        );
    }
}

/// The route scan's `request` rows in the firewall audit log at `path`.
#[cfg(feature = "firewall")]
fn request_rows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "request")
        .collect()
}

/// SCAN.4 (MIK-8226): on `/mcp/{name}`, `arguments` sent as a JSON string
/// carrying a blocked payload is refused exactly like the object form: the
/// same error and the same route `request` record (action, finding count,
/// argument hash), and no backend is reached. Red on base: the entry scan
/// pattern-scans objects only, so the string went through.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_string_form_direct_arguments_are_judged_as_their_object() {
    use super::direct_guards_fixture::fixture_firewalled_audited;
    let object = json!({"cmd": BLOCKED});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    let mut seen = Vec::new();
    for form in [&object, &stringly] {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = dir.path().join("audit.jsonl");
        let fx = fixture_firewalled_audited(Answer::Ok, audit.clone()).await;
        let (_, body) = direct(&fx, ("k-std", "alpha"), form.clone(), json!({})).await;
        assert_eq!(dispatched(&fx), 0, "{form}: sent: {body}");
        let request = request_rows(&audit)
            .into_iter()
            .find(|row| row["action"] == "block")
            .unwrap_or_else(|| panic!("{form}: a blocking request row; {body}"));
        seen.push((
            body["error"].clone(),
            request["findings_count"].clone(),
            request["args_hash"].clone(),
        ));
    }
    assert_eq!(
        seen[0], seen[1],
        "the string form was judged unlike the object form"
    );
}

/// SCAN.4-clean (kills "scan the parse, forward the string"): a clean
/// string-form `arguments` on a sanitized and a passthrough backend is sent
/// once, and the backend receives the parsed object, not the string. Red on
/// base: the string was forwarded as sent.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_a_clean_string_form_call_reaches_the_backend_as_its_object() {
    use super::direct_guards_fixture::fixture_firewalled;
    let object = json!({"cmd": "x"});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    for backend in BACKENDS {
        let fx = fixture_firewalled(Answer::Ok).await;
        let (_, body) = direct(&fx, ("k-std", backend), stringly.clone(), json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: {body}");
        assert_eq!(dispatched(&fx), 1, "{backend}: sent once");
        let sent = fx.seen.lock().expect("seen lock").last().cloned();
        assert_eq!(
            sent.as_ref().map(|params| &params["arguments"]),
            Some(&object),
            "{backend}: the backend did not receive the parsed object: {sent:?}"
        );
    }
}

/// SCAN.4-retry: a clean string-form retry's redeemed send carries the parsed
/// object too, on both backend kinds.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_a_clean_string_form_retry_is_sent_as_its_object() {
    use super::direct_guards_fixture::fixture_firewalled;
    let object = json!({"cmd": "x"});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    for backend in BACKENDS {
        let who = ("k-std", backend);
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, stringly.clone(), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
        let (_, answered) = direct(&fx, who, stringly.clone(), retry).await;
        assert!(answered.get("error").is_none(), "{backend}: {answered}");
        let sent = fx.seen.lock().expect("seen lock").last().cloned();
        assert_eq!(
            sent.as_ref().map(|params| &params["arguments"]),
            Some(&object),
            "{backend}: the redeemed send did not carry the parsed object: {sent:?}"
        );
    }
}

/// SCAN.4-schema: string-form `arguments` naming a parameter the tool does not
/// declare are refused before the backend exactly like the object form (same
/// answer, nothing sent). Red on base: the string skipped schema validation.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_string_form_arguments_are_schema_validated_like_the_object() {
    use super::direct_guards_fixture::fixture_firewalled;
    let object = json!({"q": "x"});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    for backend in BACKENDS {
        let mut answers = Vec::new();
        for form in [&object, &stringly] {
            let fx = fixture_firewalled(Answer::Ok).await;
            let (_, body) = direct(&fx, ("k-std", backend), form.clone(), json!({})).await;
            assert_eq!(dispatched(&fx), 0, "{backend} {form}: sent: {body}");
            answers.push(body);
        }
        assert_eq!(
            answers[0]["result"]["isError"],
            json!(true),
            "{backend}: {}",
            answers[0]
        );
        assert_eq!(
            answers[0], answers[1],
            "{backend}: the string form was validated unlike the object"
        );
    }
}

/// F7b-direct: string-form `arguments` parsing to a non-object (an array, a
/// number) are refused -32602 before anything is sent, as on the meta route.
#[tokio::test]
async fn f7b_direct_string_arguments_that_parse_to_a_non_object_are_refused() {
    use super::direct_guards_fixture::{fixture, send};
    for stringly in ["[1, 2]", "7"] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let params = json!({"name": "read", "arguments": stringly});
        let (_, body) = send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None).await;
        assert_eq!(dispatched(&fx), 0, "{stringly}: sent: {body}");
        assert_eq!(body["error"]["code"], -32602, "{stringly}: {body}");
    }
}

/// Absent `arguments` (guard and hostile pin): a clean call with no
/// `arguments` is sent unchanged; one carrying a blocked pattern in another
/// params field is refused at entry, because with no `arguments` the entry
/// scan judges the whole params (`backend_handlers.rs:96`). Mutant: absent
/// arguments judged as `{}`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn absent_direct_arguments_keep_the_whole_params_scan() {
    use super::direct_guards_fixture::{fixture_firewalled, send};
    let fx = fixture_firewalled(Answer::Ok).await;
    let (_, clean) = send(
        &fx,
        "/mcp/alpha",
        "k-std",
        "tools/call",
        json!({"name": "read"}),
        None,
    )
    .await;
    assert!(clean.get("error").is_none(), "clean: {clean}");
    assert_eq!(dispatched(&fx), 1, "clean: sent once");

    let fx = fixture_firewalled(Answer::Ok).await;
    let hostile = json!({"name": "read", "note": BLOCKED});
    let (_, refused) = send(&fx, "/mcp/alpha", "k-std", "tools/call", hostile, None).await;
    assert_eq!(dispatched(&fx), 0, "hostile: sent: {refused}");
    assert!(
        refused.to_string().contains("Firewall blocked"),
        "hostile: refused by the entry scan: {refused}"
    );
}

/// A `tools/call` spelled in another letter case is refused -32601 and never
/// forwarded: the only door to a backend for a tool call is the one that
/// takes the chokepoint's permit (upgrading.d/8351.md). Red on base: the
/// variant was forwarded unchecked.
#[tokio::test]
async fn a_case_variant_tools_call_is_refused_not_forwarded() {
    use super::direct_guards_fixture::{fixture, send};
    for method in ["TOOLS/CALL", "Tools/Call"] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let params = json!({"name": "read", "arguments": {}});
        let (_, body) = send(&fx, "/mcp/alpha", "k-std", method, params, None).await;
        assert_eq!(dispatched(&fx), 0, "{method}: forwarded: {body}");
        assert_eq!(body["error"]["code"], -32601, "{method}: {body}");
    }
}

/// Guard (grok t1): a non-call method is not a tool send, so it takes no
/// permit and no dispatch rescan; a blocked pattern in `ping` params is still
/// forwarded, as before. The send count, not the absence of a dispatch row,
/// is the oracle: an allowed send writes no dispatch row either.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_non_call_method_is_forwarded_without_a_permit() {
    use super::direct_guards_fixture::{fixture_firewalled, send};
    let fx = fixture_firewalled(Answer::Ok).await;
    let params = json!({"note": BLOCKED});
    let (_, body) = send(&fx, "/mcp/alpha", "k-std", "ping", params, None).await;
    assert_eq!(dispatched(&fx), 1, "ping was not forwarded: {body}");
}

/// F2d, nonce (MIK-8379.DIRECTREFUND.2; was F2d-giveback, grok t2 HIGH): a
/// signed direct retry consumes its continuation, then the chokepoint refuses
/// it. The consume is an effect, so the nonce stays spent: a fresh signed call
/// under it is refused as a replay, as on /mcp (K-choke-consume). The consume
/// is asserted: the same continuation, honestly answered under a fresh nonce,
/// is refused as already redeemed. Red on base (the direct route refunded).
/// Mutant mC: the chokepoint refusal releases the nonce unconditionally.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2d_a_chokepoint_refusal_after_a_consume_keeps_the_nonce() {
    use super::direct_continuation_tests::{answers, signed_call};
    use super::direct_guards_fixture::fixture_hardened_signed_firewalled;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed_firewalled(Answer::AskOnce).await;
        let who = ("k-std", backend);
        let (_, asked) = signed_call(&fx, who, &format!("{backend}-n1"), json!({})).await;
        let state = state_of(&asked);
        let n2 = format!("{backend}-n2");
        let hostile = json!({"requestState": state, "inputResponses": answering(BLOCKED)});
        let (_, refused) = signed_call(&fx, who, &n2, hostile).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert_eq!(dispatched(&fx), 1, "{backend}: the hostile answer was sent");

        let (status, fresh) = signed_call(&fx, who, &n2, json!({})).await;
        assert!(
            fresh.to_string().to_lowercase().contains("replay"),
            "{backend}: the nonce was given back after a consume ({status}): {fresh}"
        );
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: the replay reached the backend"
        );

        let honest = json!({"requestState": state, "inputResponses": answers()});
        let (_, again) = signed_call(&fx, who, &format!("{backend}-n3"), honest).await;
        assert_eq!(
            code(&again),
            Some(-32602),
            "{backend}: the continuation was consumed: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{backend}");
    }
}

/// C-refund (MIK-8379.DIRECTREFUND.3/.4, site C): a chokepoint refusal with
/// nothing acted before it (the schema warm from the first call, no mint, no
/// continuation) gives the nonce back: the same call re-sent is served, and a
/// third send is a replay. The direct twin of R-choke-fresh. Mutant mCKeep:
/// the chokepoint refusal never releases.
#[tokio::test]
async fn a_direct_chokepoint_refusal_with_nothing_acted_gives_the_nonce_back() {
    use super::backend_handlers::direct_permit_seams as seams;
    use super::direct_continuation_tests::signed_call;
    use super::direct_guards_fixture::fixture_hardened_signed;
    for backend in super::direct_continuation_tests::BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let who = ("k-std", backend);
        let (_, first) = signed_call(&fx, who, &format!("{backend}-n1"), json!({})).await;
        assert!(
            first.get("error").is_none(),
            "{backend}: the warm-up: {first}"
        );
        let warm = fx.state.backends.get(backend).expect("fixture backend");
        let fills = warm.list_fills();

        let n2 = format!("{backend}-n2");
        seams::refuse_next_permit();
        let (_, refused) = signed_call(&fx, who, &n2, json!({})).await;
        assert!(
            refused.to_string().contains(seams::REFUSED),
            "{backend}: the chokepoint refusal: {refused}"
        );
        assert_eq!(
            warm.list_fills(),
            fills,
            "{backend}: premise: nothing filled"
        );
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: the refused call was not sent"
        );

        let (_, again) = signed_call(&fx, who, &n2, json!({})).await;
        assert!(
            again.get("error").is_none(),
            "{backend}: the nonce was kept though nothing acted: {again}"
        );
        assert_eq!(dispatched(&fx), 2, "{backend}: the re-send was sent");
        let (_, third) = signed_call(&fx, who, &n2, json!({})).await;
        assert!(
            third.to_string().to_lowercase().contains("replay"),
            "{backend}: the nonce was given back twice: {third}"
        );
    }
}

/// F2d-giveback, idempotency key: a direct retry the chokepoint refuses holds
/// no idempotency key, so a fresh call under that key reaches the backend, as
/// R6b shows for a refused seal. Red on base. Mutant m6b: the reservation
/// kept on the chokepoint refusal.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2d_giveback_a_refused_direct_send_holds_no_key() {
    use super::direct_guards_fixture::fixture_firewalled;
    use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    for backend in BACKENDS {
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let who = ("k-std", backend);
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let keyed = |key: &str| json!({ IDEMPOTENCY_KEY_META: key });
        let mut hostile =
            json!({"requestState": state_of(&asked), "inputResponses": answering(BLOCKED)});
        hostile["_meta"] = keyed(&format!("k-8351-{backend}"));
        let (_, refused) = direct(&fx, who, json!({}), hostile).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert_eq!(dispatched(&fx), 1, "{backend}: the hostile answer was sent");
        let fresh = json!({"_meta": keyed(&format!("k-8351-{backend}"))});
        let (_, again) = direct(&fx, who, json!({}), fresh).await;
        assert_eq!(dispatched(&fx), 2, "{backend}: the key was held: {again}");
    }
}

/// F2d-giveback, spend: a direct retry the chokepoint refuses keeps no spend
/// reservation. `k-budget` has 2.5 at 1.0 a call: the question spends 1.0;
/// the refused retry reserves 1.0 and must give it back, so the recorded spend
/// stays at the question's and a fresh call still fits (a leaked reservation
/// would make it 3.0 and refuse it). Red on base. Mutant m6c: the admission
/// kept on the chokepoint refusal.
#[cfg(all(feature = "firewall", feature = "cost-governance"))]
#[tokio::test]
async fn f2d_giveback_a_refused_direct_send_keeps_no_spend() {
    use super::direct_guards_fixture::fixture_firewalled_built;
    use crate::cost_accounting::config::CostGovernanceConfig;
    for backend in BACKENDS {
        let mut cfg = CostGovernanceConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.tool_costs.insert("read".to_string(), 1.0);
        cfg.budgets.per_key.insert("k-budget".to_string(), 2.5);
        let registry =
            std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
        let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
            cfg,
            std::sync::Arc::clone(&registry),
        ));
        let fx = fixture_firewalled_built(Answer::AskOnce, move |meta| {
            meta.with_cost_governance(enforcer, registry)
        })
        .await;
        let spend = || {
            let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
            enforcer
                .snapshot()
                .key_daily
                .get("k-budget")
                .copied()
                .unwrap_or(0.0)
        };
        let who = ("k-budget", backend);
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let after_question = spend();
        let hostile =
            json!({"requestState": state_of(&asked), "inputResponses": answering(BLOCKED)});
        let (_, refused) = direct(&fx, who, json!({}), hostile).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert!(
            (spend() - after_question).abs() < f64::EPSILON,
            "{backend}: the refused send was charged"
        );
        let (_, fresh) = direct(&fx, who, json!({}), json!({})).await;
        assert!(
            fresh.get("error").is_none(),
            "{backend}: the fresh call did not fit; a reservation leaked: {fresh}"
        );
        assert_eq!(dispatched(&fx), 2, "{backend}: the fresh call was not sent");
    }
}

/// `body` posted raw to `/mcp/alpha` as `k-std`: the response status and body.
async fn post_raw(fx: &super::direct_guards_fixture::Fx, body: Value) -> (u16, String) {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = fx.router.clone().oneshot(request).await.expect("served");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Path inventory (gpt and grok t2): an id-less `tools/call` is not a tool
/// send on any door: the parser refuses it -32600 "Missing id" before routing,
/// and nothing reaches the backend.
#[tokio::test]
async fn an_id_less_direct_tools_call_is_refused_before_routing() {
    use super::direct_guards_fixture::fixture;
    let fx = fixture(Answer::Ok, |_| {}).await;
    let body = json!({"jsonrpc": "2.0", "method": "tools/call",
        "params": {"name": "read", "arguments": {}}});
    let (_, answer) = post_raw(&fx, body).await;
    assert_eq!(dispatched(&fx), 0, "sent: {answer}");
    assert!(answer.contains("Missing id"), "{answer}");
}

/// Path inventory: a JSON-RPC batch carrying a `tools/call` does not reach the
/// backend around the permit. Measured on base before this row was pinned; if
/// the route ever serves batches, each item must take its own permit.
#[tokio::test]
async fn a_direct_batch_carrying_tools_call_is_not_forwarded_unchecked() {
    use super::direct_guards_fixture::fixture;
    let fx = fixture(Answer::Ok, |_| {}).await;
    let body = json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}}]);
    let (_, answer) = post_raw(&fx, body).await;
    assert_eq!(
        dispatched(&fx),
        0,
        "a batched tools/call was forwarded: {answer}"
    );
}

/// Path inventory: a task-augmented direct `tools/call` whose redeemed answers
/// the firewall blocks is refused at the chokepoint like any other retry.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_hostile_task_augmented_direct_retry_is_refused() {
    use super::direct_guards_fixture::fixture_firewalled;
    let task = json!({"task": {"ttl": 60_000}});
    let fx = fixture_firewalled(Answer::AskOnce).await;
    let who = ("k-std", "alpha");
    let (_, asked) = direct(&fx, who, json!({}), task.clone()).await;
    let mut hostile =
        json!({"requestState": state_of(&asked), "inputResponses": answering(BLOCKED)});
    hostile["task"] = task["task"].clone();
    let (_, refused) = direct(&fx, who, json!({}), hostile).await;
    assert_eq!(code(&refused), Some(-32600), "{refused}");
    assert_eq!(dispatched(&fx), 1, "the hostile answer was sent");
}

/// F2r (guard): a parked direct round cannot be resumed by a restarted
/// gateway. Continuations are sealed per process, so a fresh fixture stands in
/// for the restart: the first process's state is refused at redemption and
/// the new process's backend is never reached. (F1r, the interrupted task
/// settled with no send, is `task_service::runtime_tests::recovery` row
/// `x6a-undispatched`.)
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2r_a_restarted_gateway_refuses_the_old_round_at_redemption() {
    use super::direct_guards_fixture::fixture_firewalled;
    let who = ("k-std", "alpha");
    let first = fixture_firewalled(Answer::AskOnce).await;
    let (_, asked) = direct(&first, who, json!({}), json!({})).await;
    let restarted = fixture_firewalled(Answer::AskOnce).await;
    let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
    let (_, refused) = direct(&restarted, who, json!({}), retry).await;
    assert!(
        refused.get("error").is_some(),
        "the old round resumed: {refused}"
    );
    assert_eq!(
        dispatched(&restarted),
        0,
        "the restarted backend was reached"
    );
}
