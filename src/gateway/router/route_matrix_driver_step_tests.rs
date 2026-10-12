// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only drivers for the playbook-step rows of the route x check matrix
//! (MIK-8362): `/mcp` `gateway_run_playbook` under a call budget.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::Answer;

/// MIK-8362: `runs` `/mcp` `gateway_run_playbook` calls of `definition` (named
/// `steps`, steps on `alpha`) under a call budget of `budget` per window on the
/// production firewalls, audit rows written to `audit`. Returns each answer and
/// the backend's `tools/call` sends.
pub(crate) async fn playbook_budgeted(
    audit: &Path,
    budget: usize,
    (definition, runs): (Value, usize),
) -> (Vec<Value>, usize) {
    playbook_exposed(audit, budget, (definition, runs), &[]).await
}

/// [`playbook_budgeted`] exposing only the meta-tools in `exposed`; an empty
/// list exposes them all (`MetaMcp::with_exposed_meta_tools`).
pub(crate) async fn playbook_exposed(
    audit: &Path,
    budget: usize,
    (definition, runs): (Value, usize),
    exposed: &[String],
) -> (Vec<Value>, usize) {
    playbook_run(audit, budget, (definition, runs), (exposed, "k-std")).await
}

/// [`playbook_budgeted`] as the API key `key` (the fixture's `k-deny` may not
/// invoke `read`).
pub(crate) async fn playbook_as(
    audit: &Path,
    key: &str,
    (definition, runs): (Value, usize),
) -> (Vec<Value>, usize) {
    playbook_run(audit, 10, (definition, runs), (&[], key)).await
}

async fn playbook_run(
    audit: &Path,
    budget: usize,
    (definition, runs): (Value, usize),
    (exposed, key): (&[String], &str),
) -> (Vec<Value>, usize) {
    let definition = serde_json::from_value(definition).expect("the playbook deserialises");
    let fx = crate::gateway::router::direct_guards_fixture::fixture_firewalled_budget_built(
        Answer::Ok,
        (audit.to_path_buf(), budget),
        |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta.with_exposed_meta_tools(exposed)
        },
    )
    .await;
    let mut answers = Vec::new();
    for _ in 0..runs {
        let params = serde_json::json!({ "name": "gateway_run_playbook",
            "arguments": { "name": "steps" } });
        let (_, body) = crate::gateway::router::direct_guards_fixture::send(
            &fx,
            "/mcp",
            key,
            "tools/call",
            params,
            None,
        )
        .await;
        answers.push(body);
    }
    (answers, fx.calls.load(Ordering::SeqCst))
}

/// MIK-8362 STEPFW.3: `runs` `/mcp` `gateway_run_playbook` calls of `definition`
/// (steps on `alpha`, a backend requiring per-user identity propagation) as the
/// verified identity `alice`, under a call budget of `budget` per window.
/// Returns each answer, how many credentials were minted after each run, and
/// the backend's `tools/call` sends.
pub(crate) async fn playbook_minting(
    audit: &Path,
    budget: usize,
    (definition, runs): (Value, usize),
) -> (Vec<Value>, Vec<usize>, usize) {
    let definition = serde_json::from_value(definition).expect("the playbook deserialises");
    let minting =
        std::sync::Arc::new(crate::gateway::router::direct_guards_fixture::Minting::default());
    let strategy = std::sync::Arc::clone(&minting);
    let fx = crate::gateway::router::direct_guards_fixture::fixture_propagating_budgeted(
        (audit.to_path_buf(), budget),
        move |meta| {
            meta.set_identity_propagation(strategy);
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
        },
    )
    .await;
    // A propagated call dispatches on the caller's own pool slot, keyed by its
    // binding: seed alice's slot with the fixture's scripted backend.
    let registered = fx.state.backends.get("alpha").expect("fixture backend");
    let shared = registered
        .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
        .expect("the fixture's scripted transport");
    registered.set_pooled_transport_for_test(
        &crate::backend::PoolKey::PerUser {
            binding: "alice@aud-alpha".to_string(),
        },
        shared,
    );
    let (mut answers, mut minted) = (Vec::new(), Vec::new());
    for _ in 0..runs {
        let params = serde_json::json!({ "name": "gateway_run_playbook",
            "arguments": { "name": "steps" } });
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", "Bearer k-std")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": params })
                .to_string(),
            ))
            .expect("the request builds");
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
            .expect("the router answers");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        answers.push(serde_json::from_slice(&body).unwrap_or(Value::Null));
        minted.push(minting.count());
    }
    (answers, minted, fx.calls.load(Ordering::SeqCst))
}

/// MIK-8362 p5: one synchronous `gateway_run_playbook` of `definition` spends a
/// call budget of `budget`, then a task-augmented call of the same playbook is
/// made as a modern client that declares tasks. Returns the task call's answer.
pub(crate) async fn playbook_then_task(audit: &Path, budget: usize, definition: Value) -> Value {
    let definition = serde_json::from_value(definition).expect("the playbook deserialises");
    let fx = crate::gateway::router::direct_guards_fixture::fixture_firewalled_budget_built(
        Answer::Ok,
        (audit.to_path_buf(), budget),
        |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    let run = serde_json::json!({ "name": "gateway_run_playbook",
        "arguments": { "name": "steps" } });
    let (_, first) = crate::gateway::router::direct_guards_fixture::send(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        run,
        None,
    )
    .await;
    assert!(
        first.get("error").is_none(),
        "setup: the first run was refused: {first}"
    );
    let task = serde_json::json!({
        "name": "gateway_run_playbook",
        "arguments": { "name": "steps" },
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":
                { "extensions": { "io.modelcontextprotocol/tasks": {} } },
            "io.modelcontextprotocol/clientInfo": { "name": "StepFw", "version": "1" },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "stepfw-task-1"
        }
    });
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_run_playbook")
        .body(axum::body::Body::from(
            serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": task })
            .to_string(),
        ))
        .expect("the request builds");
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .expect("the router answers");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}
