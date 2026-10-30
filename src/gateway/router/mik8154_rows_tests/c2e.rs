// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 C2e (option (a), lead ruling 2026-10-11): intake judges a
//! playbook's sanitize exemption on one definition, and the run refuses a
//! different one. Green on the tip, where every playbook run is sanitized;
//! the mutant that skips the comparison in `run_playbook` turns C2e1 red.

use super::*;

/// The refusal `run_playbook` answers when the definition changed.
const CHANGED: &str = "The playbook changed after this call was admitted; retry the call";

/// C2e1: an unkeyed sync run judged exempt (both steps passthrough) whose
/// playbook is reloaded after intake with a step on a non-passthrough backend
/// is refused, and no step runs: the NUL intake let through never reaches a
/// backend that was not judged.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn c2e1_a_sync_run_reloaded_after_intake_is_refused() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    let meta = std::sync::Arc::clone(&fx.state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::after_route_stage(move || {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(playbook_definition(["alpha-pt", "alpha"]));
        meta.set_playbook_engine(engine);
    });
    let body = run_with_nul(&fx).await;
    assert!(message(&body).contains(CHANGED), "c2e1: {body}");
    assert_eq!(calls(&fx), 0, "c2e1: a step ran");
}

/// C2e4 CONTROL: the same run with no reload runs, and its NUL reaches the
/// passthrough backend.
#[tokio::test]
async fn c2e4_a_sync_run_with_no_reload_runs() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    let body = run_with_nul(&fx).await;
    assert!(body.get("error").is_none(), "c2e4: {body}");
    assert!(
        forwarded_nul(&fx),
        "c2e4: the NUL did not reach the backend"
    );
}

/// Submit `gateway_run_playbook pb` with a NUL input as a keyed task, and wait
/// for it to leave `working`; returns the last `tasks/get` body.
async fn task_run_with_nul(fx: &Fx, key: &str) -> Value {
    task_run_with(fx, key, json!({"x": NUL})).await
}

/// [`task_run_with_nul`] with the playbook's `arguments` given.
async fn task_run_with(fx: &Fx, key: &str, arguments: Value) -> Value {
    let modern = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    });
    let mut submit_meta = modern.clone();
    submit_meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    // The fixture enforces message signing: every call carries a fresh nonce.
    let nonce_meta = crate::gateway::meta_mcp::signing::NONCE_META;
    submit_meta[nonce_meta] = json!(format!("{key}-submit"));
    let submit = json!({
        "name": "gateway_run_playbook",
        "arguments": {"name": "pb", "arguments": arguments},
        "task": {},
        "_meta": submit_meta,
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_run_playbook"),
    ];
    let send = super::super::direct_guards_fixture::send_with_headers;
    let (_, created) = send(fx, "/mcp", "k-std", "tools/call", submit, None, &headers).await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the submit was refused: {created}"))
        .to_owned();
    let get_headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id.as_str()),
    ];
    let mut poll = 0u32;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            poll += 1;
            let mut get_meta = modern.clone();
            get_meta[nonce_meta] = json!(format!("{key}-get-{poll}"));
            let get = json!({"taskId": id, "_meta": get_meta});
            let (_, body) = send(fx, "/mcp", "k-std", "tasks/get", get, None, &get_headers).await;
            if body.pointer("/result/status").and_then(Value::as_str) != Some("working") {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// C2e2: a task judged exempt at submit whose playbook is reloaded before its
/// worker runs, with a step on a non-passthrough backend, fails with the
/// refusal, and no step runs.
#[tokio::test]
async fn c2e2_a_task_reloaded_before_its_run_is_refused() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    let meta = std::sync::Arc::clone(&fx.state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(playbook_definition(["alpha-pt", "alpha"]));
        meta.set_playbook_engine(engine);
    });
    let got = task_run_with_nul(&fx, "c2e2-k").await;
    assert_eq!(
        got.pointer("/result/status"),
        Some(&json!("failed")),
        "c2e2: {got}"
    );
    assert!(got.to_string().contains(CHANGED), "c2e2: {got}");
    assert_eq!(calls(&fx), 0, "c2e2: a step ran");
}

/// C2e5 CONTROL: the same task with no reload completes, and its NUL reaches
/// the passthrough backend.
#[tokio::test]
async fn c2e5_a_task_with_no_reload_runs() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    let got = task_run_with_nul(&fx, "c2e5-k").await;
    assert_eq!(
        got.pointer("/result/status"),
        Some(&json!("completed")),
        "c2e5: {got}"
    );
    assert!(
        forwarded_nul(&fx),
        "c2e5: the NUL did not reach the backend"
    );
}

/// C2e3' (lead ruling (b')): with sanitizing off at submit, intake judges no
/// exemption and records no digest, so a task whose playbook is reloaded
/// before its run runs the reloaded definition: no judgement, no comparison.
/// (C2e3, a persisted record with no digest, is unreachable: a restart
/// settles a task rather than running it, `task_service` `recovery.rs`.)
#[tokio::test]
async fn c2e3_a_task_with_no_judgement_runs_a_reloaded_playbook() {
    let definition = playbook_definition(["alpha-pt", "alpha-pt"]);
    let fx = Box::pin(sanitizing(
        false,
        super::super::direct_guards_fixture::fixture_hardened_signed_built(
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
    .await;
    let meta = std::sync::Arc::clone(&fx.state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(playbook_definition(["alpha-pt", "alpha"]));
        meta.set_playbook_engine(engine);
    });
    let got = task_run_with_nul(&fx, "c2e3-k").await;
    assert_eq!(
        got.pointer("/result/status"),
        Some(&json!("completed")),
        "c2e3': {got}"
    );
    assert_eq!(calls(&fx), 2, "c2e3': the reloaded steps did not both run");
}

/// A task submitted with sanitizing off over `pb` = `[alpha, alpha-pt]` (not
/// exempt: `alpha` is not passthrough), whose worker runs after a reload
/// turned sanitizing on: the worker re-admits it. `reload` runs between the
/// re-admission's judgement and the run. Clean arguments, so the re-admission
/// itself passes. Returns the settled body; both seams are asserted to fire.
async fn readmitted_run(key: &str, reload: Option<[&'static str; 2]>) -> (Fx, Value) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let definition = playbook_definition(["alpha", "alpha-pt"]);
    let fx = Box::pin(sanitizing(
        false,
        super::super::direct_guards_fixture::fixture_hardened_signed_built(
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
    .await;
    let live = std::sync::Arc::clone(&fx.state.live_config);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        live.edit(|c| c.security.sanitize_input = true);
    });
    let readmitted = std::sync::Arc::new(AtomicBool::new(false));
    let fired = std::sync::Arc::clone(&readmitted);
    let meta = std::sync::Arc::clone(&fx.state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::after_readmit(move || {
        fired.store(true, Ordering::SeqCst);
        if let Some(servers) = reload {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(playbook_definition(servers));
            meta.set_playbook_engine(engine);
        }
    });
    let got = task_run_with(&fx, key, json!({"x": "clean"})).await;
    assert!(
        fx.state.live_config.get().security.sanitize_input,
        "the dispatch seam never ran, so this row tested nothing: {got}"
    );
    assert!(
        readmitted.load(Ordering::SeqCst),
        "the task was never re-admitted, so this row tested nothing: {got}"
    );
    (fx, got)
}

/// C2e6: a re-admitted, non-exempt playbook task whose playbook is reloaded
/// between the re-admission and the run is refused as the synchronous path
/// refuses it, and no step runs: the re-admission keeps the digest it judged.
#[tokio::test]
async fn c2e6_a_readmitted_playbook_reloaded_before_its_run_is_refused() {
    let (fx, got) = Box::pin(readmitted_run("c2e6-k", Some(["alpha", "alpha"]))).await;
    assert!(got.to_string().contains(CHANGED), "c2e6: {got}");
    assert_eq!(
        got.pointer("/result/status"),
        Some(&json!("failed")),
        "c2e6: {got}"
    );
    assert_eq!(calls(&fx), 0, "c2e6: a step ran");
}

/// C2e7 CONTROL: the same re-admitted task with no reload completes, and both
/// steps run: keeping the digest refuses only a changed definition.
#[tokio::test]
async fn c2e7_a_readmitted_playbook_with_no_reload_runs() {
    let (fx, got) = Box::pin(readmitted_run("c2e7-k", None)).await;
    assert_eq!(
        got.pointer("/result/status"),
        Some(&json!("completed")),
        "c2e7: {got}"
    );
    assert_eq!(calls(&fx), 2, "c2e7: the steps did not both run");
}

/// The refusal a send by a reloaded backend instance meets (MIK-8154 F2).
const BACKEND_CHANGED: &str = "The backend changed after this call was admitted; retry the call";

/// F2 R1: a sync `gateway_invoke` judged exempt (its target `alpha-pt` is
/// passthrough) whose backend is reloaded after intake, as non-passthrough,
/// is refused at the send: the new instance is not the one judged, and the
/// NUL intake let through reaches no backend.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn r1_a_sync_call_whose_backend_is_reloaded_is_refused() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    crate::gateway::meta_mcp::visible::seams::after_route_stage(
        super::super::direct_guards_fixture::reload_for_test(&fx, "alpha-pt", false),
    );
    let args = json!({"cmd": NUL});
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha-pt", "read", args, None, None).await;
    // `gateway_invoke` answers a backend refusal as an `isError` tool result
    // whose recovery hint must say to retry, never to fix the parameters.
    let text = body
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let recovery = serde_json::from_str::<Value>(text).unwrap_or_default()["_recovery"].clone();
    assert_eq!(recovery["error_code"], "BACKEND_ERROR", "r1: {body}");
    assert_eq!(recovery["retry"], true, "r1: {body}");
    assert!(
        recovery["message"]
            .as_str()
            .unwrap_or_default()
            .contains(BACKEND_CHANGED),
        "r1: {body}"
    );
    assert!(!recovery.to_string().contains("input schema"), "r1: {body}");
    assert_eq!(calls(&fx), 0, "r1: the reloaded instance sent");
}

/// F2 R1d: R1 on the direct route. A `/mcp/{name}` call to the passthrough
/// backend `alpha-pt` is judged exempt at intake, and its NUL is let through.
/// The backend is then reloaded as non-passthrough before the send. The send
/// is refused: the new instance is not the one judged, so the NUL reaches no
/// backend.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn r1d_a_direct_call_whose_backend_is_reloaded_is_refused() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    crate::gateway::meta_mcp::visible::seams::after_intake(
        super::super::direct_guards_fixture::reload_for_test(&fx, "alpha-pt", false),
    );
    let args = json!({"cmd": NUL});
    let (_, body) = post_direct(&fx, "alpha-pt", "k-std", "read", args, None, None).await;
    assert!(
        body.to_string().contains(BACKEND_CHANGED),
        "r1d: not refused as a changed backend: {body}"
    );
    assert_eq!(calls(&fx), 0, "r1d: the reloaded instance sent");
}

/// F2 R2: a task over the all-passthrough playbook whose backend is reloaded
/// between submit and run, the definition unchanged (so C2e's digest still
/// matches), settles with no step sent: each send meets an instance other
/// than the one the submit judged.
#[tokio::test]
async fn r2_a_task_whose_backend_is_reloaded_sends_nothing() {
    let fx = Box::pin(playbook_fixture(["alpha-pt", "alpha-pt"])).await;
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(
        super::super::direct_guards_fixture::reload_for_test(&fx, "alpha-pt", false),
    );
    let got = Box::pin(task_run_with_nul(&fx, "r2-k")).await;
    assert!(
        got.to_string().contains(BACKEND_CHANGED),
        "r2: not refused as a changed backend: {got}"
    );
    assert_eq!(
        calls(&fx),
        0,
        "r2: a step reached the reloaded instance: {got}"
    );
    assert!(!forwarded_nul(&fx), "r2: the NUL was forwarded");
}

/// The all-passthrough playbook over a backend whose step asks a question
/// (answers `input_required` once).
async fn asking_playbook_fixture() -> Fx {
    let definition = playbook_definition(["alpha-pt", "alpha-pt"]);
    Box::pin(sanitizing(
        true,
        super::super::direct_guards_fixture::fixture_hardened_signed_built(
            Answer::AskOnce,
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

/// MIK-8341's invariant, pinned here because C2e relies on it (mrtr.rs:186-190,
/// seat finding: a resumed task would run without the judged digest): a
/// playbook never answers `input_required` at top level, even when a step's
/// backend asks a question. Sync: the run's result is not a question.
#[tokio::test]
async fn pb1_a_playbook_run_never_answers_input_required() {
    let fx = Box::pin(asking_playbook_fixture()).await;
    let body = Box::pin(run_with_nul(&fx)).await;
    let result = body.get("result").cloned().unwrap_or_default();
    assert!(
        !crate::protocol::mrtr::InputRequired::claims_input_required(&result),
        "pb1: the run asked the client: {body}"
    );
}

/// The same as a task: it settles without ever parking an input round, so no
/// resume can re-run a playbook.
#[tokio::test]
async fn pb2_a_playbook_task_never_parks_an_input_round() {
    let fx = Box::pin(asking_playbook_fixture()).await;
    let got = Box::pin(task_run_with_nul(&fx, "pb2-k")).await;
    assert_ne!(
        got.pointer("/result/status"),
        Some(&json!("input_required")),
        "pb2: the task parked a round: {got}"
    );
}
