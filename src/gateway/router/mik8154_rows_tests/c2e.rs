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
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
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
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
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
    let modern = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    });
    let mut submit_meta = modern.clone();
    submit_meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let submit = json!({
        "name": "gateway_run_playbook",
        "arguments": {"name": "pb", "arguments": {"x": NUL}},
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
    ];
    let get = json!({"taskId": id, "_meta": modern});
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let (_, body) = send(
                fx,
                "/mcp",
                "k-std",
                "tasks/get",
                get.clone(),
                None,
                &get_headers,
            )
            .await;
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
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
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
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
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
