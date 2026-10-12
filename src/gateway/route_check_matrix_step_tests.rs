// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8362 (route-check-parity): a playbook's steps get the stateful request
//! firewall at the route stage. The step `server` and `tool` are literal in the
//! playbook definition, so the route stage can scan them before any step runs;
//! authorize runs first for every target, then the firewall for every target.
//!
//! Accepted limits these rows do not claim to remove (design r3): declared
//! steps are counted, a skipped branch included; the tenant guard measures
//! the template arguments, never the rendered ones.

use super::rows::{BLOCKED, audit_rows, message};
use crate::gateway::router::route_matrix_driver_tests as router;
use crate::gateway::server::route_matrix_driver_tests::{
    playbook_of, stdio_params_counted, stdio_playbook_flaky, stdio_playbook_runs,
};
use crate::security::ToolPolicyConfig;
use crate::security::firewall::FirewallConfig;
use serde_json::json;

/// A call budget of `calls` per window, a long window.
fn budget(calls: usize) -> impl FnOnce(&mut FirewallConfig) {
    move |config| {
        config.budget.enabled = true;
        config.budget.max_calls_per_window = calls;
        config.budget.window_secs = 3_600;
    }
}

/// STEPFW.1b: a one-step playbook to `read` spends the call budget a direct
/// call to `read` spends. One call per window: the second run is refused at
/// the route stage with the budget's own finding, and its step never runs.
#[tokio::test]
async fn stdio_playbook_steps_spend_the_call_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(1),
        (playbook_of(&["read"]), ToolPolicyConfig::default()),
        2,
    )
    .await;
    assert!(
        answers[0].get("error").is_none(),
        "the first run was refused: {}",
        answers[0]
    );
    assert_eq!(answers[1]["error"]["code"], -32600, "{}", answers[1]);
    assert!(
        message(&answers[1]).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {}",
        answers[1]
    );
    assert_names_nothing_operator_defined(&answers[1]);
    assert_eq!(
        sends, 1,
        "the second run reached the backend: {}",
        answers[1]
    );
    let requests = audit_rows(&audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "block"),
        "no blocking request row: {requests:?}"
    );
}

/// STEPFW.1a: the same budget over `/mcp`, through the production router
/// firewall (the Meta-MCP holds a separate instance, as in `server/mod.rs`).
/// One call per window: run 2 of a one-step playbook is refused at the route
/// stage with the budget's finding and the step never reaches the backend. Red
/// on the base: run 2 passes and the backend is sent twice.
#[tokio::test]
async fn http_playbook_steps_spend_the_call_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = router::playbook_budgeted(&audit, 1, (playbook_of(&["read"]), 2)).await;
    assert!(
        answers[0].get("error").is_none(),
        "the first run was refused: {}",
        answers[0]
    );
    assert_eq!(answers[1]["error"]["code"], -32600, "{}", answers[1]);
    assert!(
        message(&answers[1]).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {}",
        answers[1]
    );
    assert_eq!(
        sends, 1,
        "the second run reached the backend: {}",
        answers[1]
    );
    let requests = audit_rows(&audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "block"),
        "no blocking request row: {requests:?}"
    );
}

/// STEPFW.2a: every declared step counts once against the budget. Two steps
/// and a budget of two: the first run passes (both steps ran), the second is
/// refused before it runs anything.
#[tokio::test]
async fn stdio_playbook_counts_each_declared_step_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(2),
        (playbook_of(&["read", "read"]), ToolPolicyConfig::default()),
        2,
    )
    .await;
    assert!(
        answers[0].get("error").is_none(),
        "the first run was refused: {}",
        answers[0]
    );
    assert_eq!(answers[1]["error"]["code"], -32600, "{}", answers[1]);
    assert!(
        message(&answers[1]).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {}",
        answers[1]
    );
    assert_eq!(
        sends, 2,
        "the second run reached the backend: {}",
        answers[1]
    );
}

/// STEPFW.1d: the scan covers every step before any step runs. Two steps and a
/// budget of one, a single run: the second step's charge is refused, so the
/// first step must not have reached the backend either. A scan-then-run per
/// step would send once before refusing.
#[tokio::test]
async fn stdio_playbook_refused_midway_runs_no_step() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(1),
        (playbook_of(&["read", "read"]), ToolPolicyConfig::default()),
        1,
    )
    .await;
    assert_eq!(answers[0]["error"]["code"], -32600, "{}", answers[0]);
    assert!(
        message(&answers[0]).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {}",
        answers[0]
    );
    assert_eq!(sends, 0, "a step ran before the refusal: {}", answers[0]);
}

/// STEPFW.1c: authorize runs first, for every step, before any step is scanned
/// or run. A playbook whose last step this caller's tool policy denies is
/// refused whole: no step reaches the backend and the call budget is
/// untouched (the audit has no request row, so a later direct call is not
/// short of budget).
#[tokio::test]
async fn stdio_playbook_with_a_denied_last_step_is_refused_before_any_charge() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let policy = ToolPolicyConfig {
        deny: vec!["write".to_string()],
        ..ToolPolicyConfig::default()
    };
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(1),
        (playbook_of(&["read", "write"]), policy),
        1,
    )
    .await;
    assert!(
        answers[0].get("error").is_some(),
        "a playbook with a denied step ran: {}",
        answers[0]
    );
    assert_ne!(
        answers[0]["error"]["code"], -32602,
        "refused as an unknown playbook, not by authorization: {}",
        answers[0]
    );
    assert_eq!(sends, 0, "a step ran before the refusal: {}", answers[0]);
    assert!(
        audit_rows(&audit, "request").is_empty(),
        "the refused playbook was charged: {:?}",
        audit_rows(&audit, "request")
    );
}

/// STEPFW.1c control: the same two-step playbook under a policy that allows
/// both tools runs both steps, so the refusal above is the policy's doing.
#[tokio::test]
async fn stdio_playbook_with_both_steps_allowed_runs_both() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(2),
        (playbook_of(&["read", "write"]), ToolPolicyConfig::default()),
        1,
    )
    .await;
    assert!(
        answers[0].get("error").is_none(),
        "the allowed playbook was refused: {}",
        answers[0]
    );
    assert_eq!(sends, 2, "{}", answers[0]);
}

/// STEPFW.2b: an engine retry is one logical step. The backend fails the first
/// send, the definition retries (`on_error: retry`), so run 1 sends twice and
/// still spends one unit of the budget of two; run 2 spends the other; run 3 is
/// refused. A charge per attempt would refuse run 2. Red on the base: run 3
/// passes.
#[tokio::test]
async fn stdio_playbook_retry_is_charged_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let mut definition = playbook_of(&["read"]);
    definition["on_error"] = json!("retry");
    definition["max_retries"] = json!(3);
    let (answers, sends) = stdio_playbook_flaky(&audit, budget(2), (definition, 3)).await;
    for (run, answer) in answers.iter().take(2).enumerate() {
        assert!(
            answer.get("error").is_none(),
            "run {run} was refused: {answer}"
        );
    }
    assert_eq!(answers[2]["error"]["code"], -32600, "{}", answers[2]);
    assert!(
        message(&answers[2]).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {}",
        answers[2]
    );
    // Run 1 sent twice (the failure and its retry); run 2 may be served from the
    // response cache, so only the retry is asserted.
    assert!(sends >= 2, "run 1 was not retried: {}", answers[2]);
}

/// STEPFW.2c: a step whose `condition` is false is still counted (accepted
/// residual R1: the route counts declared steps, the safe direction). Two
/// declared steps, the second always skipped, a budget of two: run 1 sends once
/// and is charged two, run 2 is refused. Red on the base: run 2 passes.
#[tokio::test]
async fn stdio_playbook_counts_a_skipped_step() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let mut definition = playbook_of(&["read", "read"]);
    definition["steps"][1]["condition"] = json!("$inputs.never");
    let (answers, sends) = stdio_playbook_runs(
        &audit,
        budget(2),
        (definition, ToolPolicyConfig::default()),
        2,
    )
    .await;
    assert!(
        answers[0].get("error").is_none(),
        "the first run was refused: {}",
        answers[0]
    );
    assert_eq!(answers[1]["error"]["code"], -32600, "{}", answers[1]);
    assert_eq!(
        sends, 1,
        "only the unskipped step of run 1 sends: {}",
        answers[1]
    );
}

/// A stdio `gateway_execute` chain over `alpha` of `tools`, in order.
fn chain_of(tools: &[&str]) -> serde_json::Value {
    let chain: Vec<serde_json::Value> = tools
        .iter()
        .map(|tool| json!({ "tool": format!("alpha:{tool}"), "arguments": {} }))
        .collect();
    json!({ "name": "gateway_execute", "arguments": { "chain": chain } })
}

/// A stdio `gateway_invoke` of `alpha:read`.
fn invoke_read() -> serde_json::Value {
    json!({ "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} } })
}

/// PIN p1 (positive control, green on the base): a two-target chain spends two
/// units and a `gateway_invoke` one, each target once. Budget of three: the
/// chain and one invoke pass, the next invoke is refused.
#[tokio::test]
async fn stdio_chain_and_invoke_count_once_per_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let params = vec![chain_of(&["read", "read"]), invoke_read(), invoke_read()];
    let (answers, _) = stdio_params_counted(
        &audit,
        budget(3),
        (None, ToolPolicyConfig::default(), params),
    )
    .await;
    assert!(answers[0].get("error").is_none(), "{}", answers[0]);
    assert!(answers[1].get("error").is_none(), "{}", answers[1]);
    assert_eq!(answers[2]["error"]["code"], -32600, "{}", answers[2]);
}

/// PIN p2 (green on the base): a playbook name that does not exist still
/// answers the handler's own -32602, and the route confirms nothing about it.
#[tokio::test]
async fn stdio_missing_playbook_keeps_its_own_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let params = vec![json!({ "name": "gateway_run_playbook", "arguments": { "name": "nope" } })];
    let (answers, sends) = stdio_params_counted(
        &audit,
        budget(1),
        (
            Some(playbook_of(&["read"])),
            ToolPolicyConfig::default(),
            params,
        ),
    )
    .await;
    assert_eq!(answers[0]["error"]["code"], -32602, "{}", answers[0]);
    assert!(
        message(&answers[0]).contains("Playbook not found: nope"),
        "{}",
        answers[0]
    );
    assert_eq!(sends, 0);
    assert!(
        audit_rows(&audit, "request").is_empty(),
        "the route charged a missing name"
    );
}

/// PIN p6 (the stated tightening, red on the base): authorize runs for every
/// target before any is scanned. A chain whose last target the policy denies is
/// refused whole and charges nothing, so the next direct call still has its
/// single unit of budget. On the base the chain charged `read` first.
#[tokio::test]
async fn stdio_chain_with_a_denied_last_target_charges_no_earlier_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let policy = ToolPolicyConfig {
        deny: vec!["write".to_string()],
        ..ToolPolicyConfig::default()
    };
    let params = vec![chain_of(&["read", "write"]), invoke_read()];
    let (answers, sends) = stdio_params_counted(&audit, budget(1), (None, policy, params)).await;
    assert!(answers[0].get("error").is_some(), "{}", answers[0]);
    assert!(
        answers[1].get("error").is_none(),
        "the refused chain spent the budget: {}",
        answers[1]
    );
    assert_eq!(sends, 1);
}

/// STEPFW.3: a playbook the call budget refuses at the route resolves no
/// per-user credential. One call per window, a one-step playbook to a backend
/// that requires per-user propagation: run 1 mints one credential and runs;
/// run 2 is refused and the count stays at one. Red on the base: run 2 runs and
/// mints a second.
#[tokio::test]
async fn http_refused_playbook_mints_no_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, minted, sends) =
        router::playbook_minting(&audit, 1, (playbook_of(&["read"]), 2)).await;
    assert!(
        answers[0].get("error").is_none(),
        "the first run was refused: {}",
        answers[0]
    );
    assert_eq!(
        minted[0], 1,
        "the allowed run mints per step: {}",
        answers[0]
    );
    assert_eq!(answers[1]["error"]["code"], -32600, "{}", answers[1]);
    assert_eq!(
        minted[1], 1,
        "the refused run resolved a credential: {}",
        answers[1]
    );
    assert_eq!(sends, 1, "{}", answers[1]);
}

/// A tenant guard of `limit` distinct tenants per window, reading the `tenant`
/// argument.
fn tenant_limit(limit: usize) -> impl FnOnce(&mut FirewallConfig) {
    move |config| {
        config.tenant_guard.enabled = true;
        config.tenant_guard.max_tenants_per_window = limit;
        config.tenant_guard.arg_keys = vec!["tenant".to_string()];
    }
}

/// STEPFW.4: the tenant guard sees a step's literal tenant argument at the
/// route. Two steps naming two tenants against a limit of one: the call is
/// refused whole, by the guard, before either step runs. Red on the base: both
/// steps run.
#[tokio::test]
async fn stdio_playbook_steps_spend_the_tenant_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let mut definition = playbook_of(&["read", "read"]);
    definition["steps"][0]["arguments"] = json!({ "tenant": "t1" });
    definition["steps"][1]["arguments"] = json!({ "tenant": "t2" });
    let params = vec![json!({ "name": "gateway_run_playbook", "arguments": { "name": "steps" } })];
    let (answers, sends) = stdio_params_counted(
        &audit,
        tenant_limit(1),
        (Some(definition), ToolPolicyConfig::default(), params),
    )
    .await;
    assert_eq!(answers[0]["error"]["code"], -32600, "{}", answers[0]);
    assert!(
        message(&answers[0]).to_lowercase().contains("tenant"),
        "not refused by the tenant guard: {}",
        answers[0]
    );
    assert_names_nothing_operator_defined(&answers[0]);
    assert_eq!(sends, 0, "a step ran before the refusal: {}", answers[0]);
}

/// PIN R2 (accepted residual, green on the base): the route sees a step's
/// tenant argument as the template the definition holds, never the rendered
/// value. One templated step, a limit of one tenant, two runs rendering two
/// tenants: both pass, where two direct calls would not. The dispatch rescan
/// is stateless and does not count tenants. If this row turns red the residual
/// was closed and the PR text and changelog must say so.
#[tokio::test]
async fn stdio_playbook_tenant_guard_sees_templates_not_rendered_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let mut definition = playbook_of(&["read"]);
    definition["steps"][0]["arguments"] = json!({ "tenant": "$inputs.t" });
    let run = |tenant: &str| {
        json!({ "name": "gateway_run_playbook",
            "arguments": { "name": "steps", "arguments": { "t": tenant } } })
    };
    let (answers, sends) = stdio_params_counted(
        &audit,
        tenant_limit(1),
        (
            Some(definition),
            ToolPolicyConfig::default(),
            vec![run("a"), run("b")],
        ),
    )
    .await;
    for answer in &answers {
        assert!(answer.get("error").is_none(), "{answer}");
    }
    assert_eq!(sends, 2);
}

/// PIN p3 (guard row, green on the base): `gateway_run_playbook` hidden by the
/// operator's meta-tool allow-list answers as a tool that does not exist, and
/// the route expands no steps for it: nothing is charged to the budget. Red
/// if the step expansion stops honouring the allow-list.
#[tokio::test]
async fn http_hidden_playbook_tool_expands_no_steps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = router::playbook_exposed(
        &audit,
        1,
        (playbook_of(&["read"]), 2),
        &["gateway_search_tools".to_string()],
    )
    .await;
    for answer in &answers {
        assert_eq!(answer["error"]["code"], -32601, "{answer}");
        assert!(message(answer).contains("gateway_run_playbook"), "{answer}");
    }
    assert_eq!(sends, 0);
    assert!(
        audit_rows(&audit, "request").is_empty(),
        "a hidden tool was charged: {:?}",
        audit_rows(&audit, "request")
    );
}

/// PIN p4 (guard row, green on the base): the response of a playbook call is
/// still judged against the gateway tool, not the steps. The step targets join
/// the route's list only after the response targets are fixed, so the response
/// audit row names `gateway:gateway_run_playbook`.
#[tokio::test]
async fn http_playbook_response_targets_stay_the_gateway_tool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, _) = router::playbook_budgeted(&audit, 10, (playbook_of(&["read"]), 1)).await;
    assert!(answers[0].get("error").is_none(), "{}", answers[0]);
    let rows = audit_rows(&audit, "response");
    let outer: Vec<_> = rows
        .iter()
        .filter(|row| row["tool"] == "gateway_run_playbook")
        .collect();
    assert!(!outer.is_empty(), "no response row for the call: {rows:?}");
    for row in outer {
        assert_eq!(
            row["policy_targets"],
            json!([{ "server": "gateway", "tool": "gateway_run_playbook" }]),
            "{row}"
        );
    }
}

/// PIN p5: a task-augmented playbook call is judged at task creation. One call
/// per window, spent by a synchronous run; the task-augmented run is refused by
/// the budget and no task handle is issued. Red on the base: a task is created
/// and the steps run on the worker, after the route.
#[tokio::test]
async fn http_task_run_playbook_is_refused_at_creation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let body = router::playbook_then_task(&audit, 1, playbook_of(&["read"])).await;
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert!(
        message(&body).starts_with("Firewall blocked: Call budget exceeded:"),
        "not refused by the budget: {body}"
    );
    assert!(
        body.pointer("/result/taskId").is_none(),
        "a task was created: {body}"
    );
}

/// A refusal of a playbook step never names the step's server or tool (A3): the
/// stateful controls word a refusal with counts and scores only.
fn assert_names_nothing_operator_defined(answer: &serde_json::Value) {
    let text = message(answer);
    let words_name_a_target = text
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| matches!(word, "alpha" | "read" | "write"));
    assert!(
        !words_name_a_target,
        "a step refusal names its target: {answer}"
    );
}

const NEUTRAL_STEP_REFUSAL: &str = "step not permitted for this caller";

/// A playbook of one `read` step whose literal `cmd` argument is the blocked
/// pattern the content scan refuses.
fn blocked_literal_playbook() -> serde_json::Value {
    let mut definition = playbook_of(&["read"]);
    definition["steps"][0]["arguments"] = json!({ "cmd": BLOCKED });
    definition
}

/// STEPFW.5 (finding: the literal-template refusal moved to the route): a
/// blocked pattern written into a step's own arguments is refused at the route,
/// whole, before any step runs, with the neutral step answer (it names neither
/// the argument nor the pattern), and the operator still gets the blocking
/// request row. Red on the base: the step ran and failed inside the playbook,
/// so the call itself was not an error.
#[tokio::test]
async fn stdio_playbook_literal_blocked_template_is_refused_at_the_route() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let params = vec![json!({ "name": "gateway_run_playbook", "arguments": { "name": "steps" } })];
    let (answers, sends) = stdio_params_counted(
        &audit,
        budget(10),
        (
            Some(blocked_literal_playbook()),
            ToolPolicyConfig::default(),
            params,
        ),
    )
    .await;
    assert_eq!(answers[0]["error"]["code"], -32003, "{}", answers[0]);
    assert_eq!(message(&answers[0]), NEUTRAL_STEP_REFUSAL, "{}", answers[0]);
    assert_eq!(sends, 0, "{}", answers[0]);
    assert!(
        audit_rows(&audit, "request")
            .iter()
            .any(|row| row["action"] == "block"),
        "the operator has no blocking request row"
    );
}

/// STEPFW.5 over `/mcp`: the same literal refusal through the router's own
/// firewall and refusal path.
#[tokio::test]
async fn http_playbook_literal_blocked_template_is_refused_at_the_route() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) =
        router::playbook_budgeted(&audit, 10, (blocked_literal_playbook(), 1)).await;
    assert_eq!(answers[0]["error"]["code"], -32003, "{}", answers[0]);
    assert_eq!(message(&answers[0]), NEUTRAL_STEP_REFUSAL, "{}", answers[0]);
    assert_eq!(sends, 0, "{}", answers[0]);
    assert!(
        audit_rows(&audit, "request")
            .iter()
            .any(|row| row["action"] == "block"),
        "the operator has no blocking request row"
    );
}

/// PIN (guard row, green on the base): over `/mcp`, a key that may not invoke
/// the step's tool is refused the whole playbook with the neutral step answer,
/// before the step runs. The base already failed an abort-mode playbook whole
/// at the step's dispatch recheck; this row pins that the route's own refusal
/// of a step target stays neutral too.
#[tokio::test]
async fn http_playbook_with_a_denied_step_is_refused_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (answers, sends) = router::playbook_as(&audit, "k-deny", (playbook_of(&["read"]), 1)).await;
    assert_eq!(answers[0]["error"]["code"], -32003, "{}", answers[0]);
    assert_eq!(message(&answers[0]), NEUTRAL_STEP_REFUSAL, "{}", answers[0]);
    assert_eq!(sends, 0, "{}", answers[0]);
}
