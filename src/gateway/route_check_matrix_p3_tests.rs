// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Route-check-parity P3 (MIK-8149, MIK-8160, MIK-8326): stdio gets the route
//! checks `/mcp` runs, and a surfaced tool withheld from the caller answers as
//! a name that matches no tool. Each row asserts the fixed behaviour and was
//! run red on the release line before the fix. MIK-8149.REQFW.2 (stdio
//! sanitize) is driven by `rows::sanitize_rows`.

use super::Route;
use super::rows::{BLOCKED, X14_PROMPT, audit_rows, blocked_call, message};
use crate::gateway::router::route_matrix_driver_tests::{self as router, Surfacing};
use crate::gateway::server::route_matrix_driver_tests as stdio;

/// MIK-8149.REQFW.1: on stdio a blocked argument is refused by the route-stage
/// request firewall: a blocking `event=request` audit row, the code and
/// message `/mcp` answers for the same argument, and no backend call.
#[tokio::test]
async fn stdio_route_firewall_refuses_as_mcp_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stdio_audit = dir.path().join("stdio.jsonl");
    let mcp_audit = dir.path().join("mcp.jsonl");
    let (stdio_body, stdio_calls) = blocked_call(Route::Stdio, &stdio_audit).await;
    let (mcp_body, _) = blocked_call(Route::Invoke, &mcp_audit).await;
    let requests = audit_rows(&stdio_audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "block"),
        "stdio: no blocking request row for {BLOCKED:?}: {requests:?}; {stdio_body}"
    );
    assert_eq!(
        stdio_body["error"]["code"], mcp_body["error"]["code"],
        "stdio answered {stdio_body}, /mcp answered {mcp_body}"
    );
    assert_eq!(
        message(&stdio_body),
        message(&mcp_body),
        "stdio answered {stdio_body}, /mcp answered {mcp_body}"
    );
    assert_eq!(stdio_calls, 0, "stdio reached its backend: {stdio_body}");
}

/// MIK-8160.X14.1: a modern task call of a destructive surfaced tool over
/// stdio gets X14's challenge, bound to the stdio principal: no task is made
/// and the backend is not called.
#[tokio::test]
async fn stdio_destructive_task_gets_the_x14_challenge() {
    assert_eq!(
        super::expect(
            super::MethodKind::ToolsCall,
            Route::Stdio,
            super::Stage::TaskConfirm
        ),
        super::Expect::Applies
    );
    let (body, calls) = Box::pin(stdio::stdio_task_surfaced()).await;
    assert!(
        body.to_string().contains(X14_PROMPT),
        "no X14 challenge on stdio: {body}"
    );
    assert!(
        body.pointer("/result/taskId").is_none(),
        "a task was made before X14 decided: {body}"
    );
    assert_eq!(calls, 0, "dispatched before X14: {body}");
}

/// [`router::task_submit_read_as`] on a current-thread runtime, with the
/// warnings it logged on this thread.
fn submit_logged(
    key: &str,
    surfacing: Surfacing,
) -> ((axum::http::StatusCode, router::Sent), String) {
    crate::test_log_capture::capture_warnings(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(router::task_submit_read_as(key, surfacing))
    })
}

/// MIK-8326.X14.1 (WH.1): on `/mcp`, a modern task call of a destructive
/// surfaced tool withheld from the caller (`k-deny` is denied `read`) answers
/// exactly as the same name does where it matches no tool: the same error and
/// HTTP status. The cause is the operator-only authorization-refusal warning
/// naming `read`, which the caller never sees. No X14 challenge, no task, no
/// backend call.
#[test]
fn mcp_withheld_surfaced_task_answers_as_a_missing_name() {
    let ((withheld_status, withheld), warnings) = submit_logged("k-deny", Surfacing::On);
    let ((missing_status, missing), _) = submit_logged("k-std", Surfacing::Off);
    assert_eq!(
        missing.body["error"]["code"], -32601,
        "premise: an unsurfaced `read` matches no tool: {}",
        missing.body
    );
    assert_eq!(
        withheld.body["error"], missing.body["error"],
        "withheld {} vs missing {}",
        withheld.body, missing.body
    );
    assert_eq!(withheld_status, missing_status, "HTTP status differs");
    let refusal = warnings
        .lines()
        .find(|line| line.contains("Tool invocation refused by authorization"))
        .unwrap_or_else(|| panic!("no operator refusal warning:\n{warnings}"));
    assert!(refusal.contains("read"), "{refusal}");
    assert!(
        !withheld.body.to_string().contains(X14_PROMPT),
        "X14 challenged a withheld tool: {}",
        withheld.body
    );
    assert_eq!(withheld.backend_calls, 0, "{}", withheld.body);
}

/// [`stdio::stdio_task_read`] on a current-thread runtime, with the warnings
/// it logged on this thread.
fn stdio_logged(
    policy: Option<crate::security::ToolPolicy>,
    surfacing: Surfacing,
) -> ((serde_json::Value, usize), String) {
    crate::test_log_capture::capture_warnings(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(Box::pin(stdio::stdio_task_read(policy, surfacing)))
    })
}

/// MIK-8326.X14.2 (WH.2): the stdio sibling of WH.1. A modern task call of a
/// destructive surfaced tool stdio's tool policy denies answers exactly as
/// the same name does where nothing is surfaced; the operator-only refusal
/// warning names it. No X14 challenge, no task, no backend call.
#[test]
fn stdio_withheld_surfaced_task_answers_as_a_missing_name() {
    let denying = crate::security::ToolPolicy::from_config(&crate::security::ToolPolicyConfig {
        deny: vec!["echo".to_string()],
        ..crate::security::ToolPolicyConfig::default()
    });
    let ((withheld, withheld_calls), warnings) = stdio_logged(Some(denying), Surfacing::On);
    let ((missing, _), _) = stdio_logged(None, Surfacing::Off);
    assert_eq!(
        missing["error"]["code"], -32601,
        "premise: an unsurfaced `echo` matches no tool: {missing}"
    );
    assert_eq!(
        withheld["error"], missing["error"],
        "withheld {withheld} vs missing {missing}"
    );
    let refusal = warnings
        .lines()
        .find(|line| line.contains("Tool invocation refused by authorization"))
        .unwrap_or_else(|| panic!("no operator refusal warning:\n{warnings}"));
    assert!(refusal.contains("echo"), "{refusal}");
    assert!(
        !withheld.to_string().contains(X14_PROMPT),
        "X14 challenged a withheld tool: {withheld}"
    );
    assert_eq!(withheld_calls, 0, "{withheld}");
}

/// MIK-8149.REQFW.2 through the serve loop (design A6): `run_stdio_on` reads
/// `security.sanitize_input` from the gateway's config and refuses the NUL
/// with the sanitizer's own message, before the backend.
#[tokio::test]
async fn served_stdio_honours_sanitize_input_from_config() {
    let (body, calls) = Box::pin(stdio::served_sanitizing()).await;
    assert!(
        message(&body).contains(super::rows::NUL_REFUSED),
        "not the sanitizer's refusal: {body}"
    );
    assert_eq!(calls, 0, "the NUL reached the backend: {body}");
}

/// The one firewall refusal wording every route answers (P3): an ASI10 block
/// is `-32002` "Anomaly detection blocked: ...", any other block `-32600`
/// "Firewall blocked: ...", and an allowed verdict refuses nothing.
#[test]
fn the_firewall_refusal_is_one_definition() {
    use crate::security::firewall::{
        Finding, FindingLocation, FirewallAction, FirewallVerdict, ScanType, Severity,
    };
    let verdict = |allowed, scan_type, location| FirewallVerdict {
        allowed,
        action: if allowed {
            FirewallAction::Allow
        } else {
            FirewallAction::Block
        },
        findings: vec![Finding {
            scan_type,
            severity: Severity::High,
            description: "the finding".to_string(),
            matched: String::new(),
            location,
        }],
        anomaly_score: None,
    };
    let anomaly = verdict(
        false,
        ScanType::SequenceAnomaly,
        FindingLocation::SequenceAnomaly,
    );
    assert_eq!(
        anomaly.request_refusal(),
        Some((-32002, "Anomaly detection blocked: the finding".to_string()))
    );
    let content = verdict(
        false,
        ScanType::ShellInjection,
        FindingLocation::RequestArgs,
    );
    assert_eq!(
        content.request_refusal(),
        Some((-32600, "Firewall blocked: the finding".to_string()))
    );
    let allowed = verdict(true, ScanType::ShellInjection, FindingLocation::RequestArgs);
    assert_eq!(allowed.request_refusal(), None);
}

/// P3: with anomaly detection on, a clean stdio call passes the route-stage
/// scan and reaches its backend. Pins the non-empty `stdio` control identity:
/// an empty one makes the detector refuse every call unscored.
#[tokio::test]
async fn stdio_clean_call_passes_with_anomaly_detection_on() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let sent = stdio::stdio_anomaly_clean(&audit).await;
    assert!(
        sent.body.get("error").is_none(),
        "a clean call was refused: {}",
        sent.body
    );
    assert_eq!(sent.backend_calls, 1, "{}", sent.body);
    let requests = audit_rows(&audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "allow"),
        "the route stage wrote no allow row: {requests:?}"
    );
}

/// The second of two stdio calls is refused at the route stage by the
/// firewall control `tune` configures: `-32600`, a blocking request row, no
/// second send; the first ran.
async fn second_stdio_call_is_refused(
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    args: (serde_json::Value, serde_json::Value),
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (first, second, calls) = stdio::stdio_twice(&audit, tune, args).await;
    assert!(
        first.get("error").is_none(),
        "the first call was refused: {first}"
    );
    assert_eq!(second["error"]["code"], -32600, "{second}");
    assert!(
        message(&second).starts_with("Firewall blocked: "),
        "not the firewall's refusal: {second}"
    );
    assert_eq!(calls, 1, "the second call reached the backend: {second}");
    let requests = audit_rows(&audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "block"),
        "no blocking request row: {requests:?}"
    );
}

/// P3 (A10): the call budget applies to stdio, all of one process's calls
/// counted as one caller. One call per window: the second is refused.
#[tokio::test]
async fn stdio_calls_spend_the_call_budget() {
    let budget = |config: &mut crate::security::firewall::FirewallConfig| {
        config.budget.enabled = true;
        config.budget.max_calls_per_window = 1;
        config.budget.window_secs = 3_600;
    };
    second_stdio_call_is_refused(budget, (serde_json::json!({}), serde_json::json!({}))).await;
}

/// P3 (A10): the tenant guard applies to stdio. One tenant per window: a
/// second call naming another tenant is refused.
#[tokio::test]
async fn stdio_calls_meet_the_tenant_guard() {
    let tenants = |config: &mut crate::security::firewall::FirewallConfig| {
        config.tenant_guard.enabled = true;
        config.tenant_guard.max_tenants_per_window = 1;
        config.tenant_guard.window_secs = 3_600;
        config.tenant_guard.arg_keys = vec!["tenant".to_string()];
    };
    let args = (
        serde_json::json!({ "tenant": "acme" }),
        serde_json::json!({ "tenant": "globex" }),
    );
    second_stdio_call_is_refused(tenants, args).await;
}

/// P3: X14's round trip on hardened stdio spends one signing nonce once. The
/// challenge gives it back, the same nonce redeems the grant and is spent,
/// and a third call carrying it is refused as a replay.
#[tokio::test]
async fn stdio_x14_round_spends_its_nonce_once() {
    let (challenge, redeemed, replay) = Box::pin(stdio::stdio_x14_signed_round()).await;
    assert!(
        challenge.to_string().contains(X14_PROMPT),
        "no X14 challenge: {challenge}"
    );
    assert!(
        redeemed.pointer("/result/taskId").is_some(),
        "the same nonce did not redeem the grant: {redeemed}"
    );
    assert_eq!(replay["error"]["code"], -32001, "{replay}");
    assert_eq!(
        message(&replay),
        "Nonce replay detected",
        "the spent nonce was not refused as a replay: {replay}"
    );
}
