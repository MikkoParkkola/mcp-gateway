// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Route-check-parity P3 (MIK-8149, MIK-8160, MIK-8326): stdio gets the route
//! checks `/mcp` runs, and a surfaced tool withheld from the caller answers as
//! a name that matches no tool. Each row asserts the fixed behaviour and was
//! run red on the release line before the fix. MIK-8149.REQFW.2 (stdio
//! sanitize) is driven by `rows::sanitize_rows`.

use serde_json::{Value, json};

use super::Route;
use super::rows::{BLOCKED, X14_PROMPT, audit_rows, blocked_call, message};
use crate::gateway::router::route_matrix_driver_tests::{self as router, Surfacing};
use crate::gateway::router::route_matrix_x14_nonce_tests as x14;
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

/// MIK-8326.X14.1 and X14.5 on `/mcp`, with the production firewall on: a
/// withheld surfaced task call leaves the audit log a missing name leaves,
/// and is refused before the request firewall (no `request` row), X14 and
/// admission (no idempotency key stored, no task committed). Control: the
/// same call by a caller the tool is visible to writes a `request` row and
/// gets X14's challenge, so the absent row is the refusal's, not the fixture's.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn mcp_withheld_surfaced_task_leaves_what_a_missing_name_leaves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let traced = |key: &'static str, surfacing, file: &str| {
        let audit = dir.path().join(file);
        async move { Box::pin(router::task_submit_traced(key, surfacing, &audit)).await }
    };
    let visible = traced("k-std", Surfacing::On, "visible.jsonl").await;
    assert_visible_control(&visible.body, &visible.events);
    let withheld = traced("k-deny", Surfacing::On, "withheld.jsonl").await;
    let missing = traced("k-std", Surfacing::Off, "missing.jsonl").await;
    assert_eq!(withheld.status, missing.status, "HTTP status differs");
    assert_refused_as_missing(
        (&withheld.body, &withheld.events),
        (&missing.body, &missing.events),
        (
            withheld.backend_calls,
            withheld.stored_keys,
            withheld.admitted,
            withheld.committed,
        ),
    );
}

/// MIK-8326.X14.2 and X14.5 on stdio, with the production firewall on: the
/// sibling of the `/mcp` row above, with the same control.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn stdio_withheld_surfaced_task_leaves_what_a_missing_name_leaves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denying = crate::security::ToolPolicyConfig {
        deny: vec!["echo".to_string()],
        ..crate::security::ToolPolicyConfig::default()
    };
    let traced = |policy, surfacing, file: &str| {
        let audit = dir.path().join(file);
        async move { Box::pin(stdio::stdio_task_traced(policy, surfacing, &audit)).await }
    };
    let visible = traced(None, Surfacing::On, "visible.jsonl").await;
    assert_visible_control(&visible.body, &visible.events);
    let withheld = traced(Some(denying), Surfacing::On, "withheld.jsonl").await;
    let missing = traced(None, Surfacing::Off, "missing.jsonl").await;
    assert_refused_as_missing(
        (&withheld.body, &withheld.events),
        (&missing.body, &missing.events),
        (
            withheld.backend_calls,
            withheld.stored_keys,
            withheld.admitted,
            withheld.committed,
        ),
    );
}

/// The X14.5 control: a visible destructive surfaced task call passes the
/// request firewall (a `request` row) and reaches X14's challenge.
#[cfg(feature = "firewall")]
fn assert_visible_control(body: &serde_json::Value, events: &[String]) {
    assert!(
        events.iter().any(|event| event == "request"),
        "control: no request row for a visible call: {events:?}; {body}"
    );
    assert!(
        body.to_string().contains(X14_PROMPT),
        "control: no X14 challenge for a visible call: {body}"
    );
}

/// A withheld call answered and audited as the missing name was, refused
/// before the request firewall, X14 and admission: no `request` row, no
/// challenge, and no backend call, key (legacy cache or execution admission)
/// or committed task.
#[cfg(feature = "firewall")]
fn assert_refused_as_missing(
    (withheld, withheld_events): (&serde_json::Value, &[String]),
    (missing, missing_events): (&serde_json::Value, &[String]),
    (calls, cached, admitted, tasks): (usize, usize, usize, usize),
) {
    assert_eq!(missing["error"]["code"], -32601, "premise: {missing}");
    assert_eq!(withheld["error"], missing["error"], "{withheld}");
    assert_eq!(withheld_events, missing_events, "audit rows differ");
    assert!(
        !withheld_events.iter().any(|event| event == "request"),
        "the request firewall ran: {withheld_events:?}"
    );
    assert!(!withheld.to_string().contains(X14_PROMPT), "{withheld}");
    assert_eq!(
        (calls, cached, admitted, tasks),
        (0, 0, 0, 0),
        "(backend calls, legacy cached keys, admission entries, tasks): {withheld}"
    );
}

/// [`stdio::stdio_task_read`] on a current-thread runtime, with the warnings
/// it logged on this thread.
fn stdio_logged(
    policy: Option<crate::security::ToolPolicyConfig>,
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
    let denying = crate::security::ToolPolicyConfig {
        deny: vec!["echo".to_string()],
        ..crate::security::ToolPolicyConfig::default()
    };
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

/// MIK-8154 P2 (option (a)): over the real stdio serve loop with sanitizing
/// on, a `gateway_invoke` whose target backend is `passthrough` forwards the
/// NUL: no refusal, and the backend runs. The sanitizer refuses a NUL rather
/// than stripping it, so a run proves it was forwarded.
#[tokio::test]
async fn p2_stdio_passthrough_forwards_a_nul() {
    let (body, calls) = Box::pin(stdio::served_sanitizing_with(true)).await;
    assert!(body.get("error").is_none(), "p2: {body}");
    assert_eq!(calls, 1, "p2: the backend did not run: {body}");
}

/// S2d on stdio (critical coverage of `prepare_signing`'s protocol-field
/// refusal): a control character in `method` is refused before anything
/// reads it, with no id (the envelope may be what is dirty), and nothing
/// reaches the backend. Without the check the sanitize step would strip it
/// into `tools/call` and dispatch.
#[tokio::test]
async fn s2d_stdio_refuses_a_control_character_in_the_method() {
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/\u{7}call", "params": {
        "name": "gateway_list_servers", "arguments": {}}});
    let (body, calls) = Box::pin(stdio::served_sanitizing_call(false, call)).await;
    assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32600)),
        "s2d stdio: {body}"
    );
    assert!(
        body.pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("control characters")),
        "s2d stdio: {body}"
    );
    assert_eq!(body.get("id"), Some(&Value::Null), "s2d stdio: {body}");
    assert_eq!(calls, 0, "s2d stdio: reached the backend");
}

/// The one firewall refusal wording every route answers (P3): an ASI10 block
/// is `-32002` "Anomaly detection blocked: ...", any other block `-32600`
/// "Firewall blocked: ...", and an allowed verdict refuses nothing.
#[test]
fn the_firewall_refusal_is_one_definition() {
    use crate::security::Severity;
    use crate::security::firewall::{
        Finding, FindingLocation, FirewallAction, FirewallVerdict, ScanType,
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
/// firewall control `tune` configures, with that control's own `finding`:
/// `-32600`, a blocking request row, no second send; the first ran.
async fn second_stdio_call_is_refused(
    tune: impl FnOnce(&mut crate::security::firewall::FirewallConfig),
    args: (serde_json::Value, serde_json::Value),
    finding: &str,
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
        message(&second).starts_with(&format!("Firewall blocked: {finding}")),
        "not refused by this control: {second}"
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
    let args = (serde_json::json!({}), serde_json::json!({}));
    second_stdio_call_is_refused(budget, args, "Call budget exceeded:").await;
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
    second_stdio_call_is_refused(tenants, args, "Cross-tenant reach exceeded:").await;
}

/// P3: X14's round trip on hardened stdio spends one signing nonce once. The
/// challenge gives it back, the same nonce redeems the grant and is spent,
/// and a third call carrying it is refused as a replay. A retry under a fresh
/// nonce returns the admitted task without asking again (the stdio owner).
#[tokio::test]
async fn stdio_x14_round_spends_its_nonce_once() {
    let (challenge, redeemed, replay, retried) = Box::pin(stdio::stdio_x14_signed_round()).await;
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
    // The stdio owner's replay: X14 finds the admitted task under the local
    // operator and lets the retry through, so no second question is asked.
    assert!(
        !retried.to_string().contains(X14_PROMPT),
        "an admitted stdio task was challenged again: {retried}"
    );
    assert_eq!(
        retried.pointer("/result/taskId"),
        redeemed.pointer("/result/taskId"),
        "the retry did not get the admitted task: {retried}"
    );
}

/// MIK-8353.E2E.1 (and S1-d): on hardened stdio a task call spends a real X14
/// grant, execution admission then refuses it (the backend is killed), and the
/// nonce stays spent. Oracles: the confirmation ledger grew by exactly one
/// across the redemption (the grant was consumed); the refusal is the kill
/// switch's own; once the backend is revived the same nonce is refused as a
/// nonce replay (an X14 re-challenge fails the row); nothing reached the
/// backend until then; and a fresh nonce's honest round runs it exactly once.
/// Green on base through MIK-8150's `caller.task.is_none()` guard; it must
/// stay green when the refund rework replaces that guard. Mutants: mE2E (the
/// guard removed and the stdio X14 pass returning its witness after the
/// consume) and mE2E-consume (the consume skipped).
#[tokio::test]
async fn stdio_task_refused_after_its_grant_was_consumed_keeps_its_nonce() {
    let seen = Box::pin(stdio::stdio_x14_consumed_then_refused()).await;
    assert!(
        seen.challenge.to_string().contains(X14_PROMPT),
        "premise: no X14 challenge: {}",
        seen.challenge
    );
    let [unasked, asked, redeemed, resent] = seen.ledger;
    assert_eq!(
        asked, unasked,
        "premise: the challenge itself moved the ledger"
    );
    assert_eq!(
        redeemed,
        asked + 1,
        "premise: the redemption did not consume the grant: {}",
        seen.refused
    );
    assert_eq!(resent, redeemed, "the refused re-send consumed a grant");
    assert_eq!(seen.refused["error"]["code"], -32000, "{}", seen.refused);
    assert!(
        message(&seen.refused).contains("kill switch"),
        "premise: admission's kill-switch refusal: {}",
        seen.refused
    );
    assert_eq!(seen.resent["error"]["code"], -32001, "{}", seen.resent);
    assert_eq!(
        message(&seen.resent),
        "Nonce replay detected",
        "a nonce whose grant was consumed was given back: {}",
        seen.resent
    );
    assert_eq!(
        seen.calls_before_honest, 0,
        "the backend ran before the honest round"
    );
    assert_eq!(
        seen.honest["status"], "Completed",
        "control: a fresh nonce's honest round did not complete: {}",
        seen.honest
    );
    assert_eq!(
        seen.calls_after_honest, 1,
        "control: the honest round did not run the backend exactly once"
    );
}

/// MIK-8149.REQFW.1, task form (grok's row): a task-augmented stdio call whose
/// argument the request firewall blocks is refused at the route stage, before
/// any task exists: the firewall's own refusal, no `taskId`, no backend call.
#[tokio::test]
async fn stdio_blocked_task_call_makes_no_task() {
    let (body, calls) = Box::pin(stdio::stdio_blocked_task()).await;
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert!(
        message(&body).starts_with("Firewall blocked: "),
        "not the firewall's refusal: {body}"
    );
    assert!(
        body.pointer("/result/taskId").is_none(),
        "a task was made for a blocked call: {body}"
    );
    assert_eq!(calls, 0, "{body}");
}

/// MIK-8353 H1-mcp: on `/mcp` X14 consumes a task call's grant BEFORE nonce
/// admission, and admission then refuses it (the backend is killed). A refund
/// witness minted at admission would be fresh after that consume, so the
/// nonce must stay spent. Oracles as E2E.1: the ledger grew by one across the
/// redemption; the refusal is the kill switch's own; the same nonce re-sent
/// once revived is a nonce replay; nothing ran before the honest round; a
/// fresh nonce's honest round runs the backend once. Green on base (MIK-8150's
/// task guard). Mutant mH1: the witness minted unconditionally at admission
/// (run with the veto off).
#[tokio::test]
async fn mcp_task_refused_after_its_grant_was_consumed_keeps_its_nonce() {
    let seen = Box::pin(x14::mcp_x14_consumed_then_refused()).await;
    assert!(
        seen.challenge.to_string().contains(X14_PROMPT),
        "premise: no X14 challenge: {}",
        seen.challenge
    );
    let [unasked, asked, redeemed, resent] = seen.ledger;
    assert_eq!(
        asked, unasked,
        "premise: the challenge itself moved the ledger"
    );
    assert_eq!(
        redeemed,
        asked + 1,
        "premise: the redemption did not consume the grant: {}",
        seen.refused
    );
    // Design r4 amendment L1 (lead ruling): a confirmation authorises one
    // attempt, not one success. The re-send carries a new grant, X14 consumes
    // it before the nonce check refuses the replay, and it stays spent:
    // exactly one more, and never the first grant again.
    let a_refused_resend_spends_its_confirmation = redeemed + 1;
    assert_eq!(
        resent, a_refused_resend_spends_its_confirmation,
        "a confirmation refused before dispatch was refunded or spent twice: {}",
        seen.resent
    );
    assert!(
        message(&seen.refused).contains("kill switch"),
        "premise: admission's kill-switch refusal: {}",
        seen.refused
    );
    assert_eq!(
        message(&seen.resent),
        "Nonce replay detected",
        "a nonce whose grant was consumed was given back: {}",
        seen.resent
    );
    assert_eq!(
        seen.calls_before_honest, 0,
        "the backend ran before the honest round"
    );
    assert_eq!(
        seen.honest_status, "completed",
        "control: the honest round did not complete: {}",
        seen.honest
    );
    assert_eq!(
        seen.calls_after_honest, 1,
        "control: the honest round did not run the backend exactly once"
    );
}

/// MIK-8353 H1-mcp-control: the same admission refusal of a signed task call
/// with NO grant consumed (nothing for X14 to ask) gives the nonce back: once
/// revived, the same nonce is accepted once (its task runs the backend) and a
/// third send is a replay. Red on base: MIK-8150 keeps every task call's nonce
/// spent. Kills: the refund site removed.
#[tokio::test]
async fn mcp_task_refused_without_a_grant_gives_its_nonce_back() {
    let (refused, resent, status, third, calls) =
        Box::pin(x14::mcp_task_refused_without_grant()).await;
    assert_eq!(
        status, "completed",
        "the re-sent task did not complete: {resent}"
    );
    assert!(
        !refused.to_string().contains(X14_PROMPT),
        "premise: X14 asked, so a grant path was taken: {refused}"
    );
    assert!(
        message(&refused).contains("kill switch"),
        "premise: admission's kill-switch refusal: {refused}"
    );
    assert!(
        resent.pointer("/result/taskId").is_some(),
        "the refused task call kept its nonce: {resent}"
    );
    assert_eq!(calls, 1, "the re-sent task did not run the backend once");
    assert_eq!(
        message(&third),
        "Nonce replay detected",
        "the nonce was given back twice: {third}"
    );
}

/// MIK-8353 STDIO-TWIN (NONCEFX.7, pairs with E2E.1): on hardened stdio a signed
/// task call that X14 has nothing to ask (a harmless tool, warm catalogue),
/// refused by execution admission with nothing consumed, gets its nonce back:
/// once revived, the same nonce is accepted once (its task runs the backend
/// once) and a third send is a replay. Red on base (MIK-8150's task guard).
/// Mutants: mNoMint-stdio (no stdio witness) and mGuard (the guard kept).
#[tokio::test]
async fn stdio_task_refused_without_a_grant_gives_its_nonce_back() {
    let (refused, resent, status, third, calls) =
        Box::pin(stdio::stdio_task_refused_without_a_grant()).await;
    assert_eq!(
        status, "Completed",
        "the re-sent task did not complete: {resent}"
    );
    assert!(
        !refused.to_string().contains(X14_PROMPT),
        "premise: X14 asked, so a grant path was taken: {refused}"
    );
    assert!(
        message(&refused).contains("kill switch"),
        "premise: admission's kill-switch refusal: {refused}"
    );
    assert!(
        resent.pointer("/result/taskId").is_some(),
        "the refused task call kept its nonce: {resent}"
    );
    assert_eq!(calls, 1, "the re-sent task did not run the backend once");
    assert_eq!(
        message(&third),
        "Nonce replay detected",
        "the nonce was given back twice: {third}"
    );
}

/// MIK-8353 STDIO-SETTLE (r4: stdio settles in exactly one place): through
/// the staged dispatch and `judge_and_commit`, a signed call refused before its
/// backend gives its nonce back exactly once; the honest re-send under it is
/// delivered and gives nothing back; a third send is a replay and gives
/// nothing back. Mutants: mSettle-0 (the settle's give-back removed) and
/// mSettle-2 (a second give-back added in the delivery tail).
#[test]
fn stdio_settles_a_refund_once_through_the_delivery_tail() {
    let [refused, resent, third] = stdio::stdio_refund_through_delivery();
    assert!(
        !refused.delivers_result,
        "premise: the forged continuation was refused"
    );
    assert_eq!(
        refused.given_back, 1,
        "the refusal's nonce was not given back exactly once"
    );
    assert!(
        resent.delivers_result,
        "the honest re-send was refused: the nonce was kept"
    );
    assert_eq!(resent.given_back, 0, "a delivered call gave its nonce back");
    assert!(!third.delivers_result, "the nonce was given back twice");
    assert_eq!(third.given_back, 0, "a replay refusal gave a nonce back");
}
