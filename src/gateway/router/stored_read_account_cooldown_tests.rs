// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 stored-task cooldown regression (design §3.6): the stored read
//! of a per-user tool no longer meets the error-rate cooldown in its policy
//! (`task_replay.rs`, the stored read's `check_visible_policy`), and since
//! MIK-8474 neither does its account pre-pass: the cooling target is
//! account-filled (one custody read), so a caller with no view is answered
//! as a missing name, and the cooldown is met last, answering retryable,
//! sending nothing and serving nothing until it ends. Uses the parent's
//! fixture.

use super::*;

/// The stored read of the operator's finished `read`, with `read` pushed
/// into error-rate cooldown after it ran: retryable (-32603, `retryable`),
/// exactly one custody read (the pre-pass's, MIK-8474), no output and no cooldown
/// text. Once the cooldown is cleared the same read serves. RED at base: the
/// stored read's policy answers the cooldown refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stored_read_of_a_cooling_per_user_tool_answers_retryable_then_serves() {
    let fx = fixture().await;
    let id = finished(&fx, "8439-cooldown").await;
    let kill_switch = fx.state.meta_mcp.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
    let (reads, sends) = (fx.gateway.resolves(), fx.gateway.tool_calls().len());
    let read = task_get(&fx, &id).await;
    // Whether the answer came through the broken-invariant branch
    // (`unfilled_outcome_read`): printed for the fix's review, not asserted.
    eprintln!(
        "unfilled_outcome_reads: {}",
        fx.gateway
            .backends()
            .get(BACKEND)
            .expect("the backend")
            .unfilled_outcome_reads
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(
        !read.to_string().contains("temporarily disabled"),
        "the stored read met the cooldown in its policy: {read}"
    );
    assert_retryable(&read, "cooldown");
    // MIK-8474: telling a revoked caller from this one needs the custody
    // read, so the cooling target is account-filled: exactly one.
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "the pre-pass's one custody read: {read}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sends, "a stored read sent");
    kill_switch.revive_capability(BACKEND, TOOL);
    let served = task_get(&fx, &id).await;
    assert!(
        served.to_string().contains(MARKER),
        "served once the cooldown ended: {served}"
    );
}

use super::super::assert_answers_as_absent;

/// Push `read` into error-rate cooldown on the kill switch.
fn cool(fx: &Fx) -> std::sync::Arc<crate::kill_switch::KillSwitch> {
    let kill_switch = fx.state.meta_mcp.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
    kill_switch
}

/// MIK-8474 (STOREDCD.1/.2): a caller whose grant was revoked reads a stored
/// task of a tool now in error-rate cooldown. The answer must equal a missing
/// name's, as `l4` does without the cooldown: a retryable -32603 would tell a
/// no-view caller that a hidden per-user tool exists. No custody read beyond
/// the pre-pass's one (it is what tells `NoView` from unfilled), nothing sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_caller_reading_a_cooling_tools_task_answers_as_a_missing_name() {
    let fx = fixture().await;
    let id = finished(&fx, "8474-revoked-cooldown").await;
    fx.gateway.revoke_operator_grant().await;
    list_tools(&fx).await;
    cool(&fx);
    let (reads, sends) = (fx.gateway.resolves(), fx.gateway.tool_calls().len());
    let read = task_get(&fx, &id).await;
    eprintln!("MIK-8474 revoked+cooling read: {read}");
    eprintln!(
        "MIK-8474 missing-name twin: {}",
        super::super::absent_twin(&fx).await
    );
    assert_answers_as_absent(&fx, &read, "MIK-8474").await;
    assert_absent(&read, "MIK-8474");
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "MIK-8474: the pre-pass's one custody read tells NoView from unfilled"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sends, "a stored read sent");
}

/// MIK-8474 (STOREDCD.3, control): the same cooling tool read by a caller
/// WITH a view keeps the retryable answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_with_a_view_reading_a_cooling_tools_task_still_answers_retryable() {
    let fx = fixture().await;
    let id = finished(&fx, "8474-view-cooldown").await;
    cool(&fx);
    let sends = fx.gateway.tool_calls().len();
    assert_retryable(&task_get(&fx, &id).await, "MIK-8474 control");
    assert_eq!(fx.gateway.tool_calls().len(), sends, "a stored read sent");
}
