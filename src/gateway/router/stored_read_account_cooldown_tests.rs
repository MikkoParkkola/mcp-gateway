// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 stored-task cooldown regression (design §3.6): the stored read
//! of a per-user tool no longer meets the error-rate cooldown in its policy
//! (`task_replay.rs`, the stored read's `check_visible_policy`), while its
//! account pre-pass still skips a target the kill switch refuses
//! (`refused_without_catalogue`). The two disagree only on whether to
//! resolve, and that fails closed: the read answers retryable, resolves
//! nothing and serves nothing until the cooldown ends. Uses the parent's
//! fixture.

use super::*;

/// The stored read of the operator's finished `read`, with `read` pushed
/// into error-rate cooldown after it ran: retryable (-32603, `retryable`),
/// no custody read (the pre-pass skipped it), no output and no cooldown
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
    assert_eq!(
        fx.gateway.resolves(),
        reads,
        "the pre-pass resolved a target the kill switch refuses: {read}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sends, "a stored read sent");
    kill_switch.revive_capability(BACKEND, TOOL);
    let served = task_get(&fx, &id).await;
    assert!(
        served.to_string().contains(MARKER),
        "served once the cooldown ended: {served}"
    );
}
