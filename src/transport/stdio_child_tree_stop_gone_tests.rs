// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! macOS's answer to a group kill that finds every member exited (ESRCH),
//! injected on any host: the record keeps it as the kill of a group already
//! gone, which the live and strict rules take as the kill. Helpers are the
//! parent modules'.
use super::*;

/// macOS's answer, on any host: a backend that exits on SIGTERM leaves only
/// exited members, so the kill that follows finds no process (ESRCH, injected
/// here) and is recorded as the kill of a group already gone, which the live
/// rule takes as the kill.
#[tokio::test]
async fn a_kill_that_finds_the_group_gone_after_sigterm_counts_as_the_kill() {
    let (w, t) = started(
        "trap 'exit 0' TERM\necho ready > ready.mark\nwhile :; do sleep 0.05; done",
        None,
    )
    .await;
    poll_until("the TERM handler is installed", || {
        w.path().join("ready.mark").exists()
    })
    .await;
    let pid = leader(&t).await;
    signal_log::arm(pid);
    signal_log::inject(pid, signal_log::Esrch::Only);
    t.close().await.expect("close");
    signal_log::assert_gone_kill_counts(pid, "a group gone at the kill", signal_log::Rule::Live)
        .await;
}

/// macOS's answer for a tree that resists SIGTERM, on any host: the sweep
/// SIGKILLs the leader just before the group kill, so that kill can find
/// every member exited (ESRCH once the leader is dead, injected here); the
/// strict rule still takes it as the kill.
#[tokio::test]
async fn a_resisting_trees_kill_that_finds_the_group_gone_passes_the_strict_rule() {
    let (w, t) = started_unhurried(&resists_term(), None).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    signal_log::arm(pid);
    signal_log::inject(pid, signal_log::Esrch::AfterKillingLeader);
    tokio::time::timeout(HANG_BOUND, t.close())
        .await
        .expect("close returns within the hang bound")
        .expect("close");
    signal_log::assert_gone_kill_counts(
        pid,
        "a resisting tree gone at the kill",
        signal_log::Rule::Strict,
    )
    .await;
    gone(child).await;
}
