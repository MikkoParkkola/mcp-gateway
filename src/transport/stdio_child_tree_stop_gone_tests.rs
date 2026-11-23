// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! macOS's answer to a group kill that finds every member exited (ESRCH),
//! injected on any host: the record keeps it as the kill of a group already
//! gone, which the record's judge takes as the kill. Helpers are the
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
    signal_log::assert_gone_kill_counts(pid, "a group gone at the kill").await;
}

/// macOS's answer for a tree that resists SIGTERM, on any host: the sweep
/// SIGKILLs the leader just before the group kill, so that kill can find
/// every member exited (ESRCH once the leader is dead, injected here); the
/// rule still takes it as the kill.
#[tokio::test]
async fn a_resisting_trees_kill_that_finds_the_group_gone_counts_as_the_kill() {
    let (w, t) = started_unhurried(&resists_term(), None).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    signal_log::arm(pid);
    signal_log::inject(pid, signal_log::Esrch::AfterKillingLeader);
    tokio::time::timeout(HANG_BOUND, t.close())
        .await
        .expect("close returns within the hang bound")
        .expect("close");
    signal_log::assert_gone_kill_counts(pid, "a resisting tree gone at the kill").await;
    gone(child).await;
}

/// macOS's gap, on any host: a resisting tree's group kills answer ESRCH while
/// the record still reads the leader running for `steps` kills. Each is the
/// kill of a group already gone on macOS rules, and gone is not forgotten:
/// close returns in the bound, the leader is reaped (no zombie left) and no
/// member of the tree survives.
async fn a_gap_of(steps: u8) {
    use rustix::process::{WaitId, WaitIdOptions, waitid};
    let what = format!("a {steps}-step gap");
    let (w, t) = started_unhurried(&resists_term(), None).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    signal_log::arm(pid);
    signal_log::inject(pid, signal_log::Esrch::MacGap { steps });
    tokio::time::timeout(HANG_BOUND, t.close())
        .await
        .expect("close returns within the hang bound")
        .expect("close");
    signal_log::assert_gone_kill_counts(pid, &what).await;
    assert_killed(pid).await;
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    assert_eq!(
        waitid(WaitId::Pid(pid), options).err(),
        Some(rustix::io::Errno::CHILD),
        "{what}: the leader is reaped, no zombie left"
    );
    gone(child).await;
}

#[tokio::test]
async fn a_one_step_gap_still_counts_as_the_kill() {
    a_gap_of(1).await;
}

#[tokio::test]
async fn a_three_step_gap_still_counts_as_the_kill() {
    a_gap_of(3).await;
}

#[tokio::test]
async fn a_five_step_gap_still_counts_as_the_kill() {
    a_gap_of(5).await;
}
