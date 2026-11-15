// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record's judges on fixed shapes: each accepted shape passes, and each
//! refused shape is refused for the reason it names.
use std::time::Duration;

use super::*;

const LATE: Sent = Sent::SkipLate {
    late: Duration::from_secs(1),
};
const EARLY: Sent = Sent::SkipLate {
    late: Duration::ZERO,
};

/// `judge` on each shape: `None` must pass, `Some(reason)` must be refused
/// with a message containing `reason`.
fn check(judge: fn(&[Sent]) -> Result<(), String>, cases: &[(&[Sent], Option<&str>)]) {
    for (sent, want) in cases {
        match (judge(sent), want) {
            (Ok(()), None) => {}
            (Err(why), Some(reason)) => assert!(
                why.contains(reason),
                "{sent:?}: refused as {why:?}, expected {reason:?}"
            ),
            (got, want) => panic!("{sent:?}: got {got:?}, expected {want:?}"),
        }
    }
}

#[test]
fn the_live_rule_accepts_sigterm_then_kill_or_a_justified_late_skip_only() {
    use Sent::{Kill, KillFailed, KillGone, LeaderGone, Term, Unproven};
    check(
        judge_term_then_kill,
        &[
            (&[Term, Kill], None),
            (&[Term, Kill, Kill], None),
            (&[Unproven, Term, Kill], None),
            (&[LATE, Kill], None),
            (&[LATE, LATE, Kill, Kill], None),
            (&[Term, KillGone], None),
            (&[Term, KillGone, KillGone], None),
            (&[Term, Kill, KillGone], None),
            (&[LATE, KillGone], None),
            (&[Term, KillFailed], Some("a kill failed")),
            (&[Term, KillFailed, KillGone], Some("a kill failed")),
            (&[KillGone, Term, KillGone], Some("not one SIGTERM")),
            (&[Kill], Some("no recorded reason")),
            (&[Unproven, Kill], Some("ownership was not shown")),
            (&[Unproven, LATE, Kill], Some("ownership was not shown")),
            (&[LeaderGone, Kill], Some("leader was already gone")),
            (&[EARLY, Kill], Some("under the")),
            (&[LATE, EARLY, Kill], Some("under the")),
            (&[EARLY, Term, Kill], Some("not one SIGTERM")),
            (&[Kill, Term, Kill], Some("not one SIGTERM")),
            (&[Term, Kill, Term], Some("not one SIGTERM")),
            (&[Term], Some("not one SIGTERM")),
            (&[LATE], Some("no kill after the skip")),
        ],
    );
}

#[test]
fn the_strict_rule_accepts_the_normal_path_only() {
    use Sent::{Kill, KillFailed, KillGone, LeaderGone, Term, Unproven};
    check(
        judge_strict,
        &[
            (&[Term, Kill], None),
            (&[Unproven, Term, Kill], None),
            (&[LATE, Kill], Some("not one SIGTERM")),
            (&[LATE, Term, Kill], Some("not one SIGTERM")),
            (&[LeaderGone, Term, Kill], Some("not one SIGTERM")),
            (&[Kill], Some("not one SIGTERM")),
            (&[Term, KillGone], Some("not one SIGTERM")),
            (&[Term, KillGone, Kill], Some("not one SIGTERM")),
            (&[Term, Kill, KillGone], None),
            (&[Term, Kill, KillGone, KillGone], None),
            (&[Term, KillFailed], Some("a kill failed")),
        ],
    );
}

#[test]
fn the_skip_rule_accepts_the_kill_alone() {
    use Sent::{Kill, KillFailed, KillGone, LeaderGone, Term, Unproven};
    check(
        judge_kill_without_term,
        &[
            (&[Kill], None),
            (&[Kill, Kill], None),
            (&[EARLY, Kill], None),
            (&[KillGone], None),
            (&[Kill, KillGone], None),
            (&[KillFailed], Some("a kill failed")),
            (&[Term, KillGone], Some("not the kill alone")),
            (&[Term, Kill], Some("not the kill alone")),
            (&[], Some("not the kill alone")),
            (&[Unproven, Kill], Some("another reason")),
            (&[LeaderGone, Kill], Some("another reason")),
        ],
    );
}

#[test]
fn a_kill_records_its_outcome() {
    use rustix::io::Errno;
    let err = |e: Errno| Err(std::io::Error::from_raw_os_error(e.raw_os_error()));
    let cases: [(std::io::Result<()>, bool, Sent); 5] = [
        (Ok(()), false, Sent::Kill),
        (Ok(()), true, Sent::Kill),
        (err(Errno::SRCH), true, Sent::KillGone),
        (err(Errno::SRCH), false, Sent::KillFailed),
        (err(Errno::PERM), true, Sent::KillFailed),
    ];
    for (sent, exited, want) in cases {
        assert_eq!(
            kill_outcome(&sent, exited),
            want,
            "{sent:?}, exited: {exited}"
        );
    }
}

/// A tree whose leader loops until killed, and the leader's pid.
fn running_tree() -> (super::super::ChildTree, Pid) {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.args(["-c", "while :; do sleep 0.05; done"]);
    let tree =
        super::super::ChildTree::new(super::super::super::spawn_in_own_tree(cmd).expect("spawn"));
    let pid = tree.pid.expect("the leader's pid");
    (tree, pid)
}

/// Kill what a row left of `tree`'s group and reap its leader: an injected kill
/// sent nothing, and the closed gate sends nothing on drop.
async fn end_tree(mut tree: super::super::ChildTree, pid: Pid) {
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    tokio::time::timeout(crate::test_wait::HANG_BOUND, tree.wrapper.wait())
        .await
        .expect("the leader is reaped within the hang bound")
        .expect("wait for the leader");
}

/// A group kill answering ESRCH while the leader still runs (it named a group the
/// leader is not in) is a failed kill, never the kill of a group already gone.
#[tokio::test]
async fn esrch_with_the_leader_running_is_a_failed_kill() {
    let (mut tree, pid) = running_tree();
    arm(pid);
    inject(pid, Esrch::Only);
    tree.start_kill();
    assert_eq!(take(pid), [Sent::KillFailed]);
    end_tree(tree, pid).await;
}

/// A group kill answering ESRCH after the leader died between the check and the
/// send, as the descendant sweep's SIGKILL can land, is the kill of a group
/// already gone: the leader reads exited right after the ESRCH.
#[tokio::test]
async fn esrch_after_the_leader_died_mid_send_is_a_gone_kill() {
    let (mut tree, pid) = running_tree();
    arm(pid);
    inject(pid, Esrch::AfterKillingLeader);
    tree.start_kill();
    assert_eq!(take(pid), [Sent::KillGone]);
    end_tree(tree, pid).await;
}
