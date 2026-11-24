// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record's judges on fixed shapes: each accepted shape passes, and each
//! refused shape is refused for the reason it names.
use std::time::Duration;

use super::*;

/// A failed kill; the judges read no errno.
const FAILED: Sent = Sent::KillFailed { errno: 1 };

const LATE: Sent = Sent::SkipLate {
    late: Duration::from_secs(1),
};
const EARLY: Sent = Sent::SkipLate {
    late: Duration::ZERO,
};
/// The threshold's two sides, as literals: the slack is 6 s - 5 s - 0.1 s.
const JUST_OVER: Sent = Sent::SkipLate {
    // limit-under-test (injected-clock): a recorded lateness handed straight to the pure judge
    late: Duration::from_millis(901),
};
const AT_THRESHOLD: Sent = Sent::SkipLate {
    // limit-under-test (injected-clock): a recorded lateness handed straight to the pure judge
    late: Duration::from_millis(900),
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
    use Sent::{Kill, KillGone, LeaderGone, Term, Unproven};
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
            (&[Term, KillGone, Kill], None),
            (&[Term, Kill, KillGone], None),
            (&[Term, Kill, KillGone, KillGone], None),
            (&[LATE, KillGone], None),
            (&[JUST_OVER, Kill], None),
            (&[AT_THRESHOLD, Kill], Some("under the")),
            (&[JUST_OVER, KillGone], None),
            (&[AT_THRESHOLD, KillGone], Some("under the")),
            (&[Term, FAILED], Some("a kill failed")),
            (&[Term, FAILED, KillGone], Some("a kill failed")),
            (&[KillGone, Term, KillGone], Some("not one SIGTERM")),
            (&[Kill], Some("no recorded reason")),
            (&[KillGone], Some("no recorded reason")),
            (&[LeaderGone, KillGone], Some("leader was already gone")),
            (&[LATE, Term, Kill], Some("not one SIGTERM")),
            (&[LeaderGone, Term, Kill], Some("not one SIGTERM")),
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
fn the_skip_rule_accepts_the_kill_alone() {
    use Sent::{Kill, KillGone, LeaderGone, Term, Unproven};
    check(
        judge_kill_without_term,
        &[
            (&[Kill], None),
            (&[Kill, Kill], None),
            (&[EARLY, Kill], None),
            (&[KillGone], None),
            (&[Kill, KillGone], None),
            (&[FAILED], Some("a kill failed")),
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
    use EsrchOn::{Linux, MacOs};
    use rustix::io::Errno;
    const SRCH: Errno = Errno::SRCH;
    const PERM: Errno = Errno::PERM;
    const INVAL: Errno = Errno::INVAL;
    const ACCES: Errno = Errno::ACCESS;
    let failed = |e: Errno| Sent::KillFailed {
        errno: e.raw_os_error(),
    };
    // (errno, or None for Ok; leader seen exited; leader's own group; a live
    // member; host; recorded)
    let cases: [(Option<Errno>, bool, bool, bool, EsrchOn, Sent); 16] = [
        (None, false, true, true, Linux, Sent::Kill),
        (None, true, true, false, MacOs, Sent::Kill),
        (Some(SRCH), true, true, true, Linux, Sent::KillGone),
        (Some(SRCH), true, true, true, MacOs, Sent::KillGone),
        (Some(SRCH), false, true, true, Linux, failed(SRCH)),
        // macOS: the group is ending before the leader reads exited.
        (Some(SRCH), false, true, true, MacOs, Sent::KillGone),
        // A group that is not the leader's own is never gone, on any host.
        (Some(SRCH), false, false, false, MacOs, failed(SRCH)),
        (Some(SRCH), true, false, false, Linux, failed(SRCH)),
        // macOS EPERM (members found, none signalled): gone only with no live
        // member left, which BSD killpg answers for a group of zombies.
        (Some(PERM), false, true, false, MacOs, Sent::KillGone),
        // Linux signals zombies, so its EPERM is always a member beyond reach.
        (Some(PERM), true, true, false, Linux, failed(PERM)),
        (Some(PERM), true, true, true, MacOs, failed(PERM)),
        (Some(PERM), false, true, true, Linux, failed(PERM)),
        (Some(PERM), false, false, false, MacOs, failed(PERM)),
        // Any other errno is a failed kill that names itself.
        (Some(INVAL), true, true, false, MacOs, failed(INVAL)),
        (Some(INVAL), true, true, false, Linux, failed(INVAL)),
        (Some(ACCES), false, true, false, MacOs, failed(ACCES)),
    ];
    for (errno, exited, own, live, host, want) in cases {
        let sent = errno.map_or(Ok(()), |e| {
            Err(std::io::Error::from_raw_os_error(e.raw_os_error()))
        });
        assert_eq!(
            classify(&sent, exited, own, live, host),
            want,
            "{sent:?}, exited: {exited}, own group: {own}, live member: {live}, {host:?}"
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

/// Kill what a row left of `tree`'s group through its owner, the wrapper, and
/// reap its leader: an injected kill sent nothing, and the closed gate sends
/// nothing on drop.
async fn end_tree(mut tree: super::super::ChildTree) {
    let _ = tree.wrapper.start_kill();
    tokio::time::timeout(crate::test_wait::HANG_BOUND, tree.wrapper.wait())
        .await
        .expect("the leader is reaped within the hang bound")
        .expect("wait for the leader");
}

/// A group kill answering ESRCH while the leader still runs (it named a group the
/// leader is not in) is a failed kill, never the kill of a group already gone.
/// Linux only: macOS answers ESRCH for its own ending group too (see `EsrchOn`).
/// The group the kill names comes from shared spawn and kill code, so this row
/// catches a wrong-group bug for every platform.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn esrch_with_the_leader_running_is_a_failed_kill() {
    let (mut tree, pid) = running_tree();
    arm(pid);
    inject(pid, Esrch::Only);
    tree.start_kill();
    assert_eq!(
        take(pid),
        [Sent::KillFailed {
            errno: rustix::io::Errno::SRCH.raw_os_error()
        }]
    );
    end_tree(tree).await;
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
    end_tree(tree).await;
}
