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
    use Sent::{Kill, LeaderGone, Term, Unproven};
    check(
        judge_term_then_kill,
        &[
            (&[Term, Kill], None),
            (&[Term, Kill, Kill], None),
            (&[Unproven, Term, Kill], None),
            (&[LATE, Kill], None),
            (&[LATE, LATE, Kill, Kill], None),
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
    use Sent::{Kill, LeaderGone, Term, Unproven};
    check(
        judge_strict,
        &[
            (&[Term, Kill], None),
            (&[Unproven, Term, Kill], None),
            (&[LATE, Kill], Some("not one SIGTERM")),
            (&[LATE, Term, Kill], Some("not one SIGTERM")),
            (&[LeaderGone, Term, Kill], Some("not one SIGTERM")),
            (&[Kill], Some("not one SIGTERM")),
        ],
    );
}

#[test]
fn the_skip_rule_accepts_the_kill_alone() {
    use Sent::{Kill, LeaderGone, Term, Unproven};
    check(
        judge_kill_without_term,
        &[
            (&[Kill], None),
            (&[Kill, Kill], None),
            (&[EARLY, Kill], None),
            (&[Term, Kill], Some("not the kill alone")),
            (&[], Some("not the kill alone")),
            (&[Unproven, Kill], Some("another reason")),
            (&[LeaderGone, Kill], Some("another reason")),
        ],
    );
}
