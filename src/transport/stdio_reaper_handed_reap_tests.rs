// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use std::os::unix::process::ExitStatusExt;

/// A fresh deadline tracking one handover already in `state`.
fn tracking(state: Reaped) -> (StopDeadline, watch::Sender<Reaped>) {
    let deadline = StopDeadline::default();
    let (sender, receiver) = watch::channel(state);
    deadline.track(receiver);
    (deadline, sender)
}

#[test]
fn only_a_handover_reaped_with_a_status_counts_as_reaped() {
    assert!(
        !StopDeadline::default().handed_all_reaped(),
        "no handover is no evidence of a reap"
    );
    let (gave_up, _sender) = tracking(Reaped::Done(None));
    assert!(
        !gave_up.handed_all_reaped(),
        "an unreaped give-up counted as a reap"
    );
    let status = std::process::ExitStatus::from_raw(9);
    let (reaped, _sender) = tracking(Reaped::Done(Some(status)));
    assert!(
        reaped.handed_all_reaped(),
        "a reap with an exit status did not count"
    );
    // Every handed tree, not any: one still pending beside one reaped is
    // not all reaped, until it is reaped too. (`track` keeps only pending
    // receivers when it adds one, so the pending one goes in first.)
    let (both, pending) = tracking(Reaped::Pending);
    let (_reaped_sender, reaped_receiver) = watch::channel(Reaped::Done(Some(status)));
    both.track(reaped_receiver);
    assert!(
        !both.handed_all_reaped(),
        "one reaped handover beside a pending one counted as all reaped"
    );
    pending
        .send(Reaped::Done(Some(status)))
        .expect("the deadline holds the receiver");
    assert!(
        both.handed_all_reaped(),
        "two reaped handovers did not count"
    );
}
