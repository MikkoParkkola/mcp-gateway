// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A tree handed over at the HTTP backend stage's entry: its grace is cut
//! once, at the stage's deadline. Helpers are the parent modules'.
use super::*;

/// R4b (HANDOVER.4): a tree handed over at the HTTP backend
/// stage's entry, planned from the stage's budget under its unhurried
/// deadline, is cut once: SIGTERM goes out at entry + its EOF wait and the
/// kill lands no earlier than the deadline less one kill reserve. Red if the
/// cut takes the reserve twice.
#[tokio::test]
async fn a_handed_trees_grace_is_cut_once_at_the_stage_deadline() {
    use super::super::super::super::reaper::{KILL_RESERVE, graceful_ending};
    let (w, t) = started(
        "trap '' TERM\necho ready > ready.mark\nwhile :; do sleep 0.05; done",
        None,
    )
    .await;
    let end = EndOnDrop::new(&t);
    poll_until("the TERM handler is installed", || {
        w.path().join("ready.mark").exists()
    })
    .await;
    with_tree(&t, |tree| {
        let entry = std::time::Instant::now();
        let waits = Duration::from_millis(400);
        let stage_end = entry + KILL_RESERVE + waits;
        end.deadline().move_earlier(stage_end);
        let ending = graceful_ending(KILL_RESERVE + waits, true, Some(end.deadline().as_ref()));
        let Ending::Graceful { eof, .. } = ending else {
            panic!("premise: a graceful plan, got {ending:?}");
        };
        tree.set_ending(ending, Some(Arc::clone(end.deadline())));
        let kill = stage_end
            .checked_sub(KILL_RESERVE)
            .expect("the stage keeps its kill reserve");
        let ms = Duration::from_millis(1);
        assert!(matches!(tree.reap_step(entry), Reap::Pending));
        tree.reap_step((entry + eof).checked_sub(ms).expect("after entry"));
        assert_eq!(
            tree.term_signals_sent, 0,
            "SIGTERM before its EOF wait ended"
        );
        tree.reap_step(entry + eof);
        assert_eq!(
            tree.term_signals_sent, 1,
            "SIGTERM did not go out at entry + its EOF wait"
        );
        tree.reap_step(kill.checked_sub(ms).expect("after entry"));
        assert_eq!(
            tree.group_signals_sent, 0,
            "killed before the stage deadline less one reserve"
        );
        tree.reap_step(kill);
        assert!(
            tree.group_signals_sent > 0,
            "the kill did not land at the stage deadline less one reserve"
        );
    })
    .await;
    tokio::time::timeout(Duration::from_secs(30), t.close())
        .await
        .expect("tree reaped")
        .expect("close");
}

/// A cut plan's on-time SIGTERM keeps the cut's last third before the kill,
/// on synthetic steps. The signal-record rows prove the order on a real stop;
/// this proves the interval, which a child's own mark showed only when a
/// loaded host scheduled the child in time. Red if a cut kills at the SIGTERM
/// step, or moves the kill off the cut.
#[tokio::test]
async fn a_cut_plans_on_time_sigterm_keeps_its_third_before_the_kill() {
    let (w, t) = started(IGNORES_TERM_READY, None).await;
    let end = EndOnDrop::new(&t);
    let t0 = planned_tree(&t, &w, &end).await;
    // Waits cut from 2 s to 1.5 s, applied at t0 + 100 ms: a third of the
    // 1.4 s left keeps SIGTERM at its planned 1 s, the kill moves to 1.5 s.
    end.deadline().move_earlier(
        t0 + super::super::super::super::reaper::KILL_RESERVE + Duration::from_millis(1500),
    );
    with_tree(&t, |tree| {
        let term_at = t0 + Duration::from_secs(1);
        let kill_at = t0 + Duration::from_millis(1500);
        tree.reap_step(t0 + Duration::from_millis(100));
        tree.reap_step(before(term_at, Duration::from_millis(1)));
        assert_eq!(tree.term_signals_sent, 0, "no SIGTERM before its instant");
        tree.reap_step(term_at);
        assert_eq!(tree.term_signals_sent, 1, "the on-time step sent SIGTERM");
        tree.reap_step(before(kill_at, Duration::from_millis(1)));
        assert_eq!(tree.group_signals_sent, 0, "the SIGTERM keeps its third");
        tree.reap_step(kill_at);
        assert!(tree.group_signals_sent > 0, "the kill lands at the cut");
    })
    .await;
}

#[cfg(target_os = "linux")]
#[path = "stdio_child_tree_snapshot_measure_tests.rs"]
mod measure;
