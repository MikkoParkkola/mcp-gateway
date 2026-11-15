// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The restart status board: the order guards, a model over every short call
//! sequence, the cancel reasons and the wire form.

use super::*;
use crate::gateway::restart_floor::{CancelReason, FloorOwner, FloorStage};

const CHECKPOINT_DL: u64 = 1_000;
const STOP_DL: u64 = 2_000;

fn floor() -> RestartCancel {
    RestartCancel::Floor(Cancelled {
        owner: FloorOwner::Health,
        stage: FloorStage::Checkpoint,
        reason: CancelReason::SaveFailed,
    })
}

/// The current record's attempt id (0 before any accept): every call these
/// rows make targets the current attempt, as every call did before ids.
fn cur(board: &RestartBoard) -> u64 {
    board.status().map_or(0, |s| s.id)
}

fn phase(board: &RestartBoard) -> Option<RestartPhase> {
    board.status().map(|s| s.phase)
}

/// A board at Checkpoint, committed when `commit` is set.
fn at_checkpoint(commit: bool) -> RestartBoard {
    let board = RestartBoard::default();
    board.accept();
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    if commit {
        board.commit(cur(&board), STOP_DL);
    }
    board
}

#[test]
fn b1_restarting_before_commit_is_ignored_and_logged_once() {
    let board = at_checkpoint(false);
    let ((), logs) = crate::test_log_capture::capture_warnings(|| board.restarting(cur(&board)));
    assert_eq!(phase(&board), Some(RestartPhase::Checkpoint));
    assert_eq!(logs.matches("before commit").count(), 1, "{logs}");
    board.commit(cur(&board), STOP_DL);
    let ((), logs) = crate::test_log_capture::capture_warnings(|| board.restarting(cur(&board)));
    assert_eq!(phase(&board), Some(RestartPhase::Restarting));
    assert!(
        logs.is_empty(),
        "the committed transition logs nothing: {logs}"
    );
}

#[test]
fn b2_checkpoint_only_from_accepted() {
    let board = RestartBoard::default();
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    assert_eq!(board.status(), None);
    board.accept();
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    assert_eq!(phase(&board), Some(RestartPhase::Checkpoint));
    board.cancel(cur(&board), RestartCancel::Recheck);
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    assert_eq!(phase(&board), Some(RestartPhase::Cancelled));
}

#[test]
fn b2_commit_only_from_checkpoint_and_switches_deadline() {
    let board = RestartBoard::default();
    board.accept();
    board.commit(cur(&board), STOP_DL);
    let accepted = board.status().expect("a record");
    assert_eq!(
        (accepted.phase, accepted.deadline_unix_ms),
        (RestartPhase::Accepted, None)
    );
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    board.commit(cur(&board), STOP_DL);
    let committed = board.status().expect("a record");
    assert_eq!(
        (committed.phase, committed.deadline_unix_ms),
        (RestartPhase::Checkpoint, Some(STOP_DL))
    );
}

#[test]
fn b2_cancel_only_before_commit() {
    let board = at_checkpoint(true);
    board.cancel(cur(&board), RestartCancel::StopSignal);
    let record = board.status().expect("a record");
    assert_eq!(
        (record.phase, record.cancel),
        (RestartPhase::Checkpoint, None)
    );
    let early = RestartBoard::default();
    early.accept();
    early.cancel(cur(&early), RestartCancel::AuditRefused);
    let record = early.status().expect("a record");
    assert_eq!(
        (record.phase, record.cancel),
        (RestartPhase::Cancelled, Some(RestartCancel::AuditRefused))
    );
}

#[test]
fn b2_second_cancel_is_a_no_op() {
    let board = at_checkpoint(false);
    board.cancel(cur(&board), RestartCancel::Recheck);
    board.cancel(cur(&board), RestartCancel::StopSignal);
    assert_eq!(
        board.status().expect("a record").cancel,
        Some(RestartCancel::Recheck)
    );
}

#[test]
fn b2_stop_stages_are_silent_before_commit_and_after_cancel() {
    for cancelled in [false, true] {
        let board = at_checkpoint(false);
        if cancelled {
            board.cancel(cur(&board), RestartCancel::StopSignal);
        }
        let before = board.status();
        board.saving(cur(&board));
        board.draining(cur(&board));
        board.set_remaining_calls(cur(&board), 7);
        assert_eq!(board.status(), before, "cancelled: {cancelled}");
    }
}

#[test]
fn b2_forward_by_rank_only() {
    let board = at_checkpoint(true);
    board.restarting(cur(&board));
    board.draining(cur(&board));
    board.saving(cur(&board));
    board.restarting(cur(&board));
    assert_eq!(phase(&board), Some(RestartPhase::Draining));
    board.set_remaining_calls(cur(&board), 3);
    board.set_remaining_calls(cur(&board), 2);
    assert_eq!(board.status().expect("a record").remaining_calls, 2);
}

#[test]
fn b2_nothing_before_accept() {
    let board = RestartBoard::default();
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    board.cancel(cur(&board), RestartCancel::Recheck);
    board.commit(cur(&board), STOP_DL);
    board.restarting(cur(&board));
    board.saving(cur(&board));
    board.draining(cur(&board));
    board.set_remaining_calls(cur(&board), 1);
    assert_eq!(board.status(), None);
}

#[test]
fn b2_accept_starts_fresh_even_after_draining() {
    let board = at_checkpoint(true);
    board.restarting(cur(&board));
    board.set_remaining_calls(cur(&board), 4);
    board.draining(cur(&board));
    let first = board.status().expect("a record").id;
    let second = board.accept();
    assert_eq!(second, first + 1);
    let record = board.status().expect("a record");
    assert_eq!(
        (
            record.id,
            record.phase,
            record.deadline_unix_ms,
            record.remaining_calls,
            record.cancel
        ),
        (second, RestartPhase::Accepted, None, 0, None)
    );
    board.restarting(cur(&board));
    assert_eq!(
        phase(&board),
        Some(RestartPhase::Accepted),
        "the new attempt is not committed"
    );
}

/// B8: an accepted attempt has no deadline until the checkpoint move sets
/// it: the record's deadline is `None` and the wire's is `null`; the
/// checkpoint sets its own, and a second checkpoint call changes nothing.
#[test]
fn b8_an_accepted_attempt_has_no_deadline_until_its_checkpoint() {
    let board = RestartBoard::default();
    board.accept();
    let accepted = board.status().expect("a record");
    assert_eq!(accepted.deadline_unix_ms, None);
    // Present and null: indexing a missing key would also read null.
    assert_eq!(
        accepted.status_json().get("deadline"),
        Some(&serde_json::Value::Null),
        "{}",
        accepted.status_json()
    );
    board.checkpoint(cur(&board), CHECKPOINT_DL);
    assert_eq!(phase(&board), Some(RestartPhase::Checkpoint));
    assert_eq!(
        board.status().expect("a record").deadline_unix_ms,
        Some(CHECKPOINT_DL)
    );
    board.checkpoint(cur(&board), STOP_DL);
    assert_eq!(
        board.status().expect("a record").deadline_unix_ms,
        Some(CHECKPOINT_DL)
    );
}

/// One board call with fixed arguments.
#[derive(Clone, Copy, Debug)]
enum Call {
    Accept,
    Checkpoint,
    Cancel,
    Commit,
    Restarting,
    Saving,
    Draining,
    SetRemaining,
}

const CALLS: [Call; 8] = [
    Call::Accept,
    Call::Checkpoint,
    Call::Cancel,
    Call::Commit,
    Call::Restarting,
    Call::Saving,
    Call::Draining,
    Call::SetRemaining,
];

fn rank(p: RestartPhase) -> u8 {
    match p {
        RestartPhase::Accepted => 1,
        RestartPhase::Checkpoint => 2,
        RestartPhase::Restarting => 3,
        RestartPhase::Saving => 4,
        RestartPhase::Draining => 5,
        RestartPhase::Cancelled => 0,
    }
}

/// The design's rules, written independently of the board.
#[derive(Default)]
struct Model {
    last_id: u64,
    record: Option<RestartStatus>,
    committed: bool,
}

impl Model {
    fn apply(&mut self, call: Call) {
        if let Call::Accept = call {
            self.last_id += 1;
            self.committed = false;
            self.record = Some(RestartStatus {
                id: self.last_id,
                phase: RestartPhase::Accepted,
                deadline_unix_ms: None,
                remaining_calls: 0,
                cancel: None,
            });
            return;
        }
        let committed = self.committed;
        let Some(r) = self.record.as_mut() else {
            return;
        };
        let live = r.phase != RestartPhase::Cancelled;
        let forward = |r: &mut RestartStatus, to: RestartPhase| {
            if committed && live && rank(to) > rank(r.phase) {
                r.phase = to;
            }
        };
        match call {
            Call::Checkpoint if r.phase == RestartPhase::Accepted => {
                r.phase = RestartPhase::Checkpoint;
                r.deadline_unix_ms = Some(CHECKPOINT_DL);
            }
            Call::Cancel if live && !committed => {
                r.phase = RestartPhase::Cancelled;
                r.cancel = Some(RestartCancel::StopSignal);
            }
            Call::Commit if r.phase == RestartPhase::Checkpoint && !committed => {
                self.committed = true;
                r.deadline_unix_ms = Some(STOP_DL);
            }
            Call::Restarting if r.phase == RestartPhase::Checkpoint => {
                forward(r, RestartPhase::Restarting);
            }
            Call::Saving => forward(r, RestartPhase::Saving),
            Call::Draining => forward(r, RestartPhase::Draining),
            Call::SetRemaining if committed && live => r.remaining_calls = 3,
            _ => {}
        }
    }
}

fn call(board: &RestartBoard, c: Call) {
    match c {
        Call::Accept => {
            board.accept();
        }
        Call::Checkpoint => board.checkpoint(cur(board), CHECKPOINT_DL),
        Call::Cancel => board.cancel(cur(board), RestartCancel::StopSignal),
        Call::Commit => board.commit(cur(board), STOP_DL),
        Call::Restarting => board.restarting(cur(board)),
        Call::Saving => board.saving(cur(board)),
        Call::Draining => board.draining(cur(board)),
        Call::SetRemaining => board.set_remaining_calls(cur(board), 3),
    }
}

/// Every sequence of the eight mutating calls up to length 6, and every
/// length-6 sequence that ends at Draining followed by each call; the ninth
/// call, `status()`, is compared with the model after every step.
#[test]
fn b3_board_matches_the_model_on_every_short_sequence() {
    let mut reached_draining = 0u32;
    for len in 1..=6u32 {
        for code in 0..CALLS.len().pow(len) {
            let seq: Vec<Call> = (0..len)
                .map(|i| CALLS[code / CALLS.len().pow(i) % CALLS.len()])
                .collect();
            let (board, mut model) = (RestartBoard::default(), Model::default());
            for &c in &seq {
                call(&board, c);
                model.apply(c);
                assert_eq!(board.status(), model.record, "after {seq:?}");
            }
            if len == 6 && model.record.map(|r| r.phase) == Some(RestartPhase::Draining) {
                reached_draining += 1;
                for &next in &CALLS {
                    let (b, mut m) = (RestartBoard::default(), Model::default());
                    for &c in seq.iter().chain(std::iter::once(&next)) {
                        call(&b, c);
                        m.apply(c);
                    }
                    assert_eq!(b.status(), m.record, "after {seq:?} then {next:?}");
                }
            }
        }
    }
    assert!(
        reached_draining > 0,
        "no length-6 sequence reached Draining"
    );
}

#[test]
fn b4_each_cancel_reason_renders_and_stays_until_the_next_accept() {
    let mut seen = std::collections::BTreeSet::new();
    // Each floor variant differs from `floor()` in one part, so a text that
    // drops the owner, the stage or the reason renders two of them alike.
    let other = |owner, stage, reason| {
        RestartCancel::Floor(Cancelled {
            owner,
            stage,
            reason,
        })
    };
    for reason in [
        floor(),
        other(
            FloorOwner::Config,
            FloorStage::Checkpoint,
            CancelReason::SaveFailed,
        ),
        other(
            FloorOwner::Health,
            FloorStage::Pause,
            CancelReason::SaveFailed,
        ),
        other(
            FloorOwner::Health,
            FloorStage::Checkpoint,
            CancelReason::WorkerLost,
        ),
        RestartCancel::StopSignal,
        RestartCancel::Recheck,
        RestartCancel::AuditRefused,
    ] {
        let board = at_checkpoint(false);
        board.cancel(cur(&board), reason);
        board.saving(cur(&board));
        board.commit(cur(&board), STOP_DL);
        let text = board.status().expect("a record").status_json()["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(!text.is_empty(), "{reason:?}");
        assert!(seen.insert(text), "{reason:?} renders like another reason");
        board.accept();
        assert!(board.status().expect("a record").status_json()["reason"].is_null());
    }
    assert_eq!(RestartBoard::default().status(), None);
}

#[test]
fn b5_wire_form_has_the_agreed_keys_and_lowercase_phases() {
    // Every value, on a record whose id and remaining calls differ.
    let second = RestartBoard::default();
    second.accept();
    second.accept();
    second.checkpoint(cur(&second), CHECKPOINT_DL);
    second.commit(cur(&second), STOP_DL);
    second.set_remaining_calls(cur(&second), 7);
    assert_eq!(
        second.status().expect("a record").status_json(),
        serde_json::json!({
            "id": 2, "phase": "checkpoint", "deadline": STOP_DL, "remaining_calls": 7, "reason": null
        })
    );
    let board = at_checkpoint(true);
    let wire = board.status().expect("a record").status_json();
    let keys: Vec<&str> = wire
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 5, "{wire}");
    for key in ["id", "phase", "deadline", "remaining_calls", "reason"] {
        assert!(wire.get(key).is_some(), "{key}: {wire}");
    }
    assert_eq!(wire["deadline"], STOP_DL);
    let mut phases = vec![wire["phase"].clone()];
    for step in [
        RestartBoard::restarting,
        RestartBoard::saving,
        RestartBoard::draining,
    ] {
        step(&board, cur(&board));
        phases.push(board.status().expect("a record").status_json()["phase"].clone());
    }
    let early = RestartBoard::default();
    early.accept();
    phases.insert(
        0,
        early.status().expect("a record").status_json()["phase"].clone(),
    );
    early.cancel(cur(&early), RestartCancel::Recheck);
    phases.push(early.status().expect("a record").status_json()["phase"].clone());
    let want = [
        "accepted",
        "checkpoint",
        "restarting",
        "saving",
        "draining",
        "cancelled",
    ];
    assert_eq!(phases, want.map(serde_json::Value::from).to_vec());
}

/// A board whose first attempt was cancelled and whose second is current,
/// moved to `stage`: Accepted, Checkpoint, or committed.
fn second_attempt(stage: RestartPhase, committed: bool) -> RestartBoard {
    let board = RestartBoard::default();
    let first = board.accept();
    board.cancel(first, RestartCancel::AuditRefused);
    let second = board.accept();
    assert_eq!(second, 2, "premise: the second attempt is current");
    if stage == RestartPhase::Checkpoint {
        board.checkpoint(second, CHECKPOINT_DL);
        if committed {
            board.commit(second, STOP_DL);
        }
    }
    board
}

/// T8 (ATTEMPT.1): a call carrying the first attempt's id, or an id no attempt
/// has yet, leaves the current second attempt's whole record unchanged, and the
/// same call with its own id changes it, each staged where that call visibly
/// applies.
#[test]
fn a_call_for_an_earlier_attempt_never_moves_the_current_one() {
    type Case = (&'static str, RestartPhase, bool, fn(&RestartBoard, u64));
    let cases: [Case; 6] = [
        ("checkpoint", RestartPhase::Accepted, false, |b, id| {
            b.checkpoint(id, CHECKPOINT_DL);
        }),
        ("cancel", RestartPhase::Accepted, false, |b, id| {
            b.cancel(id, RestartCancel::Recheck);
        }),
        ("restarting", RestartPhase::Checkpoint, true, |b, id| {
            b.restarting(id);
        }),
        ("saving", RestartPhase::Checkpoint, true, |b, id| {
            b.saving(id);
        }),
        ("draining", RestartPhase::Checkpoint, true, |b, id| {
            b.draining(id);
        }),
        (
            "set_remaining_calls",
            RestartPhase::Checkpoint,
            true,
            |b, id| b.set_remaining_calls(id, 5),
        ),
    ];
    for (name, stage, committed, call) in cases {
        let board = second_attempt(stage, committed);
        let before = board.status();
        // 1 is the earlier attempt; 3 is no attempt yet (kills an ordering check).
        for wrong in [1, 3] {
            call(&board, wrong);
            assert_eq!(
                board.status(),
                before,
                "{name}: attempt {wrong}'s id moved the second"
            );
        }
        call(&board, 2);
        assert_ne!(
            board.status(),
            before,
            "{name}: positive control, its own id applies"
        );
    }

    // Commit: distinct deadlines, and its flag seen through a restarting call.
    let board = second_attempt(RestartPhase::Checkpoint, false);
    let before = board.status();
    for wrong in [1, 3] {
        board.commit(wrong, STOP_DL);
        assert_eq!(
            board.status(),
            before,
            "commit: attempt {wrong}'s id moved the second"
        );
    }
    board.restarting(2);
    assert_eq!(
        board.status(),
        before,
        "commit: the first attempt's id committed the second"
    );
    board.commit(2, STOP_DL);
    assert_eq!(
        board.status().and_then(|s| s.deadline_unix_ms),
        Some(STOP_DL),
        "commit: own id"
    );
    board.restarting(2);
    assert_eq!(
        phase(&board),
        Some(RestartPhase::Restarting),
        "commit: own id committed"
    );

    // Restarting before the commit: unchanged for either id.
    let board = second_attempt(RestartPhase::Checkpoint, false);
    let before = board.status();
    board.restarting(1);
    board.restarting(2);
    assert_eq!(
        board.status(),
        before,
        "restarting before commit: unchanged"
    );
}

/// T9 (ATTEMPT.1): before any accept, every call with any id is a no-op.
#[test]
fn every_call_before_any_accept_is_a_no_op() {
    let board = RestartBoard::default();
    for id in [0, 1, 7] {
        board.checkpoint(id, CHECKPOINT_DL);
        board.cancel(id, RestartCancel::StopSignal);
        board.commit(id, STOP_DL);
        board.restarting(id);
        board.saving(id);
        board.draining(id);
        board.set_remaining_calls(id, 3);
        assert_eq!(board.status(), None, "id {id}: a record appeared");
    }
}
