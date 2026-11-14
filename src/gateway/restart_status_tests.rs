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

fn phase(board: &RestartBoard) -> Option<RestartPhase> {
    board.status().map(|s| s.phase)
}

/// A board at Checkpoint, committed when `commit` is set.
fn at_checkpoint(commit: bool) -> RestartBoard {
    let board = RestartBoard::default();
    board.accept(CHECKPOINT_DL);
    board.checkpoint();
    if commit {
        board.commit(STOP_DL);
    }
    board
}

#[test]
fn b1_restarting_before_commit_is_ignored_and_logged_once() {
    let board = at_checkpoint(false);
    let ((), logs) = crate::test_log_capture::capture_warnings(|| board.restarting());
    assert_eq!(phase(&board), Some(RestartPhase::Checkpoint));
    assert_eq!(logs.matches("before commit").count(), 1, "{logs}");
    board.commit(STOP_DL);
    board.restarting();
    assert_eq!(phase(&board), Some(RestartPhase::Restarting));
}

#[test]
fn b2_checkpoint_only_from_accepted() {
    let board = RestartBoard::default();
    board.checkpoint();
    assert_eq!(board.status(), None);
    board.accept(CHECKPOINT_DL);
    board.checkpoint();
    assert_eq!(phase(&board), Some(RestartPhase::Checkpoint));
    board.cancel(RestartCancel::Recheck);
    board.checkpoint();
    assert_eq!(phase(&board), Some(RestartPhase::Cancelled));
}

#[test]
fn b2_commit_only_from_checkpoint_and_switches_deadline() {
    let board = RestartBoard::default();
    board.accept(CHECKPOINT_DL);
    board.commit(STOP_DL);
    let accepted = board.status().expect("a record");
    assert_eq!(
        (accepted.phase, accepted.deadline_unix_ms),
        (RestartPhase::Accepted, CHECKPOINT_DL)
    );
    board.checkpoint();
    board.commit(STOP_DL);
    let committed = board.status().expect("a record");
    assert_eq!(
        (committed.phase, committed.deadline_unix_ms),
        (RestartPhase::Checkpoint, STOP_DL)
    );
}

#[test]
fn b2_cancel_only_before_commit() {
    let board = at_checkpoint(true);
    board.cancel(RestartCancel::StopSignal);
    let record = board.status().expect("a record");
    assert_eq!(
        (record.phase, record.cancel),
        (RestartPhase::Checkpoint, None)
    );
    let early = RestartBoard::default();
    early.accept(CHECKPOINT_DL);
    early.cancel(RestartCancel::AuditRefused);
    let record = early.status().expect("a record");
    assert_eq!(
        (record.phase, record.cancel),
        (RestartPhase::Cancelled, Some(RestartCancel::AuditRefused))
    );
}

#[test]
fn b2_second_cancel_is_a_no_op() {
    let board = at_checkpoint(false);
    board.cancel(RestartCancel::Recheck);
    board.cancel(RestartCancel::StopSignal);
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
            board.cancel(RestartCancel::StopSignal);
        }
        let before = board.status();
        board.saving();
        board.draining();
        board.set_remaining_calls(7);
        assert_eq!(board.status(), before, "cancelled: {cancelled}");
    }
}

#[test]
fn b2_forward_by_rank_only() {
    let board = at_checkpoint(true);
    board.restarting();
    board.draining();
    board.saving();
    board.restarting();
    assert_eq!(phase(&board), Some(RestartPhase::Draining));
    board.set_remaining_calls(3);
    board.set_remaining_calls(2);
    assert_eq!(board.status().expect("a record").remaining_calls, 2);
}

#[test]
fn b2_nothing_before_accept() {
    let board = RestartBoard::default();
    board.checkpoint();
    board.cancel(RestartCancel::Recheck);
    board.commit(STOP_DL);
    board.restarting();
    board.saving();
    board.draining();
    board.set_remaining_calls(1);
    assert_eq!(board.status(), None);
}

#[test]
fn b2_accept_starts_fresh_even_after_draining() {
    let board = at_checkpoint(true);
    board.restarting();
    board.set_remaining_calls(4);
    board.draining();
    let first = board.status().expect("a record").id;
    let second = board.accept(CHECKPOINT_DL);
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
        (second, RestartPhase::Accepted, CHECKPOINT_DL, 0, None)
    );
    board.restarting();
    assert_eq!(
        phase(&board),
        Some(RestartPhase::Accepted),
        "the new attempt is not committed"
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
                deadline_unix_ms: CHECKPOINT_DL,
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
                r.phase = RestartPhase::Checkpoint
            }
            Call::Cancel if live && !committed => {
                r.phase = RestartPhase::Cancelled;
                r.cancel = Some(RestartCancel::StopSignal);
            }
            Call::Commit if r.phase == RestartPhase::Checkpoint && !committed => {
                self.committed = true;
                r.deadline_unix_ms = STOP_DL;
            }
            Call::Restarting if r.phase == RestartPhase::Checkpoint => {
                forward(r, RestartPhase::Restarting)
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
            board.accept(CHECKPOINT_DL);
        }
        Call::Checkpoint => board.checkpoint(),
        Call::Cancel => board.cancel(RestartCancel::StopSignal),
        Call::Commit => board.commit(STOP_DL),
        Call::Restarting => board.restarting(),
        Call::Saving => board.saving(),
        Call::Draining => board.draining(),
        Call::SetRemaining => board.set_remaining_calls(3),
    }
}

/// Every sequence of the eight mutating calls up to length 6, and every
/// length-6 sequence that ends at Draining followed by each call; the ninth
/// call, status(), is compared with the model after every step.
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
    for reason in [
        floor(),
        RestartCancel::StopSignal,
        RestartCancel::Recheck,
        RestartCancel::AuditRefused,
    ] {
        let board = at_checkpoint(false);
        board.cancel(reason);
        board.saving();
        board.commit(STOP_DL);
        let text = board.status().expect("a record").wire()["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(!text.is_empty(), "{reason:?}");
        assert!(seen.insert(text), "{reason:?} renders like another reason");
        board.accept(CHECKPOINT_DL);
        assert!(board.status().expect("a record").wire()["reason"].is_null());
    }
    assert_eq!(RestartBoard::default().status(), None);
}

#[test]
fn b5_wire_form_has_the_agreed_keys_and_lowercase_phases() {
    let board = at_checkpoint(true);
    let wire = board.status().expect("a record").wire();
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
        step(&board);
        phases.push(board.status().expect("a record").wire()["phase"].clone());
    }
    let early = RestartBoard::default();
    early.accept(CHECKPOINT_DL);
    phases.insert(0, early.status().expect("a record").wire()["phase"].clone());
    early.cancel(RestartCancel::Recheck);
    phases.push(early.status().expect("a record").wire()["phase"].clone());
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
