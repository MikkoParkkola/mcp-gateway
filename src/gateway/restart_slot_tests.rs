// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The slot contract every restart slot passes, the real one here and the
//! restart route's fake later: `rows(make)` runs each contract row on a slot
//! built over a fresh board.

use std::sync::Arc;

use super::{Reservation, RestartSlot};
use crate::gateway::restart_status::{RestartBoard, RestartCancel};

/// A restart slot under the contract.
pub(crate) trait SlotUnderTest {
    type Reservation: ReservationUnderTest;
    fn try_reserve(&self) -> Option<Self::Reservation>;
    /// How many times the slot was freed.
    fn frees(&self) -> usize;
}

/// Its reservation; a drop is an ordinary drop.
pub(crate) trait ReservationUnderTest {
    fn accept(&mut self) -> u64;
    fn activate(self);
    fn refuse(self, reason: RestartCancel);
}

impl SlotUnderTest for RestartSlot {
    type Reservation = Reservation;
    fn try_reserve(&self) -> Option<Reservation> {
        RestartSlot::try_reserve(self)
    }
    fn frees(&self) -> usize {
        RestartSlot::frees(self)
    }
}

impl ReservationUnderTest for Reservation {
    fn accept(&mut self) -> u64 {
        Reservation::accept(self)
    }
    fn activate(self) {
        Reservation::activate(self);
    }
    fn refuse(self, reason: RestartCancel) {
        Reservation::refuse(self, reason);
    }
}

/// A way to end a reservation before accept, by name.
type End<R> = (&'static str, fn(R));

fn cancelled(board: &RestartBoard, id: u64) -> Option<RestartCancel> {
    let status = board.status()?;
    if status.attempt_id() == id {
        status.cancel_reason()
    } else {
        None
    }
}

/// Every contract row, each on a fresh board and the slot `make` builds over
/// it. A failing row panics with the row's name.
pub(crate) fn rows<S>(make: impl Fn(Arc<RestartBoard>) -> S)
where
    S: SlotUnderTest + Sync,
    S::Reservation: Send,
{
    let fresh = || {
        let board = Arc::new(RestartBoard::default());
        (make(Arc::clone(&board)), board)
    };

    // A held slot is busy, through accept and after activate, which frees nothing.
    let (slot, board) = fresh();
    let mut held = slot.try_reserve().expect("held: a free slot reserves");
    assert!(
        slot.try_reserve().is_none(),
        "held: a second reservation while held"
    );
    let id = held.accept();
    assert!(
        slot.try_reserve().is_none(),
        "held: a second reservation after accept"
    );
    held.activate();
    assert!(
        slot.try_reserve().is_none(),
        "held: a second reservation after activate"
    );
    assert_eq!(slot.frees(), 0, "activate after accept: not freed");
    assert_eq!(
        cancelled(&board, id),
        None,
        "activate: the attempt is not cancelled"
    );
    assert_eq!(
        board.status().map(|s| s.attempt_id()),
        Some(id),
        "activate: the board's record is the accepted attempt"
    );

    // Before accept, a drop, a refuse and an activate each free the slot once
    // and leave the board as it was: empty, or holding an earlier attempt.
    let ends: [End<S::Reservation>; 3] = [
        ("drop", drop),
        ("refuse", |r| r.refuse(RestartCancel::Recheck)),
        ("activate", ReservationUnderTest::activate),
    ];
    for earlier in [false, true] {
        for (end, close) in ends {
            let (slot, board) = fresh();
            if earlier {
                board.accept();
            }
            let before = board.status();
            close(slot.try_reserve().expect("before accept: reserves"));
            assert_eq!(
                board.status(),
                before,
                "{end} before accept (earlier attempt: {earlier}): the board is untouched"
            );
            assert_eq!(slot.frees(), 1, "{end} before accept: freed exactly once");
            assert!(
                slot.try_reserve().is_some(),
                "{end} before accept: the slot is free"
            );
        }
    }

    // Sixteen threads reserving at once: exactly one wins. A smoke row; the
    // guarantee is the slot's own atomic reservation.
    let (slot, _board) = fresh();
    let start = std::sync::Barrier::new(16);
    let held: Vec<Option<S::Reservation>> = std::thread::scope(|s| {
        let threads: Vec<_> = (0..16)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    slot.try_reserve()
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().expect("a reserving thread"))
            .collect()
    });
    assert_eq!(held.iter().filter(|r| r.is_some()).count(), 1, "one winner");

    accepted_rows(&fresh);
}

/// The contract rows that accept an attempt, on slots from `fresh`.
fn accepted_rows<S: SlotUnderTest>(fresh: &dyn Fn() -> (S, Arc<RestartBoard>)) {
    // Accept is the board's id, from 1, the same id again.
    let (slot, board) = fresh();
    let mut first = slot.try_reserve().expect("accept: reserves");
    let id = first.accept();
    assert_eq!(id, 1, "accept: the first attempt of a boot is 1");
    assert_eq!(
        first.accept(),
        id,
        "accept: a second accept returns the same id"
    );
    assert_eq!(
        board.status().map(|s| s.attempt_id()),
        Some(id),
        "accept: the board's record"
    );
    first.refuse(RestartCancel::AuditRefused);
    let mut second = slot.try_reserve().expect("accept: reserves again");
    assert_eq!(second.accept(), 2, "accept: the next attempt is 2");
    second.activate();

    // Refused after accept: the reason on the board, the slot freed once.
    for reason in [RestartCancel::AuditRefused, RestartCancel::Recheck] {
        let (slot, board) = fresh();
        let mut held = slot.try_reserve().expect("refuse: reserves");
        let id = held.accept();
        held.refuse(reason);
        assert_eq!(
            cancelled(&board, id),
            Some(reason),
            "refuse: {reason:?} on the board"
        );
        assert_eq!(slot.frees(), 1, "refuse after accept: freed exactly once");
        assert!(slot.try_reserve().is_some(), "refuse: the slot is free");
    }

    // Dropped after accept: AuditRefused on the board, the slot freed once.
    let (slot, board) = fresh();
    let mut held = slot.try_reserve().expect("backstop: reserves");
    let id = held.accept();
    drop(held);
    assert_eq!(
        cancelled(&board, id),
        Some(RestartCancel::AuditRefused),
        "backstop: AuditRefused on the board"
    );
    assert_eq!(slot.frees(), 1, "drop after accept: freed exactly once");
    assert!(slot.try_reserve().is_some(), "backstop: the slot is free");
}

/// T7, T10, T13 (SLOT.1, SLOT.4): the real slot passes the contract.
#[test]
fn the_real_slot_passes_the_slot_contract() {
    rows(RestartSlot::for_test);
}
