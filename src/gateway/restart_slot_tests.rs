// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The slot contract every restart slot passes, the real one here and the
//! restart route's fake later: `rows(make)` runs each contract row on a slot
//! built over a fresh board. The rows below it are the real slot's own.

use std::sync::Arc;

use super::{Reservation, RestartSlot};
use crate::gateway::restart_status::{RestartBoard, RestartCancel};

/// A restart slot under the contract.
pub(crate) trait SlotUnderTest {
    type Reservation: ReservationUnderTest;
    fn try_reserve(&self) -> Option<Self::Reservation>;
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
pub(crate) fn rows<S: SlotUnderTest>(make: impl Fn(Arc<RestartBoard>) -> S) {
    let fresh = || {
        let board = Arc::new(RestartBoard::default());
        (make(Arc::clone(&board)), board)
    };

    // A held slot is busy, through accept and after activate.
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

    // Dropped before accept: free, nothing on the board.
    let (slot, board) = fresh();
    drop(slot.try_reserve().expect("drop before accept: reserves"));
    assert!(
        board.status().is_none(),
        "drop before accept: the board is untouched"
    );
    assert!(
        slot.try_reserve().is_some(),
        "drop before accept: the slot is free"
    );

    // Refused before accept: free, nothing on the board.
    let (slot, board) = fresh();
    slot.try_reserve()
        .expect("refuse before accept: reserves")
        .refuse(RestartCancel::Recheck);
    assert!(
        board.status().is_none(),
        "refuse before accept: the board is untouched"
    );
    assert!(
        slot.try_reserve().is_some(),
        "refuse before accept: the slot is free"
    );

    // Activated before accept: free, nothing on the board.
    let (slot, board) = fresh();
    slot.try_reserve()
        .expect("activate before accept: reserves")
        .activate();
    assert!(
        board.status().is_none(),
        "activate before accept: the board is untouched"
    );
    assert!(
        slot.try_reserve().is_some(),
        "activate before accept: the slot is free"
    );

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

    // Refused after accept: the reason on the board, the slot free.
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
        assert!(slot.try_reserve().is_some(), "refuse: the slot is free");
    }

    // Dropped after accept: AuditRefused on the board, the slot free.
    let (slot, board) = fresh();
    let mut held = slot.try_reserve().expect("backstop: reserves");
    let id = held.accept();
    drop(held);
    assert_eq!(
        cancelled(&board, id),
        Some(RestartCancel::AuditRefused),
        "backstop: AuditRefused on the board"
    );
    assert!(slot.try_reserve().is_some(), "backstop: the slot is free");
}

/// T7 (SLOT.4): the real slot passes the contract.
#[test]
fn the_real_slot_passes_the_slot_contract() {
    rows(RestartSlot::for_test);
}

/// T13 (SLOT.1): every path frees the slot exactly once, and an accepted,
/// activated attempt keeps it. Red if a refused reservation's drop frees again.
#[test]
fn each_reservation_frees_the_slot_exactly_once() {
    let slot = RestartSlot::for_test(Arc::new(RestartBoard::default()));
    let mut frees = 0;
    let mut once = |what: &str, slot: &RestartSlot| {
        frees += 1;
        assert_eq!(slot.frees(), frees, "{what}: freed exactly once");
    };
    drop(slot.try_reserve().expect("reserves"));
    once("drop before accept", &slot);
    slot.try_reserve()
        .expect("reserves")
        .refuse(RestartCancel::Recheck);
    once("refuse before accept", &slot);
    slot.try_reserve().expect("reserves").activate();
    once("activate before accept", &slot);
    let mut held = slot.try_reserve().expect("reserves");
    held.accept();
    held.refuse(RestartCancel::AuditRefused);
    once("refuse after accept", &slot);
    let mut held = slot.try_reserve().expect("reserves");
    held.accept();
    drop(held);
    once("drop after accept", &slot);
    let mut held = slot.try_reserve().expect("reserves");
    held.accept();
    held.activate();
    assert_eq!(slot.frees(), frees, "activate after accept: not freed");
    assert!(
        slot.try_reserve().is_none(),
        "activate after accept: still held"
    );
}

/// T10 (SLOT.1): sixteen threads reserving at once get exactly one slot. A
/// smoke row: the guarantee is the flag's single compare-and-exchange.
#[test]
fn concurrent_reservations_have_one_winner() {
    let slot = Arc::new(RestartSlot::for_test(Arc::new(RestartBoard::default())));
    let start = Arc::new(std::sync::Barrier::new(16));
    let held: Vec<Option<Reservation>> = (0..16)
        .map(|_| {
            let (slot, start) = (Arc::clone(&slot), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                slot.try_reserve()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().expect("a reserving thread"))
        .collect();
    assert_eq!(held.iter().filter(|r| r.is_some()).count(), 1, "one winner");
}
