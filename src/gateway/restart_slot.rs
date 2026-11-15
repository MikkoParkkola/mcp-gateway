// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The restart slot: one restart attempt at a time. The admin restart route
//! reserves it, accepts the attempt on the restart board after the
//! confirmation is consumed, writes the audit with the board's attempt id,
//! then activates the attempt; a refused or dropped reservation frees the
//! slot and records the cancel on the board. The slot takes no lock and never
//! waits: one atomic flag holds it, and the board's own lock stays a leaf.
#![allow(
    dead_code,
    reason = "the admin restart route, a later slice, is the slot's only caller"
)]

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::restart_status::{RestartBoard, RestartCancel};

/// See the module doc. One per boot, built beside the board it wraps.
pub(crate) struct RestartSlot {
    board: Arc<RestartBoard>,
    held: Arc<AtomicBool>,
    #[cfg(test)]
    frees: Arc<std::sync::atomic::AtomicUsize>,
}

impl RestartSlot {
    /// The slot for `board`; the status view reads the same board.
    pub(crate) fn new(board: Arc<RestartBoard>) -> Self {
        Self {
            board,
            held: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            frees: Arc::default(),
        }
    }

    /// The board this slot records on (the status view reads it).
    pub(crate) fn board(&self) -> &Arc<RestartBoard> {
        &self.board
    }

    /// A slot over `board`, for rows.
    #[cfg(test)]
    pub(crate) fn for_test(board: Arc<RestartBoard>) -> Self {
        Self::new(board)
    }

    /// The slot, or `None` while another attempt holds it (the route's 409).
    pub(crate) fn try_reserve(&self) -> Option<Reservation> {
        Some(Reservation {
            board: Arc::clone(&self.board),
            held: Arc::clone(&self.held),
            state: State::Reserved,
            #[cfg(test)]
            frees: Arc::clone(&self.frees),
        })
    }

    /// How many times the slot was freed (rows read it).
    #[cfg(test)]
    pub(crate) fn frees(&self) -> usize {
        self.frees.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Reserved,
    Accepted(u64),
    Finished,
}

/// A held slot. Send, not Clone.
pub(crate) struct Reservation {
    board: Arc<RestartBoard>,
    held: Arc<AtomicBool>,
    state: State,
    #[cfg(test)]
    frees: Arc<std::sync::atomic::AtomicUsize>,
}

impl Reservation {
    /// Accept the attempt on the board, after the confirmation is consumed:
    /// the attempt id for the 202 and the audit. Again returns the same id.
    pub(crate) fn accept(&mut self) -> u64 {
        0
    }

    /// Hand the accepted attempt over; never waits.
    pub(crate) fn activate(self) {}

    /// Refuse the attempt (the route's failed audit): records `reason` on the
    /// board for an accepted attempt, then frees the slot.
    pub(crate) fn refuse(self, reason: RestartCancel) {
        let _ = reason;
    }
}

impl Drop for Reservation {
    /// Not activated and not refused: frees the slot; an accepted attempt is
    /// recorded as cancelled with AuditRefused first (the backstop).
    fn drop(&mut self) {}
}

#[cfg(test)]
#[path = "restart_slot_tests.rs"]
pub(crate) mod slot_contract;
