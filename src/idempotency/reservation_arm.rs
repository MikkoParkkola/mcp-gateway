// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Undoing an armed reservation (#1962).

use super::{IdempotencyReservation, OnDrop};

impl IdempotencyReservation {
    /// Undo [`commit`](Self::commit): dropping the reservation unsettled
    /// releases the key again. For a backend that answered it stopped to ask,
    /// or a dispatch that provably never left the gateway. No-op once the
    /// reservation is settled.
    pub fn disarm(&mut self) {
        if !self.settled {
            self.on_drop = OnDrop::Release;
        }
    }
}
