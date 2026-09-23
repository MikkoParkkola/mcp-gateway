// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Expiry sweep, terminal transition and GC (design §3, §5.2 step 2).

use super::{JourneyReason, JourneyRecord, JourneyStatus, JourneyTable, TERMINAL_RETENTION};

impl JourneyRecord {
    /// `pending`/`started`: the only records the sweep may rewrite.
    pub(crate) fn is_active(&self) -> bool {
        matches!(self.status, JourneyStatus::Pending | JourneyStatus::Started)
    }

    /// The deadline that currently applies (`expires_at`), active only.
    pub(crate) fn deadline(&self) -> Option<u64> {
        match self.status {
            JourneyStatus::Pending => Some(self.start_by),
            JourneyStatus::Started => self.callback_by,
            _ => None,
        }
    }

    /// Every terminal transition: the browser binding and the PKCE verifier
    /// leave in the same write (C04). `state_digest` stays for replay detection.
    pub(crate) fn terminate(
        &mut self,
        status: JourneyStatus,
        reason: Option<JourneyReason>,
        now: u64,
    ) {
        self.status = status;
        self.reason = reason;
        self.binding_digest = None;
        self.pkce_verifier = None;
        self.terminal_at = Some(now);
    }
}

/// Expire every active record at or past its deadline, then collect terminal
/// records older than `TERMINAL_RETENTION`. Terminal records are never rewritten.
pub(crate) fn sweep(table: &mut JourneyTable, now: u64) {
    for record in table.journeys.values_mut() {
        if record.deadline().is_some_and(|deadline| now >= deadline) {
            record.terminate(JourneyStatus::Expired, Some(JourneyReason::Expired), now);
        }
    }
    table.journeys.retain(|_, record| {
        record
            .terminal_at
            .is_none_or(|at| now < at.saturating_add(TERMINAL_RETENTION))
    });
}

/// Make room for one insert under `records_max`: evict the oldest terminal
/// records by `terminal_at`. Active records are never evicted (H3).
pub(crate) fn evict_for_insert(table: &mut JourneyTable, records_max: usize) {
    while table.journeys.len() >= records_max {
        let oldest = table
            .journeys
            .iter()
            .filter_map(|(id, record)| record.terminal_at.map(|at| (at, id.clone())))
            .min();
        let Some((_, id)) = oldest else { return };
        table.journeys.remove(&id);
    }
}
