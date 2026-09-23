// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dispatch-site offer (design §9.3, review H1): reuse the caller's active
//! journey, or mint one when none can still complete. Never supersedes.

use super::{
    AccountDescriptor, AccountKey, JourneyError, JourneyId, JourneyLimits, JourneyRefusal,
    NewJourney, PersonalAccountStore, insert, pending, predecessors, random_hex, storage,
    within_caps,
};

impl PersonalAccountStore {
    /// Reuse-or-mint in ONE transition, so two concurrent refusals cannot both
    /// see "none active" and have the second supersede the first.
    ///
    /// Reuse runs after the sweep and before any rate check: a reused journey
    /// changes no status, digest, verifier or deadline, so a consent already
    /// in flight still connects, and the unchanged table is not rewritten. A
    /// mint happens only when the sweep left nothing active for this principal
    /// and account, so `insert` supersedes nothing. Answers the id and its
    /// applicable deadline (`start_by`, or `callback_by` once started).
    pub(crate) fn offer_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        new: NewJourney,
    ) -> Result<(JourneyId, u64), JourneyError> {
        if !within_caps(&new) {
            return Err(JourneyError::Refused(JourneyRefusal::InvalidRequest));
        }
        let record = pending(&self.config, new, now).map_err(storage)?;
        let id = random_hex().map_err(storage)?;
        self.journey_transition(now, limits, |tx| {
            let active = predecessors(tx.table, &record).into_iter().next();
            if let Some(active) = active {
                let deadline = tx.table.journeys[&active].deadline().unwrap_or(now);
                return Ok((active, deadline));
            }
            let deadline = record.start_by;
            insert(tx, limits, id, record, now).map(|id| (id, deadline))
        })
    }

    /// [`Self::offer_journey`] for the configured descriptor, captured exactly
    /// as an explicit creation captures it.
    pub(crate) fn offer_connect_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        owner: AccountKey,
        descriptor: &AccountDescriptor,
        return_path: String,
    ) -> Result<(JourneyId, u64), JourneyError> {
        let new = self.connect_request(owner, descriptor, return_path)?;
        self.offer_journey(now, limits, new)
    }
}
