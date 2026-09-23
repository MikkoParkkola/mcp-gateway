// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design §4.2 step 1: the start route loads the journey before it reads the
//! browser's session, so a dead link never costs an Open `WebUI` round trip.

use super::{JourneyError, JourneyLimits, JourneyRefusal};
use crate::personal_accounts::PersonalAccountStore;

impl PersonalAccountStore {
    /// The account an active (pending or started) journey names, after the
    /// sweep. Anything else is `NotFound`; the owner is checked later, by
    /// `start_journey`, under its own acquisition.
    pub(crate) fn active_journey_account(
        &self,
        now: u64,
        limits: &JourneyLimits,
        id: &str,
    ) -> Result<String, JourneyError> {
        self.journey_transition(now, limits, |tx| {
            tx.table
                .journeys
                .get(id)
                .filter(|record| record.is_active())
                .map(|record| record.account_id.clone())
                .ok_or(JourneyRefusal::NotFound)
        })
    }
}
