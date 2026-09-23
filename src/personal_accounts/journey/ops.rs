// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The five journey operations built on `journey_transition` (design §4-§7).
//!
//! SLICE 2 PART II STUBS: the signatures are the contract `tests.rs` pins;
//! the bodies deliberately return wrong answers until the implementation.
#![allow(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    reason = "MIK-6745 slice 2 part ii contract stubs; the implementation deletes this allow"
)]

use super::{
    AccountKey, Consumed, JourneyError, JourneyId, JourneyLimits, JourneyReason, JourneyRefusal,
    JourneyStatus, JourneyView, NewJourney, StartSecrets,
};
use crate::personal_accounts::PersonalAccountStore;

impl PersonalAccountStore {
    /// POST creation: caps, rates, capacity, supersede, eviction (§5.3).
    /// STUB: an empty id.
    pub(crate) fn create_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _new: NewJourney,
    ) -> Result<JourneyId, JourneyError> {
        Ok(String::new())
    }

    /// Owner check, then mint state, binding and verifier (§4.2 steps 6-8).
    /// STUB: refuses.
    pub(crate) fn start_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
        _owner: &AccountKey,
    ) -> Result<StartSecrets, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::NotFound))
    }

    /// Callback steps 1-4 and 7: locate, replay, expiry, binding, consume.
    /// STUB: refuses as unknown state.
    pub(crate) fn consume_callback(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _state: &str,
        _binding: Option<&str>,
    ) -> Result<Consumed, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::UnknownState))
    }

    /// Terminal transition; clears `binding_digest` and `pkce_verifier` in
    /// the same write. STUB: does nothing.
    pub(crate) fn finish_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
        _status: JourneyStatus,
        _reason: Option<JourneyReason>,
    ) -> Result<(), JourneyError> {
        Ok(())
    }

    /// Status API view. STUB: not found.
    pub(crate) fn journey_status(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
    ) -> Result<JourneyView, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::NotFound))
    }
}
