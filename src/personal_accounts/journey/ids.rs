// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Journey id generation. Tests may queue the ids it returns, so a collision
//! with a live record can be forced rather than waited for.

use super::super::random_hex;
use super::{AccountError, JourneyId, JourneyTable};

#[cfg(test)]
thread_local! {
    static FORCED: std::cell::RefCell<std::collections::VecDeque<JourneyId>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// Two journey ids, drawn before the lock (a transition performs no IO).
pub(super) struct Candidates([JourneyId; 2]);

impl Candidates {
    pub(super) fn draw() -> Result<Self, AccountError> {
        Ok(Self([fresh_id()?, fresh_id()?]))
    }

    /// The first id no record holds: a collision gets one redraw, a second
    /// refuses, so an insert never overwrites a record already in `table`.
    pub(super) fn unused(self, table: &JourneyTable) -> Result<JourneyId, AccountError> {
        self.0
            .into_iter()
            .find(|id| !table.journeys.contains_key(id))
            .ok_or(AccountError::StorageUnavailable)
    }
}

/// A fresh 32-hex journey id, or the next forced one under test.
fn fresh_id() -> Result<JourneyId, AccountError> {
    #[cfg(test)]
    if let Some(id) = FORCED.with(|forced| forced.borrow_mut().pop_front()) {
        return Ok(id);
    }
    random_hex()
}

/// Queue `ids` as the next values of [`fresh_id`] on this thread.
#[cfg(test)]
pub(super) fn force_ids(ids: &[&str]) {
    FORCED.with(|forced| {
        forced
            .borrow_mut()
            .extend(ids.iter().map(|id| (*id).to_owned()));
    });
}
