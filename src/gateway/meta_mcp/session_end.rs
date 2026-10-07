// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reclaiming what a gateway keeps per session when that session ends, and
//! the key per-caller state is kept under.

use super::{MetaMcp, MetaMcpCallerContext};

impl MetaMcpCallerContext<'_> {
    /// Who the A/B arm and the prefetch hints key on (MIK-7215.CONTROL.5, G4):
    /// the caller key only. A caller with no key, stdio and keyless legacy HTTP
    /// included, gets no arm of its own and no hints (MIK-7997): a session id
    /// never stands in for the key.
    pub(crate) fn experiment_key(&self) -> Option<&str> {
        self.caller_key.filter(|key| !key.is_empty())
    }
}

impl MetaMcp {
    /// Drop every per-session store this gateway keeps for `session_id`
    /// (MIK-7215.CONTROL.5, gap G2). Registered with the session lifecycle by
    /// [`crate::gateway::session_lifecycle::wire_meta_session_cleanup`].
    pub fn forget_session(&self, session_id: &str) {
        #[cfg(feature = "spec-preview")]
        self.clear_session_promoted(session_id);
        self.session_profiles.remove_session(session_id);
        self.session_state.remove_session(session_id);
        self.cost_tracker.remove_session(session_id);
        if let Some(tracker) = self.get_transition_tracker() {
            tracker.remove_session(session_id);
        }
    }

    /// Forget the last tool recorded under a caller key whose idle deadline
    /// passed (gap G4). Hints key on the caller, and a caller key has no
    /// session end, so only the deadline reclaims it.
    pub fn forget_caller(&self, key: &str) {
        if let Some(tracker) = self.get_transition_tracker() {
            tracker.remove_session(key);
        }
    }
}
