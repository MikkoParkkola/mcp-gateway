// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reclaiming what a gateway keeps per session when that session ends, and
//! the key per-caller state is kept under.

use super::{MetaMcp, MetaMcpCallerContext, session_key};

impl MetaMcpCallerContext<'_> {
    /// Who the A/B arm and the prefetch hints key on (MIK-7215.CONTROL.5, G4):
    /// the caller key, else a real session id (a legacy connection or stdio,
    /// neither shared). A keyless modern caller has neither: no arm of its
    /// own and no hints, never the empty id every such caller shares.
    pub(crate) fn experiment_key<'s>(&'s self, session_id: Option<&'s str>) -> Option<&'s str> {
        self.caller_key
            .filter(|key| !key.is_empty())
            .or_else(|| session_key(session_id))
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

    /// Take the lifecycle calls hold their session through. Once; the first
    /// wiring wins.
    pub(crate) fn attach_session_lifecycle(
        &self,
        lifecycle: &std::sync::Arc<crate::gateway::session_lifecycle::SessionLifecycle>,
    ) {
        if self
            .session_lifecycle
            .set(std::sync::Arc::downgrade(lifecycle))
            .is_err()
        {
            tracing::debug!("session lifecycle already attached");
        }
    }

    /// Hold `session_id` for as long as the returned guard lives, so whatever
    /// the call writes under it is taken if the session ends first or meanwhile
    /// (MIK-7996). `None` for no session, the empty id or an unwired gateway.
    pub(crate) fn hold_session(
        &self,
        session_id: Option<&str>,
    ) -> Option<crate::gateway::session_lifecycle::SessionHold> {
        let id = session_key(session_id)?;
        Some(self.session_lifecycle.get()?.upgrade()?.hold_session(id))
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
