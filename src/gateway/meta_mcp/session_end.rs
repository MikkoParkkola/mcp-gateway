//! Reclaiming what a gateway keeps per session when that session ends.

use super::MetaMcp;

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
        if let Some(stats) = &self.stats {
            stats.remove_session(session_id);
        }
    }
}
