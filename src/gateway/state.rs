//! Session FSM state store.
//!
//! Each session has a current string state (default: `"default"`).
//! `gateway_set_state` transitions the session and the `tools/list` handler
//! uses it to filter capabilities whose `visible_in_states` is non-empty.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

/// Default state name used when no explicit state has been set for a session.
pub const DEFAULT_STATE: &str = "default";

/// Thread-safe per-session state store.
///
/// Keyed by session ID (`String`).  Sessions not present in the map are in
/// [`DEFAULT_STATE`].  The store is intentionally cheaply cloneable via `Arc`.
#[derive(Clone, Default)]
pub struct SessionStateStore {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl SessionStateStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the current state for `session_id`, or `"default"` if not set.
    #[must_use]
    pub fn get_state(&self, session_id: &str) -> String {
        self.inner
            .read()
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| DEFAULT_STATE.to_string())
    }

    /// Set the state for `session_id`.  Returns the previous state.
    pub fn set_state(&self, session_id: &str, state: &str) -> String {
        self.inner
            .write()
            .insert(session_id.to_string(), state.to_string())
            .unwrap_or_else(|| DEFAULT_STATE.to_string())
    }

    /// Remove a session's state entry (called on session disconnect).
    pub fn remove_session(&self, session_id: &str) {
        self.inner.write().remove(session_id);
    }

    /// Return the number of active (non-default) session state entries.
    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Return `true` when no sessions have explicit state set.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_state_returns_default_when_session_absent() {
        // GIVEN: empty store
        let store = SessionStateStore::new();
        // WHEN: getting state for unknown session
        // THEN: returns DEFAULT_STATE
        assert_eq!(store.get_state("sess-1"), DEFAULT_STATE);
    }

    #[test]
    fn set_state_returns_previous_state() {
        // GIVEN: store with no entry for sess-1
        let store = SessionStateStore::new();
        // WHEN: setting state for the first time
        let prev = store.set_state("sess-1", "checkout");
        // THEN: previous is DEFAULT_STATE
        assert_eq!(prev, DEFAULT_STATE);
    }

    #[test]
    fn set_state_updates_and_returns_correct_previous() {
        // GIVEN: store with sess-1 already in "checkout"
        let store = SessionStateStore::new();
        store.set_state("sess-1", "checkout");
        // WHEN: transitioning to "payment"
        let prev = store.set_state("sess-1", "payment");
        // THEN: previous was "checkout"
        assert_eq!(prev, "checkout");
        assert_eq!(store.get_state("sess-1"), "payment");
    }

    #[test]
    fn remove_session_clears_state() {
        // GIVEN: store with sess-1 in "checkout"
        let store = SessionStateStore::new();
        store.set_state("sess-1", "checkout");
        // WHEN: removing the session
        store.remove_session("sess-1");
        // THEN: state reverts to DEFAULT_STATE
        assert_eq!(store.get_state("sess-1"), DEFAULT_STATE);
    }

    #[test]
    fn multiple_sessions_are_independent() {
        // GIVEN: two sessions
        let store = SessionStateStore::new();
        store.set_state("sess-a", "step1");
        store.set_state("sess-b", "step2");
        // THEN: each has its own state
        assert_eq!(store.get_state("sess-a"), "step1");
        assert_eq!(store.get_state("sess-b"), "step2");
        // AND: an unset session still returns default
        assert_eq!(store.get_state("sess-c"), DEFAULT_STATE);
    }

    #[test]
    fn is_empty_and_len_reflect_entries() {
        let store = SessionStateStore::new();
        assert!(store.is_empty());
        store.set_state("s1", "x");
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
}
