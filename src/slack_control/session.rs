//! Thread-to-session mapping (B2-MEM).
//!
//! Slack `thread_ts` maps to a session identifier so the agent can recall
//! prior thread context and maintain continuity across messages.

use std::collections::HashMap;
use std::sync::Mutex;

/// Thread-to-session mapper.
///
/// Maps Slack `thread_ts` values to stable session identifiers so the
/// agent runtime can maintain conversation continuity.
pub struct SessionMap {
    inner: Mutex<HashMap<String, String>>,
}

impl SessionMap {
    /// Create a new empty session map.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Get or create a session ID for the given thread_ts.
    ///
    /// If a session already exists for this thread, returns it.
    /// Otherwise, creates a new session ID derived from the thread_ts.
    pub fn get_or_create(&self, thread_ts: &str) -> String {
        let mut map = self.inner.lock().expect("session map mutex poisoned");
        map.entry(thread_ts.to_string())
            .or_insert_with(|| format!("slack-session-{thread_ts}"))
            .clone()
    }

    /// Look up an existing session for a thread_ts, if any.
    pub fn get(&self, thread_ts: &str) -> Option<String> {
        let map = self.inner.lock().expect("session map mutex poisoned");
        map.get(thread_ts).cloned()
    }

    /// Return the number of tracked sessions.
    pub fn len(&self) -> usize {
        let map = self.inner.lock().expect("session map mutex poisoned");
        map.len()
    }

    /// Check whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_ts_maps_to_stable_session() {
        let map = SessionMap::new();
        let s1 = map.get_or_create("1234567890.123456");
        let s2 = map.get_or_create("1234567890.123456");
        assert_eq!(s1, s2);
        assert!(s1.starts_with("slack-session-"));
    }

    #[test]
    fn different_threads_get_different_sessions() {
        let map = SessionMap::new();
        let s1 = map.get_or_create("1111111111.111111");
        let s2 = map.get_or_create("2222222222.222222");
        assert_ne!(s1, s2);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn get_returns_none_for_unknown_thread() {
        let map = SessionMap::new();
        assert!(map.get("unknown").is_none());
    }
}
