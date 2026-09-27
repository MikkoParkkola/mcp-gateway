// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard bootstrap value and the browser sessions it opens.

/// A one-time value that exchanges for a dashboard session.
///
/// Printed by `serve` as part of a link. It is NOT the admin credential: the
/// link's query string reaches this gateway's own request log, so putting the
/// real token there would leak it into a file that outlives the browser tab.
/// This value is single-use and dies with the process.
#[derive(Debug)]
pub struct DashboardBootstrap {
    value: std::sync::Mutex<Option<String>>,
    /// Opaque handles issued to browsers, valid for this process only.
    sessions: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl DashboardBootstrap {
    /// Mint an opaque session for a browser that presented the bootstrap value.
    ///
    /// The cookie carries THIS, never the admin credential. A bearer token in a
    /// cookie is long-lived and, without TLS, recoverable from the wire; an
    /// opaque handle is meaningless anywhere but this process and expires with
    /// it. Kept in memory: a dashboard session is not worth persisting, and
    /// nothing on disk means nothing to steal from disk.
    pub fn issue_session(&self) -> String {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let handle =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(handle.clone());
        }
        handle
    }

    /// `true` when this handle was issued by this process and is still valid.
    #[must_use]
    pub fn session_is_valid(&self, handle: &str) -> bool {
        self.sessions
            .lock()
            .is_ok_and(|sessions| sessions.contains(handle))
    }

    /// Mint a fresh single-use value.
    #[must_use]
    pub fn new() -> Self {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
        Self {
            value: std::sync::Mutex::new(Some(value)),
            sessions: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// The value to print, while it remains unused.
    #[must_use]
    pub fn peek(&self) -> Option<String> {
        self.value.lock().ok().and_then(|v| v.clone())
    }

    /// Consume the value if it matches. Single use: a second attempt fails even
    /// with the right value, so a link left in a shell history is spent.
    #[must_use]
    pub fn consume(&self, candidate: &str) -> bool {
        let Ok(mut guard) = self.value.lock() else {
            return false;
        };
        match guard.as_deref() {
            Some(expected) if expected == candidate => {
                *guard = None;
                true
            }
            _ => false,
        }
    }
}

impl Default for DashboardBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "auth_dashboard_tests.rs"]
mod tests;
