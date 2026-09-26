// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A streaming session's id is its anonymous holder's only credential (F9).
//!
//! With authentication off nothing else tells two callers apart, so the id is
//! a secret: minted by the gateway, never adopted from a caller, and never
//! written to a log. Logs carry [`session_fp`] instead; a new log site that
//! names a session id, in a field or in the message text, goes through it too.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// A log-safe stand-in for a session id: the first 8 hex characters of its
/// SHA-256.
///
/// For correlation only. 32 bits are expected to collide somewhere past about
/// 2^16 live sessions, so a repeated fingerprint is not evidence of id reuse.
/// The empty id, the router's "no session", stays empty.
#[must_use]
pub(crate) fn session_fp(id: &str) -> String {
    if id.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(id.as_bytes());
    hex::encode(&digest[..4])
}

/// A session id held by the session store, which cannot print itself.
///
/// `Display` and `Debug` both print [`session_fp`], so a log that names a
/// stored id is fingerprinted without a call-site rule. The raw value is
/// reachable only through [`SessionId::expose_secret`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(Arc<str>);

impl SessionId {
    pub(crate) fn new(id: &str) -> Self {
        Self(Arc::from(id))
    }

    /// The raw id: for the map key, the response header and id comparison only.
    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }
}

// Hashes as the `str` it wraps (the derive hashes the one field), so the map
// can be queried by `&str`.
impl std::borrow::Borrow<str> for SessionId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&session_fp(&self.0))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", session_fp(&self.0))
    }
}

/// Log capture for the F9 fingerprint tests.
#[cfg(test)]
pub(crate) mod log_capture {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Capture every event at DEBUG and above on this thread until the guard
    /// drops. Run under a current-thread runtime so spawned tasks log here too.
    pub(crate) fn capture_debug() -> (Captured, tracing::subscriber::DefaultGuard) {
        // Global interest keeps a callsite first reached without a scoped
        // subscriber from being cached as disabled for this one.
        use tracing_subscriber::prelude::*;
        static INTEREST: std::sync::Once = std::sync::Once::new();
        INTEREST.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::Registry::default()
                    .with(tracing::level_filters::LevelFilter::TRACE),
            );
        });
        let captured = Captured::default();
        let buffer = Arc::clone(&captured.0);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || Sink(Arc::clone(&buffer)))
            .finish();
        (captured, tracing::subscriber::set_default(subscriber))
    }

    /// The line carrying `message` is present and names the session by its
    /// fingerprint; the raw id appears nowhere in the capture.
    pub(crate) fn assert_fingerprinted(text: &str, message: &str, raw: &str) {
        let fp = super::session_fp(raw);
        let line = text
            .lines()
            .find(|l| l.contains(message))
            .unwrap_or_else(|| panic!("no log line containing {message:?} in:\n{text}"));
        assert!(
            line.contains(&fp),
            "{message:?} must name the session by fingerprint {fp}: {line}"
        );
        assert!(
            !text.contains(raw),
            "the raw session id {raw} was logged:\n{text}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // F9-T7d
    #[test]
    fn a_session_id_prints_only_its_fingerprint() {
        let raw = "gw-5f0c7a4e-secret-session";
        let id = SessionId::new(raw);
        let fp = session_fp(raw);
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(format!("{id}"), fp);
        assert!(format!("{id:?}").contains(&fp));
        assert!(!format!("{id}").contains(raw));
        assert!(!format!("{id:?}").contains(raw));
        assert_eq!(id.expose_secret(), raw);
    }
}
