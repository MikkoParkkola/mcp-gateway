// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a deferring dispatch's secret rules resolved to, kept only as a keyed
//! fingerprint, so a deferred upstream result is delivered only while the
//! gateway can still redact what that dispatch injected.
//!
//! The key is random per process, never persisted and never logged: a
//! fingerprint made under another process (a restart) never matches, because
//! nothing vouches that the new process's redaction set holds the old values.

use std::sync::OnceLock;

/// Domain label: a fingerprint is never confused with another HMAC under
/// a key that happened to match.
const LABEL: &[u8] = b"mcp-gateway/dispatched-secrets/v1";

/// The stored form of a capture the dispatch slot held no value for.
pub(crate) const MISSING: &str = "missing";

/// What one dispatch injected, as stored on its upstream record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dispatched {
    /// No rule applied to the call.
    None,
    /// The fingerprint of the applying rules' resolved values.
    Fingerprint(String),
}

impl Dispatched {
    /// The fingerprint of `pairs` (rule name, resolved value) for `backend`:
    /// `None` when there are no pairs. The input is length-framed and sorted,
    /// so the order rules are written in does not matter.
    pub(crate) fn of(backend: &str, pairs: &[(String, String)]) -> Self {
        if pairs.is_empty() {
            return Self::None;
        }
        let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
        sorted.sort();
        let mut message = Vec::new();
        for part in std::iter::once(backend).chain(
            sorted
                .iter()
                .flat_map(|(name, value)| [name.as_str(), value.as_str()]),
        ) {
            let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
            message.extend_from_slice(&length.to_be_bytes());
            message.extend_from_slice(part.as_bytes());
        }
        let mut keyed = LABEL.to_vec();
        keyed.extend_from_slice(&message);
        Self::Fingerprint(crate::hashing::hmac_sha256_hex(key(), &keyed))
    }

    /// The form written to the record: `"none"` or `"hmac:<hex>"`.
    pub(crate) fn stored(&self) -> String {
        match self {
            Self::None => "none".to_owned(),
            Self::Fingerprint(hex) => format!("hmac:{hex}"),
        }
    }
}

/// Whether a stored value vouches for delivery now: it must equal the
/// current value exactly. Absent (a row from before the upgrade) and
/// [`MISSING`] never match.
pub(crate) fn delivers(stored: Option<&str>, current: &Dispatched) -> bool {
    stored.is_some_and(|stored| stored != MISSING && stored == current.stored())
}

/// This process's fingerprint key.
fn key() -> &'static [u8] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0_u8; 32];
        // invariant: the system random source does not fail on supported
        // platforms; a key of zeros would only make every check withhold
        // across processes, never deliver one.
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .expect("the system random source fills a key");
        bytes
    })
}

#[cfg(test)]
#[path = "dispatched_tests.rs"]
mod tests;
