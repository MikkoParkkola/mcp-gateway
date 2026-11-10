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

/// The widest stored form, for the record-size reservation.
pub(crate) const WIDEST: &str =
    "hmac:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// What one dispatch injected, as stored on its upstream record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dispatched {
    /// No rule applied to the call.
    None,
    /// The fingerprint of the applying rules' resolved values.
    Fingerprint(String),
    /// Rules applied, but this process has no key to fingerprint them with:
    /// stored as missing, so it never delivers.
    Unkeyed,
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
        match key() {
            Some(key) => Self::Fingerprint(crate::hashing::hmac_sha256_hex(key, &keyed)),
            // No key: a value that matches nothing, so the task is withheld.
            None => Self::Unkeyed,
        }
    }

    /// The form written to the record: `"none"` or `"hmac:<hex>"`.
    pub(crate) fn stored(&self) -> String {
        match self {
            Self::None => "none".to_owned(),
            Self::Fingerprint(hex) => format!("hmac:{hex}"),
            Self::Unkeyed => MISSING.to_owned(),
        }
    }
}

/// Whether a stored value vouches for delivery now: it must equal the
/// current value exactly. Absent (a row from before the upgrade) and
/// [`MISSING`] never match.
pub(crate) fn delivers(stored: Option<&str>, current: &Dispatched) -> bool {
    stored.is_some_and(|stored| stored != MISSING && stored == current.stored())
}

/// The slot one deferring dispatch writes what it injected into: armed for
/// one `(server, tool)`, as the upstream handle's slot is, and keeping only
/// the first value it is offered.
pub(crate) struct Slot {
    server: String,
    tool: String,
    value: parking_lot::Mutex<Option<Dispatched>>,
}

impl Slot {
    pub(crate) fn armed_for(server: &str, tool: &str) -> Self {
        Self {
            server: server.to_owned(),
            tool: tool.to_owned(),
            value: parking_lot::Mutex::new(None),
        }
    }

    /// What the dispatch injected; `None` when no send of the armed target
    /// wrote here (stored as [`MISSING`]).
    pub(crate) fn value(&self) -> Option<Dispatched> {
        self.value.lock().clone()
    }
}

tokio::task_local! {
    /// The armed slot for the current deferring dispatch, if any.
    static SLOT: std::sync::Arc<Slot>;
}

/// Run `future` with `slot` armed for this task and nothing else. Opened
/// only beside the upstream handle's own slot (`with_upstream_submission`).
/// A plain function, not an `async fn`, for the reason
/// `with_upstream_submission` gives: it would hold `future` twice.
pub(crate) fn scope<F: std::future::Future>(
    slot: std::sync::Arc<Slot>,
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    SLOT.scope(slot, future)
}

/// Record what a send of `(server, tool)` injects, if a slot armed for that
/// target is open and holds nothing yet; otherwise a no-op. `value` runs only
/// then, so a send outside a deferring dispatch hashes nothing; it gives
/// `None` when the rules cannot resolve, a send that then fails before it
/// leaves, so nothing is recorded for it.
pub(crate) fn record(server: &str, tool: &str, value: impl FnOnce() -> Option<Dispatched>) {
    let _ = SLOT.try_with(|slot| {
        if slot.server == server && slot.tool == tool {
            let mut held = slot.value.lock();
            if held.is_none() {
                *held = value();
            }
        }
    });
}

/// This process's fingerprint key.
/// `None` when the system random source cannot fill one. A fixed fallback
/// key would be shared by every process and let a fingerprint match across
/// a restart, so without a key no fingerprint is made at all.
fn key() -> Option<&'static [u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    KEY.get_or_init(|| {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0_u8; 32];
        ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
        Some(bytes)
    })
    .as_ref()
}

#[cfg(test)]
#[path = "dispatched_tests.rs"]
mod tests;
