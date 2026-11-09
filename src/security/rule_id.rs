// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stable, keyed ids for the configured rules a decision record names.
//!
//! An id is `"<kind>:"` plus the HMAC-SHA-256 hex of the rule's serialised
//! definition under a key derived from the record key. Keyed, so a reader of
//! the log cannot test guesses about a short rule; derived, so it needs no new
//! config key; computed when the rule compiles, never per call.

/// The HKDF info that derives the rule key from the record key. Distinct from
/// the config revision's, so the two never share a key.
pub(crate) const TAG: &[u8] = b"decision.rule_id.v1";

/// The key rule ids are computed under. Its own type, so a revision key can
/// never be passed where a rule key is meant.
#[derive(Clone)]
pub(crate) struct RuleKey([u8; 32]);

impl RuleKey {
    pub(crate) const fn from_derived(key: [u8; 32]) -> Self {
        Self(key)
    }
}

/// Never the key bytes: a holder's `Debug` may reach a log line.
impl std::fmt::Debug for RuleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuleKey(..)")
    }
}

/// One rule's id, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RuleId(String);

impl RuleId {
    /// The id of a rule of `kind` whose serialised definition is `definition`.
    #[must_use]
    pub(crate) fn of(kind: &str, key: &RuleKey, definition: &[u8]) -> Self {
        Self(format!(
            "{kind}:{}",
            crate::hashing::hmac_sha256_hex(&key.0, definition)
        ))
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "rule_id_tests.rs"]
mod tests;
