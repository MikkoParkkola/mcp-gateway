// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The open decisions an admin must take, held in memory and kept current by
//! their producers, never recomputed on a read.
//!
//! An access request is a projection over the dispatch grant-decision notes:
//! keyed by subject and proven agent, open per capability while a missing
//! grant denial for it is newer than the last UI decision on it and no live
//! grant row covers it. A changed capability is one capability file whose
//! bytes no longer match their pin.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::identity_grants::{IdentityGrant, IdentityGrantAuditEvent};

#[cfg(test)]
mod tests;

/// A source the set is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Source {
    /// Grant-decision notes in the transparency log.
    Access,
    /// Decline and allow-attribution events in the control-plane audit.
    ControlPlane,
    /// Pin mismatches on the capability backend.
    Capability,
}

/// Whether a source can be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    /// Read and current.
    Ready,
    /// Not configured here: it contributes no items and is not an error.
    Absent,
    /// Configured but unreadable, or its startup replay has not finished.
    Unavailable,
}

/// The decision set: open items, a revision that rises on any visible change,
/// and each source's health.
pub(crate) struct DecisionSet {
    key: [u8; 32],
    health: BTreeMap<Source, Health>,
    revision: u64,
}

impl DecisionSet {
    /// A set whose ids are keyed by `key`; every source starts `Unavailable`.
    pub(crate) fn with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            health: BTreeMap::new(),
            revision: 0,
        }
    }

    /// Record a source's health.
    pub(crate) fn set_health(&mut self, source: Source, health: Health) {
        self.health.insert(source, health);
    }

    /// Fold one grant-decision note, live or replayed.
    pub(crate) fn note_denial(&mut self, _event: &IdentityGrantAuditEvent) {}

    /// Fold a UI decision (a decline, or a consumed allow attribution) on
    /// one capability for a subject and agent.
    pub(crate) fn note_ui_decision(
        &mut self,
        _authority: &str,
        _subject: &str,
        _agent: &str,
        _capability: &str,
        _at: DateTime<Utc>,
    ) {
    }

    /// Replace the live grant rows and re-check every open item at `now`.
    pub(crate) fn set_grants(&mut self, _grants: Vec<IdentityGrant>, _now: DateTime<Utc>) {}

    /// Re-check every open item against the held grant rows at `now`.
    pub(crate) fn expire(&mut self, _now: DateTime<Utc>) {}

    /// Close every access item whose newest denial is older than `edge`.
    pub(crate) fn evict_before(&mut self, _edge: DateTime<Utc>) {}

    /// The open count and revision for an admin, or `None` for anyone else
    /// and while any source is `Unavailable`. In memory; never blocks.
    pub(crate) fn snapshot(&self, _admin: bool) -> Option<(usize, u64)> {
        let _ = (&self.key, self.revision);
        None
    }

    /// The open items in display order.
    pub(crate) fn list(&self) -> Vec<Value> {
        Vec::new()
    }
}
