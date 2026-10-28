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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Where an event sits in its log: the replay reads up to a cut-off and live
/// delivery covers the rest, so an event can arrive by both; its position
/// makes the second arrival a repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LogPos {
    /// The log the event is in.
    pub(crate) log: Source,
    /// The segment number.
    pub(crate) segment: u64,
    /// The record's offset in its segment.
    pub(crate) offset: u64,
}

/// A UI decision on one capability for a subject and agent: a decline, or a
/// consumed allow attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UiDecision {
    /// The subject's authority.
    pub(crate) authority: String,
    /// The subject id.
    pub(crate) subject: String,
    /// The proven agent, `source:id`.
    pub(crate) agent: String,
    /// The capability decided on.
    pub(crate) capability: String,
    /// When it was decided.
    pub(crate) at: DateTime<Utc>,
}

/// One event for the set, from either log.
#[derive(Debug, Clone)]
pub(crate) enum Fold {
    /// A grant-decision note.
    Denial(IdentityGrantAuditEvent),
    /// A UI decision from the control-plane audit.
    Decided(UiDecision),
}

/// One capability whose pinned bytes no longer match their pin, as the
/// backend reported it on one read of those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapabilityChange {
    /// The capability's path on disk.
    pub(crate) file: String,
    /// The hash of the bytes read.
    pub(crate) actual: String,
    /// The name it was last loaded under while its pin matched.
    pub(crate) loaded_as: Option<String>,
    /// The text that read hashed to `actual`; only a safe summary of it is
    /// ever shown.
    pub(crate) content: String,
}

/// The list route's whole answer, read under one lock.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct View {
    /// The open items, in the order they are shown.
    pub(crate) decisions: Vec<Value>,
    /// The revision these items are at.
    pub(crate) revision: u64,
    /// Kinds this build does not produce yet.
    pub(crate) missing_kinds: Vec<&'static str>,
    /// Kinds produced, but not yet for every case.
    pub(crate) partial_kinds: Vec<&'static str>,
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

    /// Fold one event read by a source's startup replay.
    pub(crate) fn replayed(&mut self, _pos: LogPos, _event: Fold) {}

    /// Fold one live event; held while any replay runs, applied after.
    pub(crate) fn live(&mut self, _pos: LogPos, _event: Fold) {}

    /// Mark `source`'s replay finished: once every replay has, the held live
    /// events are applied and the source is `Ready`.
    pub(crate) fn replay_done(&mut self, _source: Source) {}

    /// Replace one backend's capability changes; the source is `Ready` once
    /// a backend has reported.
    pub(crate) fn set_capability_changes(
        &mut self,
        _backend: &str,
        _changes: Vec<CapabilityChange>,
        _now: DateTime<Utc>,
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
    pub(crate) fn snapshot(&self, admin: bool) -> Option<(usize, u64)> {
        let view = self.view().filter(|_| admin)?;
        Some((view.decisions.len(), view.revision))
    }

    /// Whether every source has been read: none is `Unavailable` or unset.
    fn readable(&self) -> bool {
        [Source::Access, Source::ControlPlane, Source::Capability]
            .iter()
            .all(|source| matches!(self.health.get(source), Some(Health::Ready | Health::Absent)))
    }

    /// The list route's answer, or `None` while any source is `Unavailable`.
    pub(crate) fn view(&self) -> Option<View> {
        let _ = &self.key;
        self.readable().then(|| View {
            decisions: self.list(),
            revision: self.revision,
            missing_kinds: vec!["adopt"],
            partial_kinds: vec!["capability_changed"],
        })
    }

    /// The open items in display order.
    pub(crate) fn list(&self) -> Vec<Value> {
        Vec::new()
    }
}
