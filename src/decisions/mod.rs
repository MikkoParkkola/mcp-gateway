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

use crate::identity_grants::{
    GrantScope, GrantSubject, IdentityGrant, IdentityGrantAuditEvent, IdentityGrantDecisionReason,
};

mod display;
mod items;

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

/// A subject and proven agent: whose access requests are grouped together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AccessKey {
    authority: String,
    subject: String,
    agent: String,
}

/// What is known of one (subject and agent, capability): every refused call
/// by its log position, and the newest UI decision. Kept whether or not an
/// item is open, so folding is a max-merge and order cannot change it.
#[derive(Debug, Clone, Default)]
struct Requested {
    refused: BTreeMap<LogPos, DateTime<Utc>>,
    tool: Option<String>,
    scope: Option<GrantScope>,
    decided: Option<DateTime<Utc>>,
}

impl Requested {
    /// The refusals newer than the last UI decision and not before `edge`.
    fn pending(&self, edge: Option<DateTime<Utc>>) -> impl Iterator<Item = &DateTime<Utc>> {
        self.refused
            .values()
            .filter(move |at| self.decided.is_none_or(|decided| **at > decided))
            .filter(move |at| edge.is_none_or(|edge| **at >= edge))
    }
}

/// The decision set: open items, a revision that rises on any visible change,
/// and each source's health.
pub(crate) struct DecisionSet {
    key: [u8; 32],
    health: BTreeMap<Source, Health>,
    revision: u64,
    requested: BTreeMap<(AccessKey, String), Requested>,
    grants: Vec<IdentityGrant>,
    now: Option<DateTime<Utc>>,
    edge: Option<DateTime<Utc>>,
    held: Vec<(LogPos, Fold)>,
    changes: BTreeMap<(String, String), CapabilityChange>,
    first_seen: BTreeMap<String, DateTime<Utc>>,
    items: Vec<Value>,
}

impl DecisionSet {
    /// A set whose ids are keyed by `key`; every source starts `Unavailable`.
    pub(crate) fn with_key(key: [u8; 32]) -> Self {
        Self {
            key,
            health: BTreeMap::new(),
            revision: 0,
            requested: BTreeMap::new(),
            grants: Vec::new(),
            now: None,
            edge: None,
            held: Vec::new(),
            changes: BTreeMap::new(),
            first_seen: BTreeMap::new(),
            items: Vec::new(),
        }
    }

    /// Record a source's health.
    pub(crate) fn set_health(&mut self, source: Source, health: Health) {
        self.health.insert(source, health);
        self.refresh();
    }

    /// Fold one event read by a source's startup replay.
    pub(crate) fn replayed(&mut self, pos: LogPos, event: Fold) {
        self.fold(pos, event);
        self.refresh();
    }

    /// Fold one live event; held while any replay runs, applied after.
    pub(crate) fn live(&mut self, pos: LogPos, event: Fold) {
        if self.replaying() {
            self.held.push((pos, event));
        } else {
            self.fold(pos, event);
            self.refresh();
        }
    }

    /// Mark `source`'s replay finished: once every replay has, the held live
    /// events are applied and the source is `Ready`.
    pub(crate) fn replay_done(&mut self, source: Source) {
        self.health.insert(source, Health::Ready);
        if !self.replaying() {
            for (pos, event) in std::mem::take(&mut self.held) {
                self.fold(pos, event);
            }
        }
        self.refresh();
    }

    /// Replace one backend's capability changes; the source is `Ready` once
    /// a backend has reported.
    pub(crate) fn set_capability_changes(
        &mut self,
        backend: &str,
        changes: Vec<CapabilityChange>,
        now: DateTime<Utc>,
    ) {
        self.changes.retain(|(owner, _), _| owner != backend);
        for change in changes {
            self.changes.insert((backend.to_string(), change.file.clone()), change);
        }
        self.health.insert(Source::Capability, Health::Ready);
        self.now = Some(now);
        self.refresh();
    }

    /// Replace the live grant rows and re-check every open item at `now`.
    pub(crate) fn set_grants(&mut self, grants: Vec<IdentityGrant>, now: DateTime<Utc>) {
        self.grants = grants;
        self.expire(now);
    }

    /// Re-check every open item against the held grant rows at `now`.
    pub(crate) fn expire(&mut self, now: DateTime<Utc>) {
        self.now = Some(now);
        self.refresh();
    }

    /// Close every access item whose newest denial is older than `edge`.
    pub(crate) fn evict_before(&mut self, edge: DateTime<Utc>) {
        self.edge = Some(self.edge.map_or(edge, |old| old.max(edge)));
        // Refusals past the edge can never count again: drop them.
        self.requested.retain(|_, requested| {
            requested.refused.retain(|_, at| *at >= edge);
            !requested.refused.is_empty() || requested.decided.is_some()
        });
        self.refresh();
    }

    /// Whether a log's replay has not finished: live events wait for it.
    fn replaying(&self) -> bool {
        [Source::Access, Source::ControlPlane]
            .iter()
            .any(|source| !matches!(self.health.get(source), Some(Health::Ready | Health::Absent)))
    }

    /// Apply one event. A repeat at the same position changes nothing.
    fn fold(&mut self, pos: LogPos, event: Fold) {
        match event {
            Fold::Denial(event) => {
                let Some((key, capability)) = access_key(&event) else {
                    return;
                };
                let requested = self.requested.entry((key, capability)).or_default();
                let newest = requested.refused.values().max().copied();
                requested.refused.insert(pos, event.timestamp);
                if newest.is_none_or(|newest| event.timestamp >= newest) {
                    requested.tool = event.tool;
                    requested.scope = Some(event.scope);
                }
            }
            Fold::Decided(decision) => {
                let key = AccessKey {
                    authority: decision.authority,
                    subject: decision.subject,
                    agent: decision.agent,
                };
                let requested = self.requested.entry((key, decision.capability)).or_default();
                requested.decided = Some(requested.decided.map_or(decision.at, |old| old.max(decision.at)));
            }
        }
    }

    /// Rebuild the items; the revision rises only if what is shown changed.
    fn refresh(&mut self) {
        let items = items::build(self);
        if items != self.items {
            self.items = items;
            self.revision += 1;
        }
    }

    /// Whether a live grant row now allows what `(key, capability)` refused.
    fn covered(&self, key: &AccessKey, capability: &str, requested: &Requested) -> bool {
        let (Some(now), Some(scope)) = (self.now, requested.scope.as_ref()) else {
            return false;
        };
        let subject = GrantSubject::new(&key.authority, &key.subject, None);
        self.grants.iter().any(|grant| {
            grant.covers_noted(&subject, &key.agent, capability, requested.tool.as_deref(), scope, now)
        })
    }

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
        self.readable().then(|| View {
            decisions: self.items.clone(),
            revision: self.revision,
            missing_kinds: vec!["adopt"],
            partial_kinds: vec!["capability_changed"],
        })
    }

    /// The open items in display order.
    pub(crate) fn list(&self) -> Vec<Value> {
        self.items.clone()
    }
}

/// The subject, agent and capability a note refused for a missing grant, or
/// `None` for every note A1 excludes: allowed, another reason, no subject or
/// no proven agent. MissingGrant is reached only for a personal capability.
fn access_key(event: &IdentityGrantAuditEvent) -> Option<(AccessKey, String)> {
    if event.allowed || event.reason != IdentityGrantDecisionReason::MissingGrant {
        return None;
    }
    let subject = event.subject.as_ref().filter(|s| !s.authority.is_empty() && !s.subject.is_empty())?;
    let agent = event.agent_id.clone().filter(|agent| !agent.is_empty())?;
    let key = AccessKey {
        authority: subject.authority.clone(),
        subject: subject.subject.clone(),
        agent,
    };
    Some((key, event.capability.clone()))
}
