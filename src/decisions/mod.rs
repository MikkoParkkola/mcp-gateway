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

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::identity_grants::{
    GrantScope, GrantSubject, IdentityGrant, IdentityGrantAuditEvent, IdentityGrantDecisionReason,
};

mod display;
mod items;
mod record;
pub(crate) use items::OpenRequest;
pub(crate) use record::{decision_record, decisions_from_record, decisions_of, event_id};

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
    /// Client config files on this host, through the shared discovery cache.
    Discovery,
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

/// Which record an event is: the replay and live delivery can both hand
/// over one record, and its entry hash makes the second arrival a repeat.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LogPos {
    /// The log the event is in.
    pub(crate) log: Source,
    /// The record's `entry_hash`, unique in its log's chain.
    pub(crate) entry: String,
    /// The record's chain counter: its place in the log, across segments.
    pub(crate) counter: u64,
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
    /// The refusals it closes, by log position: exactly the ones the admin
    /// was shown. A later refusal, even at an equal time, has another
    /// position and stays open.
    pub(crate) closes: BTreeSet<LogPos>,
}

/// One event for the set, from either log.
#[derive(Debug, Clone)]
pub(crate) enum Fold {
    /// A grant-decision note.
    Denial(IdentityGrantAuditEvent),
    /// A UI decision.
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
/// by its log position, and the refusals UI decisions closed. Kept whether
/// or not an item is open, so folding is a union and order cannot change it.
#[derive(Debug, Clone, Default)]
struct Requested {
    refused: BTreeMap<LogPos, DateTime<Utc>>,
    tool: Option<String>,
    scope: Option<GrantScope>,
    /// Refusals a UI decision closed, by log position.
    closed: BTreeSet<LogPos>,
}

impl Requested {
    /// The refusals no UI decision closed and still kept: at or after the
    /// log's `edge` counter.
    fn pending(&self, edge: Option<u64>) -> impl Iterator<Item = &DateTime<Utc>> {
        self.pending_refusals(edge).map(|(_, at)| at)
    }

    /// The same refusals with their log positions: what an admin was shown,
    /// and what a scope digest must cover.
    fn pending_refusals(
        &self,
        edge: Option<u64>,
    ) -> impl Iterator<Item = (&LogPos, &DateTime<Utc>)> {
        self.refused
            .iter()
            .filter(move |(pos, _)| edge.is_none_or(|edge| pos.counter >= edge))
            .filter(move |(pos, _)| !self.closed.contains(*pos))
    }
}

/// Live events held while a replay runs: past this, one is dropped and the
/// replay runs again, so a replay that cannot finish never grows memory.
const HELD_CAP: usize = 4096;

/// The decision set: open items, a revision that rises on any visible change,
/// and each source's health.
pub(crate) struct DecisionSet {
    key: [u8; 32],
    health: BTreeMap<Source, Health>,
    revision: u64,
    requested: BTreeMap<(AccessKey, String), Requested>,
    grants: Vec<IdentityGrant>,
    now: Option<DateTime<Utc>>,
    edge: Option<u64>,
    held: Vec<(LogPos, Fold)>,
    /// Each log a live event was dropped from because `held` was full: that
    /// log's replay must run again before its source can be ready.
    held_lost: std::collections::BTreeSet<Source>,
    changes: BTreeMap<(String, String), CapabilityChange>,
    adopt: Vec<AdoptFind>,
    unreadable: Vec<UnreadableFile>,
    /// The generation of the discovery listing `adopt` and `unreadable`
    /// came from.
    discovery_generation: Option<u64>,
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
            held_lost: std::collections::BTreeSet::new(),
            changes: BTreeMap::new(),
            adopt: Vec::new(),
            unreadable: Vec::new(),
            discovery_generation: None,
            first_seen: BTreeMap::new(),
            items: Vec::new(),
        }
    }

    /// Record a source's health.
    pub(crate) fn set_health(&mut self, source: Source, health: Health) {
        self.health.insert(source, health);
        self.refresh();
    }

    /// Fold one event read by a source's startup replay. Nothing is shown
    /// until the replay ends, so the items are rebuilt once, at its end.
    pub(crate) fn replayed(&mut self, pos: LogPos, event: Fold) {
        self.fold(pos, event);
    }

    /// Fold one live event; held while any replay runs, applied after.
    pub(crate) fn live(&mut self, pos: LogPos, event: Fold) {
        if self.replaying() {
            if self.held.len() < HELD_CAP {
                self.held.push((pos, event));
            } else {
                // The log keeps it: the next replay reads it back.
                self.held_lost.insert(pos.log);
            }
        } else {
            self.fold(pos, event);
            self.refresh();
        }
    }

    /// Mark `source`'s replay finished: once every replay has, the held live
    /// events are applied and the source is `Ready`. If a held event was
    /// dropped meanwhile, the source stays `Unavailable` and this answers
    /// `false`: the replay must run again to read it back from the log.
    pub(crate) fn replay_done(&mut self, source: Source) -> bool {
        if self.held_lost.remove(&source) {
            // This log's held events are re-read by its next replay; another
            // log's stay held for its own.
            self.held.retain(|(pos, _)| pos.log != source);
            self.health.insert(source, Health::Unavailable);
            self.refresh();
            return false;
        }
        self.health.insert(source, Health::Ready);
        if !self.replaying() {
            for (pos, event) in std::mem::take(&mut self.held) {
                self.fold(pos, event);
            }
        }
        self.refresh();
        true
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
            self.changes
                .insert((backend.to_string(), change.file.clone()), change);
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

    /// Close every access item whose refusals all left the log: their records'
    /// counters are below `edge`, the oldest kept record's.
    pub(crate) fn evict_before(&mut self, edge: u64) {
        self.edge = Some(self.edge.map_or(edge, |old| old.max(edge)));
        // Refusals whose record left the log can never count again.
        self.requested.retain(|_, requested| {
            requested.refused.retain(|pos, _| pos.counter >= edge);
            requested.closed.retain(|pos| pos.counter >= edge);
            !requested.refused.is_empty() || !requested.closed.is_empty()
        });
        self.refresh();
    }

    /// Whether a log's replay has not finished: live events wait for it.
    fn replaying(&self) -> bool {
        [Source::Access, Source::ControlPlane].iter().any(|source| {
            !matches!(
                self.health.get(source),
                Some(Health::Ready | Health::Absent)
            )
        })
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
            Fold::Decided(decision) => self.fold_decided(decision),
        }
    }

    /// Apply one UI decision: a union, so order and repeats change nothing.
    fn fold_decided(&mut self, decision: UiDecision) {
        let key = AccessKey {
            authority: decision.authority,
            subject: decision.subject,
            agent: decision.agent,
        };
        let requested = self
            .requested
            .entry((key, decision.capability))
            .or_default();
        mutant!(
            "closeall",
            {
                let all: Vec<_> = requested.refused.keys().cloned().collect();
                requested.closed.extend(all)
            },
            requested.closed.extend(decision.closes)
        );
    }

    /// Apply UI decisions now, never held behind a replay: the resolve route
    /// folds what it just wrote so the item leaves the queue at once. A
    /// decision is order-independent, so the log's own delivery of the same
    /// record later changes nothing.
    pub(crate) fn apply_decisions(&mut self, decisions: Vec<UiDecision>) {
        for decision in decisions {
            self.fold_decided(decision);
        }
        self.refresh();
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
        let Some(subject) = GrantSubject::new(&key.authority, &key.subject, None).ok() else {
            return false;
        };
        self.grants.iter().any(|grant| {
            grant.covers_noted(
                &subject,
                &key.agent,
                capability,
                requested.tool.as_deref(),
                scope,
                now,
            )
        })
    }

    /// The open count and revision, or `None` while any source is not yet
    /// readable. In memory, never blocks, and copies no item. Who may read it
    /// is the route's guard's question, not the set's.
    pub(crate) fn snapshot(&self) -> Option<(usize, u64)> {
        self.readable().then_some((self.items.len(), self.revision))
    }

    /// Each source not yet readable, and why: `replaying` before it first
    /// reported, `unreadable` when it reported it cannot be read.
    pub(crate) fn unavailable(&self) -> Vec<(&'static str, &'static str)> {
        [
            (Source::Access, "grant_decisions"),
            (Source::ControlPlane, "ui_decisions"),
            (Source::Capability, "capability_changes"),
            (Source::Discovery, "discovery"),
        ]
        .into_iter()
        .filter_map(|(source, name)| match self.health.get(&source) {
            None => Some((name, "replaying")),
            Some(Health::Unavailable) => Some((name, "unreadable")),
            Some(Health::Ready | Health::Absent) => None,
        })
        .collect()
    }

    /// Whether every source has been read: none is `Unavailable` or unset.
    fn readable(&self) -> bool {
        [
            Source::Access,
            Source::ControlPlane,
            Source::Capability,
            Source::Discovery,
        ]
        .iter()
        .all(|source| {
            matches!(
                self.health.get(source),
                Some(Health::Ready | Health::Absent)
            )
        })
    }

    /// The list route's answer, or `None` while any source is `Unavailable`.
    pub(crate) fn view(&self) -> Option<View> {
        self.readable().then(|| View {
            decisions: self.items.clone(),
            revision: self.revision,
            missing_kinds: Vec::new(),
            partial_kinds: vec!["capability_changed"],
        })
    }

    /// The open items in display order.
    #[cfg(test)]
    pub(crate) fn list(&self) -> Vec<Value> {
        self.items.clone()
    }
}

/// The kind a grant decision is written as.
pub(crate) const GRANT_DECISION_KIND: &str = "identity_grant_decision";

/// An unmanaged client find the set shows as an adopt decision: only what the
/// discovery route may show, never a value (ADR-021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdoptFind {
    pub(crate) find_id: String,
    pub(crate) name: String,
    pub(crate) source: crate::discovery::DiscoverySource,
    pub(crate) config_file: Option<String>,
    pub(crate) transport: &'static str,
    pub(crate) command: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) severity: crate::discovery::shadow::ShadowRiskSeverity,
}

/// Why a client config file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnreadableReason {
    /// Not a regular file, or larger than any client config: never read.
    NotAReadableFile,
    /// The gateway may not open it.
    NoPermission,
    /// It was read but did not parse, or the read failed otherwise.
    DidNotParse,
}

impl UnreadableReason {
    /// The reason as the item shows it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotAReadableFile => "not_a_readable_file",
            Self::NoPermission => "no_permission",
            Self::DidNotParse => "did_not_parse",
        }
    }
}

/// A client config file that exists but could not be read: its file name and
/// a keyed digest of its path, never the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnreadableFile {
    pub(crate) source: crate::discovery::DiscoverySource,
    pub(crate) file: String,
    pub(crate) path_digest: String,
    pub(crate) reason: UnreadableReason,
}

impl DecisionSet {
    /// Replace the discovery source's adopt finds and unreadable files, from
    /// the listing of `generation`; the source is `Ready` from its first
    /// listing on. A listing older than the one held is ignored: a reader
    /// that took a listing before a newer one landed cannot put it back. The
    /// same generation again applies, so eligibility is re-judged.
    pub(crate) fn set_discovery(
        &mut self,
        finds: Vec<AdoptFind>,
        unreadable: Vec<UnreadableFile>,
        generation: u64,
        now: DateTime<Utc>,
    ) {
        if self
            .discovery_generation
            .is_some_and(|held| generation < held)
        {
            return;
        }
        self.discovery_generation = Some(generation);
        self.adopt = finds;
        self.unreadable = unreadable;
        self.health.insert(Source::Discovery, Health::Ready);
        self.now = Some(now);
        self.refresh();
    }

    /// The discovery source timed out with no listing to fall back on: the
    /// count is unavailable until a scan lands.
    pub(crate) fn discovery_down(&mut self) {
        self.health.insert(Source::Discovery, Health::Unavailable);
        self.refresh();
    }
}

/// A written grant-decision record read back into the event it was noted
/// from, live or replayed alike; `None` for a record that names no subject.
pub(crate) fn denial_from_record(record: &Map<String, Value>) -> Option<IdentityGrantAuditEvent> {
    let text = |key: &str| record.get(key).and_then(Value::as_str);
    let (reason, scope) = reason_and_scope(record)?;
    let subject = record.get("subject")?;
    let timestamp = DateTime::parse_from_rfc3339(text("timestamp")?).ok()?;
    Some(IdentityGrantAuditEvent {
        event: GRANT_DECISION_KIND.to_string(),
        timestamp: timestamp.with_timezone(&Utc),
        // Public and shared capabilities are never recorded; of the rest only
        // a matched grant allowed the call.
        allowed: reason == IdentityGrantDecisionReason::GrantMatched,
        reason,
        // Through the checked constructor: a record naming no one is no request.
        subject: Some(
            GrantSubject::new(
                subject.get("authority")?.as_str()?,
                subject.get("subject")?.as_str()?,
                None,
            )
            .ok()?,
        ),
        agent_id: text("agent_id").map(str::to_string),
        capability: text("capability")?.to_string(),
        tool: text("tool").map(str::to_string),
        scope,
        grant_id: text("grant_id").map(str::to_string),
    })
}

/// A record's decision reason and requested scope: the two typed fields that
/// are no identity.
fn reason_and_scope(
    record: &Map<String, Value>,
) -> Option<(IdentityGrantDecisionReason, GrantScope)> {
    let reason = serde_json::from_value(record.get("reason")?.clone()).ok()?;
    let scope = serde_json::from_value(record.get("scope")?.clone()).ok()?;
    Some((reason, scope))
}

/// The set as the gateway holds it: one lock, read by the list route and the
/// stream's snapshot, written by the producers.
pub(crate) struct Shared {
    set: parking_lot::RwLock<DecisionSet>,
    /// Serializes the resolve route: one resolve at a time, so a second
    /// resolve of an id sees what the first one changed.
    resolve: tokio::sync::Mutex<()>,
    /// What each resolved item id answered, one per scope digest it was
    /// resolved at (a later refusal reopens a request under the same id), so
    /// a retry of any of them is answered from this and writes nothing. Held
    /// in memory: item ids do not survive a restart.
    outcomes: parking_lot::Mutex<BTreeMap<String, Vec<Outcome>>>,
}

/// What a resolve recorded, for the retry of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// The id of the note it wrote.
    pub(crate) event_id: String,
    /// The scope digest it was resolved at.
    pub(crate) scope_digest: String,
}

/// What an open decision id names.
pub(crate) enum Lookup {
    /// An access request, with the raw parts a decision names.
    Access(Box<items::OpenRequest>),
    /// Another kind of decision, which a resolve does not take.
    Other,
}

impl Shared {
    /// A handle over a set keyed by `key`.
    pub(crate) fn with_key(key: [u8; 32]) -> Self {
        Self {
            set: parking_lot::RwLock::new(DecisionSet::with_key(key)),
            resolve: tokio::sync::Mutex::new(()),
            outcomes: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }

    /// What resolving `id` at `scope_digest` answered, if it was resolved
    /// there.
    pub(crate) fn outcome(&self, id: &str, scope_digest: &str) -> Option<Outcome> {
        self.outcomes
            .lock()
            .get(id)?
            .iter()
            .find(|done| mutant!("reopenorder", true, done.scope_digest == scope_digest))
            .cloned()
    }

    /// Whether `id` was resolved here, at any digest.
    pub(crate) fn resolved(&self, id: &str) -> bool {
        self.outcomes.lock().contains_key(id)
    }

    /// Remember what resolving `id` answered.
    pub(crate) fn remember(&self, id: &str, outcome: Outcome) {
        self.outcomes
            .lock()
            .entry(id.to_owned())
            .or_default()
            .push(outcome);
    }

    /// Hold the resolve mutex. Taken before anything else of a resolve.
    pub(crate) async fn resolving(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.resolve.lock().await
    }

    /// The open access request with `id`, read under one lock: the listed
    /// item and the raw refusal positions its digest covers. `Err` names the
    /// sources not yet readable; `Ok(None)` is no such open request.
    pub(crate) fn request(
        &self,
        id: &str,
    ) -> Result<Option<Lookup>, Vec<(&'static str, &'static str)>> {
        let set = self.set.read();
        if set.view().is_none() {
            return Err(set.unavailable());
        }
        if let Some(request) = items::open_request(&set, id) {
            return Ok(Some(Lookup::Access(Box::new(request))));
        }
        Ok(set
            .items
            .iter()
            .any(|item| item.get("id").and_then(Value::as_str) == Some(id))
            .then_some(Lookup::Other))
    }

    /// Apply `change` under the write lock.
    pub(crate) fn update<T>(&self, change: impl FnOnce(&mut DecisionSet) -> T) -> T {
        change(&mut self.set.write())
    }

    /// [`DecisionSet::snapshot`] under the read lock.
    pub(crate) fn snapshot(&self) -> Option<(usize, u64)> {
        self.set.read().snapshot()
    }

    /// [`DecisionSet::view`] under the read lock, or the sources not yet
    /// readable.
    pub(crate) fn view(&self) -> Result<View, Vec<(&'static str, &'static str)>> {
        let set = self.set.read();
        set.view().ok_or_else(|| set.unavailable())
    }
}

/// The subject, agent and capability a note refused for a missing grant, or
/// `None` for every note the projection excludes: allowed, another reason, no
/// subject or no proven agent. `MissingGrant` is reached only for a personal
/// capability.
fn access_key(event: &IdentityGrantAuditEvent) -> Option<(AccessKey, String)> {
    if event.allowed || event.reason != IdentityGrantDecisionReason::MissingGrant {
        return None;
    }
    // The checked constructor's rule: a subject that names no one is none.
    let subject = event.subject.as_ref().filter(|s| {
        GrantSubject::new(s.authority(), s.subject(), None)
            .ok()
            .is_some()
    })?;
    let agent = event.agent_id.clone().filter(|agent| !agent.is_empty())?;
    let key = AccessKey {
        authority: subject.authority().to_owned(),
        subject: subject.subject().to_owned(),
        agent,
    };
    Some((key, event.capability.clone()))
}
