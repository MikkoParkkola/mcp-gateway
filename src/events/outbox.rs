// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Outbox and dead-letter records (design §5): one pending delivery per
//! file under `outbox/`, one failed delivery per file under `dead/`. The
//! record holds the exact body bytes every attempt signs; the secret is
//! never copied here, it is read from the subscription at each attempt.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where a pending record stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutboxState {
    /// Waiting for `next_attempt_at`.
    Pending,
    /// An attempt is on the wire; a restart returns it to `Pending`.
    InFlight,
}

/// One pending delivery of one event to one subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OutboxRecord {
    pub v: u32,
    pub event_id: String,
    pub subscription_id: String,
    /// The event name: the audit tool and the budget's `events:<name>`.
    pub name: String,
    /// The backend whose visibility gates the event (audit `server`).
    pub backend: String,
    /// Owner-scoped (task) event: the attempt re-check needs a live credential,
    /// not a backend grant.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_scoped: bool,
    /// The callback host, stamped at fan-out from the subscription the record
    /// is for (its id hashes the URL, so the host cannot change under it).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub callback_host: String,
    /// The exact body bytes, base64.
    pub body_b64: String,
    /// Hashed tenant attribution of `data` (MIN.1), fixed at fan-out.
    #[serde(default)]
    pub tenants: Vec<String>,
    /// What `data` named before the event firewall redacted it (MIN.2 E1),
    /// fixed at fan-out for the read verdict at delivery. Absent on older
    /// records: they count as unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<crate::security::tenant_reads::ReadAttribution>,
    /// The `arg_keys` `attribution` was taken under: after a policy change
    /// it names tenants the new keys might see differently, so it counts
    /// only while they match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attribution_keys: Vec<String>,
    /// What the firewall decided about the payload at fan-out (`pass`,
    /// `redacted`, `block`, `none`); absent on older records, whose attempt
    /// records carry `unrecorded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<String>,
    /// Attempts started so far.
    pub attempt: u32,
    /// Of those, claims that sent nothing because the audit log refused
    /// them: they number the audit records but not the attempt limit.
    /// Absent on older records.
    #[serde(default)]
    pub unsent: u32,
    pub next_attempt_at: DateTime<Utc>,
    pub first_attempt_at: Option<DateTime<Utc>>,
    /// Fan-out time: the per-subscription delivery order.
    pub created_at: DateTime<Utc>,
    pub state: OutboxState,
    /// Category of the last failed attempt; never a body or a header.
    #[serde(default)]
    pub last_status: Option<String>,
    /// Settled dead, but the disk refused the dead letter: the record is
    /// buried again, never sent again. Written with the next claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_as: Option<DeadReason>,
    /// Placed by an operator replay (MIK-8061): its dead letter is gone, so
    /// if its subscription expires it is buried again, never dropped. Always
    /// written; a record written before the field existed may be a replay,
    /// so it reads as one and is kept rather than dropped.
    #[serde(default = "may_be_a_replay")]
    pub replayed: bool,
    /// What its row was observed under at fan-out: it is
    /// sent only while the row still is. `None` for a shared row, and on
    /// records written before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<ObservedUnder>,
    /// Set on the one notice that an ended row's incarnation has ended:
    /// it maps to the ended row, never to a live row
    /// under the same id. `None` on every event, and on older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_incarnation: Option<u64>,
}

/// A per-user row's observation as one value: its grant, the identity
/// config its key came from, and for passthrough the lease generation (hex;
/// never the token or a digest of it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObservedUnder {
    pub incarnation: u64,
    pub obs_basis: super::observation::ObsBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<String>,
}

impl OutboxRecord {
    /// Attempts that could have reached the callback: what the attempt
    /// limit and the backoff count.
    pub(crate) fn sends(&self) -> u32 {
        self.attempt.saturating_sub(self.unsent)
    }

    /// Whether this record outlives its subscription's expiry as a dead
    /// letter: it was replayed or tried, or it is on the wire (MIK-8061).
    pub(crate) fn needs_burial_at_expiry(&self) -> bool {
        self.replayed || self.sends() > 0 || self.state == OutboxState::InFlight
    }

    /// The body bytes, or `None` for a record whose body does not decode.
    pub(crate) fn body(&self) -> Option<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.body_b64)
            .ok()
    }

    /// The attribution, while the policy it was taken under still holds.
    pub(crate) fn attribution_under(
        &self,
        keys: &[String],
    ) -> Option<&crate::security::tenant_reads::ReadAttribution> {
        self.attribution
            .as_ref()
            .filter(|_| self.attribution_keys == keys)
    }

    pub(crate) fn file(event_id: &str) -> String {
        format!("{event_id}.json")
    }

    /// The ended row an ended-notice record is for, keyed as `State::ended`.
    pub(crate) fn ended_key(&self) -> Option<(String, u64)> {
        self.ended_incarnation
            .map(|incarnation| (self.subscription_id.clone(), incarnation))
    }

    /// Whether this record is an event for the live row under its id.
    pub(crate) fn is_event(&self) -> bool {
        self.ended_incarnation.is_none()
    }

    /// The worker's busy and rate key: the subscription id for an event,
    /// the id and incarnation for an ended notice, so a notice and a live
    /// successor under the same id never share a slot.
    pub(crate) fn busy_key(&self) -> String {
        match self.ended_incarnation {
            None => self.subscription_id.clone(),
            Some(incarnation) => ended_busy_key(&self.subscription_id, incarnation),
        }
    }
}

/// The busy key of the ended notice of `(id, incarnation)`.
pub(crate) fn ended_busy_key(id: &str, incarnation: u64) -> String {
    format!("{id}#{incarnation}")
}

/// Whether busy key `key` belongs to subscription `id`: its events or any
/// of its ended notices.
pub(crate) fn busy_key_of(key: &str, id: &str) -> bool {
    key.strip_prefix(id)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('#'))
}

/// The reserved event name of the gateway's own ended notice: no source may
/// offer or emit it (design D').
pub(crate) const ENDED_NAME: &str = "subscription.ended";

/// When and why a row ended, stamped on its ended file (design Y' 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EndedStamp {
    pub at: DateTime<Utc>,
    pub code: i64,
    /// The notice record this ending enqueued.
    pub event_id: String,
}

/// An ended row: the row as it was, with its ending. Persisted under
/// `ended/`, never `subs/`, so no live-row reader and no older binary loads
/// it as live (design Y'' 1).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EndedRow {
    #[serde(flatten)]
    pub row: super::records::Subscription,
    pub ended: EndedStamp,
}

impl std::fmt::Debug for EndedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The row's own Debug redacts the id, principal and secrets.
        f.debug_struct("EndedRow")
            .field("row", &self.row)
            .field("ended_at", &self.ended.at)
            .field("code", &self.ended.code)
            .finish_non_exhaustive()
    }
}

impl EndedRow {
    /// Its file under `ended/`: one per ended incarnation.
    pub(crate) fn file(id: &str, incarnation: u64) -> String {
        format!("{id}.{incarnation}.json")
    }

    /// The notice body (design D'): no `_meta`, no secret, principal,
    /// backend name or reason detail.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the revoke paths, a later step, call it")
    )]
    pub(crate) fn notice_body(&self) -> Vec<u8> {
        let message = match self.ended.code {
            -32011 => "NotFound",
            _ => "Forbidden",
        };
        let at = self
            .ended
            .at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        serde_json::to_vec(&serde_json::json!({
            "eventId": self.ended.event_id,
            "name": ENDED_NAME,
            "timestamp": at,
            "data": { "code": self.ended.code, "message": message, "endedAt": at },
            "cursor": null,
        }))
        .unwrap_or_default()
    }

    /// The one outbox record carrying this row's notice.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the revoke paths, a later step, call it")
    )]
    pub(crate) fn notice_record(&self) -> OutboxRecord {
        OutboxRecord {
            v: 1,
            event_id: self.ended.event_id.clone(),
            subscription_id: self.row.id.clone(),
            name: ENDED_NAME.to_owned(),
            backend: String::new(),
            owner_scoped: true,
            callback_host: callback_host_of(&self.row.url),
            body_b64: base64::engine::general_purpose::STANDARD.encode(self.notice_body()),
            tenants: Vec::new(),
            attribution: None,
            attribution_keys: Vec::new(),
            firewall: None,
            attempt: 0,
            unsent: 0,
            next_attempt_at: self.ended.at,
            first_attempt_at: None,
            created_at: self.ended.at,
            state: OutboxState::Pending,
            last_status: None,
            dead_as: None,
            replayed: false,
            observed: None,
            ended_incarnation: Some(self.row.incarnation),
        }
    }
}

/// Why a delivery was dead-lettered (design §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeadReason {
    Gone,
    TooLarge,
    Exhausted,
    FirewallBlocked,
    Budget,
    /// The cross-tenant read verdict withheld it (MIN.2 E1).
    Tenant,
    /// Its subscription expired with it replayed or tried (MIK-8061).
    #[serde(rename = "subscription_expired")]
    Expired,
    /// The row it was observed for changed under it: re-granted, a new
    /// identity config, or a rotated lease.
    #[serde(rename = "observation_changed")]
    Observation,
}

impl DeadReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Gone => "gone",
            Self::TooLarge => "too_large",
            Self::Exhausted => "exhausted",
            Self::FirewallBlocked => "firewall_blocked",
            Self::Budget => "budget",
            Self::Tenant => "tenant",
            Self::Expired => "subscription_expired",
            Self::Observation => "observation_changed",
        }
    }
}

/// A dead letter: the outbox fields plus why and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeadLetter {
    #[serde(flatten)]
    pub record: OutboxRecord,
    pub reason: String,
    pub dead_at: DateTime<Utc>,
}

/// Bounds on the dead-letter directory.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeadPolicy {
    pub retention: std::time::Duration,
    pub max_records: usize,
    pub max_bytes: u64,
}

/// Bounds on the outbox, checked before every insert.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboxCaps {
    pub global: usize,
    pub per_subscription: usize,
}

/// What an insert did. A drop never touches a record already pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Enqueued {
    Written,
    DroppedGlobal,
    DroppedPerSubscription,
    /// The subscription went away before the write: nothing to deliver.
    NoSubscription,
}

/// A dead letter evicted by retention or a cap, for the audit record.
#[derive(Debug, Clone)]
pub(crate) struct Evicted {
    pub event_id: String,
    pub subscription_id: String,
    pub reason: String,
}

/// `replayed` for a record written before the field: it may be a replay,
/// so it is buried at expiry rather than dropped.
const fn may_be_a_replay() -> bool {
    true
}

/// The host of callback `url`, as a record is stamped with it; empty when
/// the URL has none.
pub(crate) fn callback_host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}
