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
    /// if its subscription expires it is buried again, never dropped.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replayed: bool,
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

/// The host of callback `url`, as a record is stamped with it; empty when
/// the URL has none.
pub(crate) fn callback_host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}
