// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! UI-decision detail carried by a governance audit record: an
//! administrator's decline of an open access request, and the exact
//! refusals it closes.
//!
//! The record's `actor_id` is the administrator, its `reason` theirs, and
//! everything the decision is known by lives here. A decline closes only the
//! refusals the administrator was shown, by their place in the invocation
//! log, so a later refusal of the same capability opens the request again.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What the administrator decided.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UiDecisionKind {
    /// Declined: the shown refusals are closed and nothing is granted.
    Decline,
    /// Accepted: grant rows are written; the request closes once they are
    /// published, never by this record alone.
    Accept,
}

/// One capability of the request, with the refusals of it that were shown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct UiDecisionEntry {
    /// The capability refused.
    pub capability: String,
    /// Each refusal closed, as (`entry_hash`, chain counter) of its record
    /// in the invocation log.
    pub positions: Vec<(String, u64)>,
}

/// The values a UI-decision record carries beyond the common audit fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct UiDecisionRecord {
    /// The subject's authority.
    pub authority: String,
    /// The subject id.
    pub subject: String,
    /// The proven agent, `source:id`.
    pub agent: String,
    /// The scope digest the administrator was shown.
    pub scope_digest: String,
    /// Every capability decided, each with its refusals.
    pub entries: Vec<UiDecisionEntry>,
    /// What was decided. Absent on a decline written before accepts
    /// existed, which reads as a decline only when it names no rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<UiDecisionKind>,
    /// For an accept: each grant row it writes, as (row id, row digest).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<(String, String)>,
    /// For an accept with a ttl: the expiry, computed once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl UiDecisionRecord {
    /// Whether this record is a decline: an explicit one naming no rows,
    /// or one written before accepts existed (no kind, no rows). Anything
    /// else, an accept or a record that mixes the two, is not.
    #[must_use]
    pub fn is_decline(&self) -> bool {
        mutant!(
            "defaultflip",
            matches!(self.decision, Some(UiDecisionKind::Decline)),
            matches!(self.decision, None | Some(UiDecisionKind::Decline))
        ) && mutant!("norows", true, self.rows.is_empty())
            && mutant!("noexpiry", true, self.expires_at.is_none())
    }
}
