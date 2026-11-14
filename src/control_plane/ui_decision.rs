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

use serde::{Deserialize, Serialize};

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
    /// Every capability declined, each with its refusals.
    pub entries: Vec<UiDecisionEntry>,
}
