// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change detail carried by a governance audit record (MIK-7570.AUDIT.4).
//!
//! A grant change applied through the grant file has no authenticated actor,
//! so its record's `actor_id` is the literal `unknown` and everything the
//! change is known by lives here. See
//! `docs/design/2026-09-28-grant-change-journal.md` section 2.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What a grant record says happened.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GrantChangeVerb {
    /// The CLI added a new grant id.
    Add,
    /// The CLI overwrote an existing grant id (`--replace`).
    Replace,
    /// The CLI revoked a grant.
    Revoke,
    /// Startup snapshot: this grant was active and served.
    Loaded,
    /// Startup snapshot closing record; `count` holds the number of `loaded` records.
    LoadedComplete,
    /// The grant file changed with no journal entry to account for it.
    OutOfBand,
    /// History here cannot be stated exactly (an earlier record was lost, or the journal was damaged).
    Indeterminate,
}

/// The values a grant record carries beyond the common audit fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct GrantChangeRecord {
    /// What happened.
    pub verb: GrantChangeVerb,
    /// `sha256:<hex>` of the grant row after the change; `None` for a deleted row or a closing record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Expiry of the row after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The CLI's clock at the change (journal records only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<DateTime<Utc>>,
    /// OS account that ran the CLI. Unauthenticated: a hint, not an identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_account_hint: Option<String>,
    /// Startup run id (snapshot records only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Active grants in the snapshot (closing record only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

impl GrantChangeRecord {
    /// A record with only its verb set.
    #[must_use]
    pub const fn new(verb: GrantChangeVerb) -> Self {
        Self {
            verb,
            digest: None,
            expires_at: None,
            occurred_at: None,
            os_account_hint: None,
            run_id: None,
            count: None,
        }
    }
}
