// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Revoke's postcondition, inspected only inside the shared writer's locks.
#![cfg_attr(
    not(feature = "webui"),
    expect(dead_code, reason = "revoke requires webui")
)]

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

#[cfg(test)]
use super::order;
use super::{Audit, FileRevision, Intent, ReplaceError, ReplaceOutcome, audit};
use crate::config_reload::LiveConfig;
use crate::gateway::auth::{digest_tag_of, presented_digest};

#[cfg(test)]
#[path = "replace_receipt_tests.rs"]
mod tests;

/// Filled by target selection under the writer locks, never from a request snapshot.
pub(crate) struct RevokeCheck {
    pub(crate) name: String,
    pub(crate) tags: Arc<OnceLock<BTreeSet<String>>>,
    /// The gateway's actual authorization table, also when contexts are split.
    pub(crate) live: Arc<LiveConfig>,
}

/// Evidence of durable completion and absence in the published generation.
#[derive(Debug)]
pub(crate) struct RevokeReceipt {
    pub(crate) name: String,
    pub(crate) revision: FileRevision,
}

impl RevokeCheck {
    pub(super) fn confirm(self, revision: FileRevision) -> Result<RevokeReceipt, String> {
        let tags = self
            .tags
            .get()
            .filter(|tags| !tags.is_empty())
            .ok_or_else(|| "revoke target was not selected under the writer locks".to_owned())?;
        let generation = self.live.generation();
        let auth = generation.auth();
        let present = auth
            .api_keys()
            .iter()
            .any(|key| key.name == self.name || key.accepted_tags().any(|tag| tags.contains(&tag)));
        let bearer_present = auth
            .bearer_token
            .as_deref()
            .is_some_and(|token| tags.contains(&digest_tag_of(&presented_digest(token))));
        if present || bearer_present {
            return Err("revoke postcondition failed after durable completion".into());
        }
        Ok(RevokeReceipt {
            name: self.name,
            revision,
        })
    }
}

/// Append the write intent before creating secrets or changing config bytes.
pub(super) fn record_write_intent(
    audit: &mut Audit,
    current: &[u8],
    unchanged: bool,
    recovery_intent_id: Option<audit::IntentId>,
    target: &std::path::Path,
) -> Result<(), ReplaceError> {
    #[cfg(not(test))]
    let _ = target;
    if let Audit::Required { sink, kind, writer } = audit {
        let intent = Intent {
            kind: kind.clone(),
            base: FileRevision::of(current),
            outside_change: unchanged,
            recovery_intent_id,
            writer: writer.clone(),
        };
        sink.append(&intent).map_err(|e| {
            ReplaceError::AuditRefused(format!(
                "the audit log refused this change's record; nothing was written: {e}"
            ))
        })?;
        #[cfg(test)]
        order::record(target, "intent");
    }
    Ok(())
}

/// Check the optional revoke receipt while the caller still holds both locks.
pub(super) fn check_revoke_receipt(
    result: Result<ReplaceOutcome, ReplaceError>,
    receipt: Option<RevokeCheck>,
    current: &[u8],
    target: &std::path::Path,
) -> Result<(ReplaceOutcome, Option<RevokeReceipt>), ReplaceError> {
    #[cfg(not(test))]
    let _ = target;
    result.and_then(|outcome| {
        #[cfg(test)]
        if receipt.is_some() {
            order::record(target, "reload");
        }
        let checked = receipt
            .map(|check| {
                check.confirm(
                    outcome
                        .revision
                        .clone()
                        .unwrap_or_else(|| FileRevision::of(current)),
                )
            })
            .transpose()
            .map_err(ReplaceError::Failed)?;
        #[cfg(test)]
        if checked.is_some() {
            order::record(target, "receipt");
        }
        Ok((outcome, checked))
    })
}
