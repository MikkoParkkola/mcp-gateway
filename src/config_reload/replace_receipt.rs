// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Revoke's postcondition, inspected only inside the shared writer's locks.
#![expect(dead_code, reason = "revoke handler wiring follows in the next slice")]

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

use super::FileRevision;
use crate::config_reload::LiveConfig;
use crate::gateway::auth::digest_tag_of;

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
        let present = auth.api_keys().iter().any(|key| {
            key.name == self.name
                || tags.contains(&digest_tag_of(&key.digest))
                || key
                    .previous
                    .as_ref()
                    .is_some_and(|slot| tags.contains(&digest_tag_of(&slot.digest)))
        });
        let bearer_present = auth.bearer_token.as_deref().is_some_and(|token| {
            tags.contains(&digest_tag_of(&Sha256::digest(token.as_bytes()).into()))
        });
        if present || bearer_present {
            return Err("revoke postcondition failed after durable completion".into());
        }
        Ok(RevokeReceipt {
            name: self.name,
            revision,
        })
    }
}
