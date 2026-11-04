// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grants file as written, read with the loader's own types, before its
//! rows' subjects are checked. Every row whose subject or owner names no one
//! is then named in one refusal: the same parse, so its ids, duplicate-field
//! refusal and scalar handling are the loader's, by construction.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::subject::RawGrantSubject;
use super::{GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile};

#[derive(Deserialize)]
pub(super) struct RawGrantFile {
    #[serde(default = "super::default_identity_grants_file_schema_version")]
    schema_version: String,
    #[serde(default)]
    grants: Vec<RawGrant>,
}

/// [`IdentityGrant`]'s fields, with the subject and owner unchecked. The
/// conversion below writes `IdentityGrant` as a struct literal, so a field
/// added there and not here does not compile.
#[derive(Deserialize)]
struct RawGrant {
    grant_id: String,
    subject: RawGrantSubject,
    agent: GrantAgent,
    capability: String,
    tool: Option<String>,
    scope: GrantScope,
    owner: Option<RawGrantSubject>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    provenance: String,
    reason: String,
}

impl TryFrom<RawGrantFile> for IdentityGrantFile {
    type Error = String;

    fn try_from(raw: RawGrantFile) -> Result<Self, Self::Error> {
        let mut grants = Vec::with_capacity(raw.grants.len());
        let mut nameless = Vec::new();
        // The gateway kept the last row per id, so a nameless row may have
        // been shadowing another row with its id: deleting it would make that
        // row active, and the refusal says so rather than advising blindly.
        let mut uses = std::collections::HashMap::<String, usize>::new();
        for row in &raw.grants {
            *uses.entry(row.grant_id.clone()).or_default() += 1;
        }
        for row in raw.grants {
            let subject = GrantSubject::try_from(row.subject);
            let owner = row.owner.map(GrantSubject::try_from).transpose();
            match (subject, owner) {
                (Ok(subject), Ok(owner)) => grants.push(IdentityGrant {
                    grant_id: row.grant_id,
                    subject,
                    agent: row.agent,
                    capability: row.capability,
                    tool: row.tool,
                    scope: row.scope,
                    owner,
                    expires_at: row.expires_at,
                    revoked_at: row.revoked_at,
                    provenance: row.provenance,
                    reason: row.reason,
                }),
                (subject, owner) => {
                    let fields: Vec<&str> =
                        [("subject", subject.is_err()), ("owner", owner.is_err())]
                            .into_iter()
                            .filter_map(|(field, empty)| empty.then_some(field))
                            .collect();
                    let shared = if uses[&row.grant_id] > 1 {
                        "; another rule uses this id and may take effect once this one is deleted, \
                         so decide which to keep"
                    } else {
                        ""
                    };
                    nameless.push(format!(
                        "grant '{}' (empty {}{shared})",
                        row.grant_id,
                        fields.join(" and ")
                    ));
                }
            }
        }
        if nameless.is_empty() {
            return Ok(Self {
                schema_version: raw.schema_version,
                grants,
            });
        }
        Err(format!(
            "{} row(s) name no one: {}. Such a row matches no caller, so it grants nothing; \
             delete it from the file",
            nameless.len(),
            nameless.join(", ")
        ))
    }
}
