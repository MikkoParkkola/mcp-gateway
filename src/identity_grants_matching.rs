// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What matches what when a grant is evaluated.

use serde::{Deserialize, Serialize};

use super::{GrantAgent, GrantScope, GrantSubject};
use crate::capability::CapabilityDefinition;
use crate::security::{OwnedProvenAgentId, ProofSource};

/// The proven agent an exact grant names: `{source: mtls|jwt, id}`.
///
/// The source is part of the key because an mTLS subject and a JWT `sub` that
/// stringify the same are two principals. [`ProofSource`] has no `declared`
/// value, so a grant keyed to a self-declared label cannot be written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAgentKey {
    /// The namespace `id` belongs to.
    pub source: ProofSource,
    /// The proven id: SAN URI or bare CN for mTLS, `sub` for JWT.
    #[serde(deserialize_with = "non_empty_id")]
    pub id: String,
}

/// An empty proven id matches no caller, so a row naming one is a dead grant.
/// Refused wherever a key is read, as the CLI refuses to write one.
fn non_empty_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let id = String::deserialize(deserializer)?;
    if id.trim().is_empty() {
        return Err(serde::de::Error::custom(
            "an exact agent id is empty; it would match no caller",
        ));
    }
    Ok(id)
}

impl std::fmt::Display for GrantAgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.source, self.id)
    }
}

impl GrantAgent {
    pub(super) fn matches(&self, agent: Option<&OwnedProvenAgentId>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(key) => {
                agent.is_some_and(|a| a.proof() == key.source && a.as_str() == key.id)
            }
        }
    }
}

/// Why a grants file failed its typed parse. `yaml_error` is the fallback
/// parser's; a JSON file reports `serde_json`'s own `from_str` error instead
/// of YAML's view of JSON. Both keep the line and column; the bare-row
/// remainder, re-parsed from a value, has none and is only ever a suffix.
pub(super) fn parse_refusal(
    path: &std::path::Path,
    content: &str,
    yaml_error: &serde_yaml::Error,
) -> String {
    bare_exact_refusal(path, content).unwrap_or_else(|| {
        let error = serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|_| serde_json::from_str::<super::IdentityGrantFile>(content).err())
            .map_or_else(|| yaml_error.to_string(), ToString::to_string);
        format!(
            "failed to parse identity grants file {}: {error}",
            path.display()
        )
    })
}

/// The refusal for a grants file holding 3.x bare `exact` rows, naming every
/// one, or `None` when there are none.
///
/// Called only after the typed parse failed, so it explains a refusal and
/// never admits a row: `GrantAgent` has no bare variant for one to reach
/// `matches` through. All rows at once, because the CLI's read-modify-write
/// goes through the same reader and N rows must not cost N attempts. No
/// source is defaulted and nothing becomes `any`: each would be a guess, and
/// both widen.
fn bare_exact_refusal(path: &std::path::Path, content: &str) -> Option<String> {
    use serde_yaml::Value;
    // JSON is YAML, so one parse covers both encodings. 3.x wrote YAML rows
    // as a tag (`agent: !exact runner`) and JSON rows as `{"exact": "runner"}`.
    let file: Value = serde_yaml::from_str(content).ok()?;
    let rows: Vec<String> = file
        .get("grants")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let id = bare_exact_id(row)?;
            let grant_id = row
                .get("grant_id")
                .and_then(Value::as_str)
                .unwrap_or("<no grant_id>");
            Some(format!("grant '{grant_id}' (exact {id})"))
        })
        .collect();
    (!rows.is_empty()).then(|| {
        format!(
            "identity grants file {} keys {} agent binding(s) by a bare id, which does not say \
             which proof source it came from: {}. Rewrite each as `agent: !exact {{source: mtls, \
             id: <SAN URI or bare CN>}}` or `agent: !exact {{source: jwt, id: <client_id>}}` \
             (JSON: `\"agent\": {{\"exact\": {{\"source\": \"jwt\", \"id\": ...}}}}`), or as \
             `agent: any` only if every agent of that subject is meant. The gateway will not \
             choose.{}",
            path.display(),
            rows.len(),
            rows.join(", "),
            remainder_error(content)
                .map(|e| format!(" Apart from those rows the file also fails to parse: {e}"))
                .unwrap_or_default()
        )
    })
}

/// The id of a 3.x bare `exact` row: `!exact runner` or `{exact: runner}`.
fn bare_exact_id(row: &serde_yaml::Value) -> Option<&str> {
    match row.get("agent")? {
        serde_yaml::Value::Tagged(tagged) if tagged.tag == "exact" => tagged.value.as_str(),
        agent @ serde_yaml::Value::Mapping(_) => agent.get("exact")?.as_str(),
        _ => None,
    }
}

/// Why the file still fails with its bare rows removed, so a refusal naming
/// them does not hide a second defect behind them. Each encoding is re-read
/// by its own parser: `serde_yaml` refuses the JSON map form of `exact`.
fn remainder_error(content: &str) -> Option<String> {
    if let Ok(mut file) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(rows) = file.get_mut("grants").and_then(|g| g.as_array_mut()) {
            rows.retain(|row| {
                !row.pointer("/agent/exact")
                    .is_some_and(serde_json::Value::is_string)
            });
        }
        return serde_json::from_value::<super::IdentityGrantFile>(file)
            .err()
            .map(|e| e.to_string());
    }
    let mut file: serde_yaml::Value = serde_yaml::from_str(content).ok()?;
    if let Some(rows) = file.get_mut("grants").and_then(|g| g.as_sequence_mut()) {
        rows.retain(|row| bare_exact_id(row).is_none());
    }
    serde_yaml::from_value::<super::IdentityGrantFile>(file)
        .err()
        .map(|e| e.to_string())
}

// Identity is `(authority, subject)`. The label is whatever each side had to
// hand — an API key's name at runtime, a person's name in a grant file — so
// comparing it made correctly written grants deny. Every owner and grant
// comparison routes through this impl, which is why it lives on the type.
impl PartialEq for GrantSubject {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority && self.subject == other.subject
    }
}

impl Eq for GrantSubject {}

// Must hash exactly what `eq` compares, or a set or map keyed by subject
// would hold one identity twice.
impl std::hash::Hash for GrantSubject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.authority.hash(state);
        self.subject.hash(state);
    }
}

impl GrantScope {
    /// The scope a dispatch of `capability` requests: `Read` when its author
    /// declared it read-only, `Execute` otherwise. The declaration is the only
    /// read/write signal dispatch has, which is why there is no `Write`.
    pub(crate) fn requested_by(capability: &CapabilityDefinition) -> Self {
        if capability.metadata.read_only {
            Self::Read
        } else {
            Self::Execute
        }
    }

    pub(super) fn grants(&self, requested: &Self) -> bool {
        self == requested
            || matches!(
                (self, requested),
                (Self::Any, _) | (Self::Execute, Self::Read)
            )
    }
}
