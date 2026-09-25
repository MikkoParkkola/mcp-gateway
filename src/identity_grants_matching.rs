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

/// Why a grants file failed its typed parse; `yaml_error` is the fallback
/// parser's. The file is read once as an untyped [`Tree`].
///
/// A file holding 3.x bare `exact` rows is refused naming every one. This
/// explains a refusal and never admits a row: `GrantAgent` has no bare
/// variant for one to reach `matches` through. All rows at once, because the
/// CLI's read-modify-write goes through the same reader and N rows must not
/// cost N attempts. No source is defaulted and nothing becomes `any`: each
/// would be a guess, and both widen.
///
/// Otherwise the error is a text parse's, which alone knows line and column:
/// `serde_json`'s for a JSON file rather than YAML's view of JSON, else
/// `yaml_error`.
pub(super) fn parse_refusal(
    path: &std::path::Path,
    content: &str,
    yaml_error: &serde_yaml::Error,
) -> String {
    let tree = Tree::parse(content);
    let bare = tree.as_ref().map(Tree::bare_rows).unwrap_or_default();
    if bare.is_empty() {
        let error = match tree {
            Some(Tree::Json(_)) => serde_json::from_str::<super::IdentityGrantFile>(content)
                .err()
                .map(|e| e.to_string()),
            _ => None,
        }
        .unwrap_or_else(|| yaml_error.to_string());
        return format!(
            "failed to parse identity grants file {}: {error}",
            path.display()
        );
    }
    let rows: Vec<String> = bare
        .iter()
        .map(|(grant_id, id)| format!("grant '{grant_id}' (exact {id})"))
        .collect();
    let remainder = tree
        .and_then(Tree::remainder_error)
        .map(|e| format!(" Apart from those rows the file also fails to parse: {e}"))
        .unwrap_or_default();
    format!(
        "identity grants file {} keys {} agent binding(s) by a bare id, which does not say \
         which proof source it came from: {}. Rewrite each as `agent: !exact {{source: mtls, \
         id: <SAN URI or bare CN>}}` or `agent: !exact {{source: jwt, id: <client_id>}}` \
         (JSON: `\"agent\": {{\"exact\": {{\"source\": \"jwt\", \"id\": ...}}}}`), or as \
         `agent: any` only if every agent of that subject is meant. The gateway will not \
         choose.{remainder}",
        path.display(),
        rows.len(),
        rows.join(", "),
    )
}

/// A grants file read once as an untyped tree, in its own encoding. JSON is
/// tried first: JSON is also YAML, but `serde_yaml` refuses the JSON map form
/// of `exact`, so a JSON file stays JSON.
enum Tree {
    Json(serde_json::Value),
    Yaml(serde_yaml::Value),
}

impl Tree {
    fn parse(content: &str) -> Option<Self> {
        serde_json::from_str(content)
            .map(Self::Json)
            .ok()
            .or_else(|| serde_yaml::from_str(content).ok().map(Self::Yaml))
    }

    /// `(grant_id, id)` of every 3.x bare `exact` row. 3.x wrote YAML rows as
    /// a tag (`agent: !exact runner`) and JSON rows as `{"exact": "runner"}`.
    fn bare_rows(&self) -> Vec<(String, String)> {
        let named = |grant_id: Option<&str>, id: &str| {
            (
                grant_id.unwrap_or("<no grant_id>").to_owned(),
                id.to_owned(),
            )
        };
        match self {
            Self::Json(file) => json_rows(file)
                .filter_map(|row| {
                    let id = row.pointer("/agent/exact")?.as_str()?;
                    Some(named(
                        row.get("grant_id").and_then(serde_json::Value::as_str),
                        id,
                    ))
                })
                .collect(),
            Self::Yaml(file) => yaml_rows(file)
                .filter_map(|row| {
                    let id = bare_yaml_id(row)?;
                    Some(named(
                        row.get("grant_id").and_then(serde_yaml::Value::as_str),
                        id,
                    ))
                })
                .collect(),
        }
    }

    /// Why the file still fails its typed parse with the bare rows removed,
    /// so a refusal naming them does not hide a second defect behind them.
    /// Parsed from a value, so it carries no line or column.
    fn remainder_error(self) -> Option<String> {
        match self {
            Self::Json(mut file) => {
                if let Some(rows) = file
                    .get_mut("grants")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    rows.retain(|row| {
                        !row.pointer("/agent/exact")
                            .is_some_and(serde_json::Value::is_string)
                    });
                }
                serde_json::from_value::<super::IdentityGrantFile>(file)
                    .err()
                    .map(|e| e.to_string())
            }
            Self::Yaml(mut file) => {
                if let Some(rows) = file
                    .get_mut("grants")
                    .and_then(serde_yaml::Value::as_sequence_mut)
                {
                    rows.retain(|row| bare_yaml_id(row).is_none());
                }
                serde_yaml::from_value::<super::IdentityGrantFile>(file)
                    .err()
                    .map(|e| e.to_string())
            }
        }
    }
}

fn json_rows(file: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    file.get("grants")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
}

fn yaml_rows(file: &serde_yaml::Value) -> impl Iterator<Item = &serde_yaml::Value> {
    file.get("grants")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
}

/// The id of a bare YAML row: `!exact runner` or `{exact: runner}`.
fn bare_yaml_id(row: &serde_yaml::Value) -> Option<&str> {
    match row.get("agent")? {
        serde_yaml::Value::Tagged(tagged) if tagged.tag == "exact" => tagged.value.as_str(),
        agent @ serde_yaml::Value::Mapping(_) => agent.get("exact")?.as_str(),
        _ => None,
    }
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
