// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool descriptors that fail the tool-poisoning check (AX-010) at blocking
//! severity are withheld from every served list and refused by name
//! (GitHub #1441).
//!
//! Blocked names are held per backend, not per caller slot (maintainer
//! decision): once any caller's listing, on either route, observes a blocking
//! descriptor, every caller is refused that name. A name no listing in this
//! process has returned is forwarded, since the gateway has served its
//! description to no one.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::Backend;
use crate::protocol::Tool;
use crate::validator::{Rule, Severity, ToolPoisoningRule};

/// What judging one listing decided, applied to the backend only once the
/// listing's store is accepted.
#[derive(Debug, Default)]
pub(crate) struct Verdicts {
    /// Withheld tools: name -> (digest, the rule's findings).
    withheld: BTreeMap<String, (String, Vec<String>)>,
    /// Tools served only because an operator pin matched: name -> digest.
    allowed: BTreeMap<String, String>,
    /// Every name this listing served. A served name is no longer blocked.
    served: BTreeSet<String>,
}

/// Hex SHA-256 over exactly what the rule judges, each field prefixed by its
/// UTF-8 byte length as u64 big-endian: name, description, then every
/// top-level parameter's name and description, parameters sorted by name. No
/// dependence on JSON map ordering.
pub(crate) fn descriptor_digest(tool: &Tool) -> String {
    let mut fields: Vec<&str> = vec![&tool.name, tool.description.as_deref().unwrap_or("")];
    if let Some(props) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    {
        let mut names: Vec<&String> = props.keys().collect();
        names.sort();
        for name in names {
            fields.push(name);
            fields.push(
                props[name]
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or(""),
            );
        }
    }
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize().iter().fold(String::new(), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

/// Drop every tool whose descriptor fails the rule at blocking severity,
/// unless `allow` pins its current digest. Warn-level findings are served.
pub(crate) fn judge(tools: &mut Vec<Tool>, allow: &BTreeMap<String, String>) -> Verdicts {
    let mut verdicts = Verdicts::default();
    tools.retain(|tool| {
        let blocking = ToolPoisoningRule
            .check(tool)
            .ok()
            .filter(|result| result.severity == Severity::Fail);
        if let Some(result) = blocking {
            let digest = descriptor_digest(tool);
            if allow.get(&tool.name) != Some(&digest) {
                verdicts
                    .withheld
                    .insert(tool.name.clone(), (digest, result.issues));
                return false;
            }
            verdicts.allowed.insert(tool.name.clone(), digest);
        }
        verdicts.served.insert(tool.name.clone());
        true
    });
    verdicts
}

/// A backend's withheld tools and the log lines already written for them.
#[derive(Debug, Default)]
pub(crate) struct DescriptorGate {
    /// Withheld tool name -> descriptor digest.
    blocked: parking_lot::RwLock<BTreeMap<String, String>>,
    /// Keyed (tool, digest, withheld?): one line per distinct descriptor per
    /// process, across slots and routes.
    logged: parking_lot::Mutex<HashSet<(String, String, bool)>>,
}

impl Backend {
    /// Apply an accepted listing's verdicts: block what it withheld, unblock
    /// what it served, and log each distinct descriptor once.
    pub(crate) fn commit_verdicts(&self, verdicts: Verdicts) {
        let mut blocked = self.descriptor_gate.blocked.write();
        for name in &verdicts.served {
            blocked.remove(name);
        }
        let mut logged = self.descriptor_gate.logged.lock();
        for (name, (digest, issues)) in verdicts.withheld {
            if logged.insert((name.clone(), digest.clone(), true)) {
                warn!(
                    backend = %self.name,
                    tool = %name,
                    rule = "AX-010",
                    digest = %digest,
                    issues = %issues.join("; "),
                    allow = %format!("allow_flagged_tools: {{ {name}: {digest} }}"),
                    "Tool withheld: its description failed the tool-poisoning check"
                );
            }
            blocked.insert(name, digest);
        }
        for (name, digest) in verdicts.allowed {
            if logged.insert((name.clone(), digest.clone(), false)) {
                info!(
                    backend = %self.name,
                    tool = %name,
                    rule = "AX-010",
                    digest = %digest,
                    "Tool served by allow_flagged_tools despite a failed tool-poisoning check"
                );
            }
        }
    }

    /// Refusal text when `tool` is blocked on this backend.
    pub(crate) fn blocked_tool_refusal(&self, tool: &str) -> Option<String> {
        self.descriptor_gate
            .blocked
            .read()
            .contains_key(tool)
            .then(|| {
                format!(
                    "tool `{tool}` is withheld: its description failed the tool-poisoning \
                 check (AX-010); the gateway log names the finding"
                )
            })
    }

    /// Whether a served list may carry `tool`.
    pub(crate) fn is_blocked_tool(&self, tool: &str) -> bool {
        self.descriptor_gate.blocked.read().contains_key(tool)
    }

    /// The operator pins for this backend.
    pub(crate) fn flagged_tool_pins(&self) -> &BTreeMap<String, String> {
        &self.config.allow_flagged_tools
    }
}
