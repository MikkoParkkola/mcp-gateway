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
use std::sync::Arc;

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

impl Verdicts {
    /// The names this listing withheld.
    pub(crate) fn withheld_names(&self) -> BTreeSet<String> {
        self.withheld.keys().cloned().collect()
    }
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
        // A rule that cannot judge a descriptor fails closed.
        let blocking = match ToolPoisoningRule.check(tool) {
            Ok(result) if result.severity == Severity::Fail => Some(result.issues),
            Ok(_) => None,
            Err(error) => Some(vec![format!("the check could not run: {error}")]),
        };
        if let Some(issues) = blocking {
            let digest = descriptor_digest(tool);
            if allow.get(&tool.name) != Some(&digest) {
                verdicts
                    .withheld
                    .insert(tool.name.clone(), (digest, issues));
                return false;
            }
            verdicts.allowed.insert(tool.name.clone(), digest);
        }
        verdicts.served.insert(tool.name.clone());
        true
    });
    verdicts
}

/// Whether a committed listing is the source's whole catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Listing {
    /// Every page was fetched: a name it omits is gone from the source.
    Complete,
    /// The drain stopped early: an omitted name may be on an unread page.
    Truncated,
}

/// Whether [`super::prepare_tool_metadata`] judges the descriptors it is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Judging {
    /// Raw descriptors from the backend: judge them.
    Judge,
    /// A list already judged raw and since redacted: re-judging redacted text
    /// would break a digest pin, so only the backend's blocked set applies.
    AlreadyJudged,
}

/// Distinct (tool, digest, outcome) log lines remembered per backend.
const LOGGED_CAP: usize = 1024;

/// A backend's withheld tools and the log lines already written for them.
#[derive(Debug, Default)]
pub(crate) struct DescriptorGate {
    /// Withheld tool name -> the slots whose listing withheld it. A name stays
    /// blocked while any slot's latest listing withheld it: another caller's
    /// clean copy of the name clears only that caller's entry.
    blocked: parking_lot::RwLock<BTreeMap<String, BTreeSet<String>>>,
    /// Keyed (tool, digest, withheld?): one line per distinct descriptor per
    /// process, across slots and routes.
    logged: parking_lot::Mutex<HashSet<(String, String, bool)>>,
}

/// Record a log line; `true` when it was not recorded before.
///
/// Memory bound: a backend that keeps sending fresh descriptions cannot grow
/// the set past the cap; at the cap it restarts, at the cost of logging a
/// descriptor again.
fn first_time(logged: &mut HashSet<(String, String, bool)>, line: (String, String, bool)) -> bool {
    if logged.len() >= LOGGED_CAP && !logged.contains(&line) {
        logged.clear();
    }
    logged.insert(line)
}

impl Backend {
    /// Apply an accepted listing from `source` (the slot it was listed on):
    /// block what it withheld, clear `source`'s own block on what it served
    /// (and, for a complete listing, on what it no longer lists), and log
    /// each distinct descriptor once.
    pub(crate) fn commit_verdicts(&self, source: &str, listing: Listing, verdicts: Verdicts) {
        let mut blocked = self.descriptor_gate.blocked.write();
        // What `source` no longer withholds loses `source`'s block: a name it
        // served, and, when the listing is complete, a name it no longer
        // lists at all. A truncated listing clears only what it served, since
        // a name missing from it may sit on a page it never fetched.
        blocked.retain(|name, sources| {
            let cleared = verdicts.served.contains(name)
                || (listing == Listing::Complete && !verdicts.withheld.contains_key(name));
            if cleared {
                sources.remove(source);
            }
            !sources.is_empty()
        });
        let mut logged = self.descriptor_gate.logged.lock();
        for (name, (digest, issues)) in verdicts.withheld {
            if first_time(&mut logged, (name.clone(), digest.clone(), true)) {
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
            blocked.entry(name).or_default().insert(source.to_string());
        }
        for (name, digest) in verdicts.allowed {
            if first_time(&mut logged, (name.clone(), digest.clone(), false)) {
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

    /// `tools` without the names this backend has blocked since they were
    /// cached: a slot filled before another caller's listing blocked a name
    /// must not keep serving it. The same `Arc` when nothing is blocked.
    pub(crate) fn without_blocked(&self, tools: Arc<Vec<Tool>>) -> Arc<Vec<Tool>> {
        let blocked = self.descriptor_gate.blocked.read();
        if blocked.is_empty() || !tools.iter().any(|t| blocked.contains_key(&t.name)) {
            return tools;
        }
        Arc::new(
            tools
                .iter()
                .filter(|t| !blocked.contains_key(&t.name))
                .cloned()
                .collect(),
        )
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
