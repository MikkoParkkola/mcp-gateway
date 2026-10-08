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
    /// Withhold named entries that did not parse: the rule cannot judge them,
    /// so they fail closed (#1441). Each is `(name, digest of the raw entry)`.
    pub(crate) fn add_unparseable(&mut self, entries: impl IntoIterator<Item = (String, String)>) {
        for (name, digest) in entries {
            self.withheld.insert(
                name,
                (digest, vec!["descriptor could not be parsed".to_string()]),
            );
        }
    }

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

/// Parse a raw `tools` array entry by entry: one malformed entry must not
/// fail the whole list or hide its siblings from judging. A named entry that
/// does not parse is returned with a digest of its raw JSON, to be withheld.
pub(crate) fn parse_listed(raw: &[serde_json::Value]) -> (Vec<Tool>, Vec<(String, String)>) {
    let mut parsed = Vec::with_capacity(raw.len());
    let mut unparseable = Vec::new();
    for entry in raw {
        match serde_json::from_value::<Tool>(entry.clone()) {
            Ok(tool) => parsed.push(tool),
            Err(_) => {
                if let Some(name) = entry.get("name").and_then(serde_json::Value::as_str) {
                    let bytes = serde_json::to_vec(entry).unwrap_or_default();
                    unparseable.push((name.to_string(), hex(&Sha256::digest(bytes))));
                }
            }
        }
    }
    (parsed, unparseable)
}

/// A blocked name as held: its SHA-256, so the cap bounds memory whatever
/// length the backend gives its names (#1441).
type NameKey = [u8; 32];

fn name_key(name: &str) -> NameKey {
    Sha256::digest(name.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
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

/// Callers tracked per blocked name before the set collapses to
/// [`MANY_SOURCES`].
const SOURCES_CAP: usize = 64;
/// A source no listing can clear: the name stays blocked until restart.
const MANY_SOURCES: &str = "\u{0}many";
/// Blocked names remembered per backend; memory bound against a backend that
/// invents names per caller.
const BLOCKED_NAMES_CAP: usize = 4096;

/// Distinct (tool, digest, outcome) log lines remembered per backend.
const LOGGED_CAP: usize = 1024;

/// A backend's withheld tools and the log lines already written for them.
#[derive(Debug, Default)]
pub(crate) struct DescriptorGate {
    /// Withheld tool name -> the slots whose listing withheld it. A name stays
    /// blocked while any slot's latest listing withheld it: another caller's
    /// clean copy of the name clears only that caller's entry.
    blocked: parking_lot::RwLock<BTreeMap<NameKey, BTreeSet<String>>>,
    /// Keyed (tool, digest, withheld?): one line per distinct descriptor per
    /// process, across slots and routes.
    /// Keyed by the descriptor digest, which already covers the name.
    logged: parking_lot::Mutex<HashSet<(String, bool)>>,
    /// Set when the blocked-name map hit its cap: from then on every by-name
    /// call is refused and every served list is empty. A name past the cap
    /// could not be recorded, and another caller's clean copy of it cannot be
    /// told apart from it, so the backend fails closed (#1441). Cleared only
    /// by a restart.
    saturated: std::sync::atomic::AtomicBool,
}

/// Record a log line; `true` when it was not recorded before.
///
/// Memory bound: a backend that keeps sending fresh descriptions cannot grow
/// the set past the cap; at the cap it restarts, at the cost of logging a
/// descriptor again.
fn first_time(logged: &mut HashSet<(String, bool)>, line: (String, bool)) -> bool {
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
        // Hashed once here, so every comparison inside the map is by digest.
        let served: HashSet<NameKey> = verdicts.served.iter().map(|n| name_key(n)).collect();
        let withheld: HashSet<NameKey> = verdicts.withheld.keys().map(|n| name_key(n)).collect();
        let mut blocked = self.descriptor_gate.blocked.write();
        // What `source` no longer withholds loses `source`'s block: a name it
        // served, and, when the listing is complete, a name it no longer
        // lists at all. A truncated listing clears only what it served, since
        // a name missing from it may sit on a page it never fetched.
        blocked.retain(|key, sources| {
            let cleared =
                served.contains(key) || (listing == Listing::Complete && !withheld.contains(key));
            if cleared {
                sources.remove(source);
            }
            !sources.is_empty()
        });
        let mut logged = self.descriptor_gate.logged.lock();
        for (name, (digest, issues)) in verdicts.withheld {
            if first_time(&mut logged, (digest.clone(), true)) {
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
            let key = name_key(&name);
            if !blocked.contains_key(&key) && blocked.len() >= BLOCKED_NAMES_CAP {
                // Past the cap: fail closed for the whole backend rather than
                // leave this name callable (maintainer decision, #1441).
                let was = self
                    .descriptor_gate
                    .saturated
                    .swap(true, std::sync::atomic::Ordering::SeqCst);
                if !was {
                    warn!(
                        backend = %self.name,
                        cap = BLOCKED_NAMES_CAP,
                        "Blocked tool names reached the cap: every tool of this backend \
                         is now withheld and refused until restart"
                    );
                }
                continue;
            }
            let sources = blocked.entry(key).or_default();
            if sources.len() >= SOURCES_CAP && !sources.contains(source) {
                // Held by too many callers to track one by one: the name stays
                // blocked until restart, since no single listing can clear it.
                sources.clear();
                sources.insert(MANY_SOURCES.to_string());
            } else if !sources.contains(MANY_SOURCES) {
                sources.insert(source.to_string());
            }
        }
        for (name, digest) in verdicts.allowed {
            if first_time(&mut logged, (digest.clone(), false)) {
                info!(
                    backend = %self.name,
                    tool = %name,
                    rule = "AX-010",
                    digest = %digest,
                    "Tool served by allow_flagged_tools despite a failed tool-poisoning check"
                );
            }
        }
        drop(logged);
        drop(blocked);
        // The shared view is filtered by this set, so a verdict can change what
        // discovery shows without any list being stored (`MIK-8127`).
        self.nudge_tools(super::tools_nudge::NudgeKind::Changed);
    }

    /// Refusal text when `tool` is blocked on this backend.
    pub(crate) fn blocked_tool_refusal(
        &self,
        _identity_key: Option<&str>,
        tool: &str,
    ) -> Option<String> {
        if self.is_withheld_name(tool) {
            return Some(format!(
                "tool `{tool}` is withheld: its description failed the tool-poisoning \
                 check (AX-010); the gateway log names the finding"
            ));
        }
        self.gate_saturated().then(|| {
            format!(
                "tool `{tool}` is refused: this backend withheld more tool descriptions \
                 than the gateway tracks, so none of its tools may be called until restart"
            )
        })
    }

    /// Whether the blocked-name map overflowed (sticky until restart).
    pub(crate) fn gate_saturated(&self) -> bool {
        self.descriptor_gate
            .saturated
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `tools` without the names this backend has blocked since they were
    /// cached: a slot filled before another caller's listing blocked a name
    /// must not keep serving it. The same `Arc` when nothing is blocked.
    pub(crate) fn without_blocked(&self, tools: Arc<Vec<Tool>>) -> Arc<Vec<Tool>> {
        if self.gate_saturated() {
            return if tools.is_empty() {
                tools
            } else {
                Arc::new(Vec::new())
            };
        }
        let blocked = self.descriptor_gate.blocked.read();
        if blocked.is_empty()
            || !tools
                .iter()
                .any(|t| blocked.contains_key(&name_key(&t.name)))
        {
            return tools;
        }
        Arc::new(
            tools
                .iter()
                .filter(|t| !blocked.contains_key(&name_key(&t.name)))
                .cloned()
                .collect(),
        )
    }

    /// Whether every tool in `tools` is blocked, decided from one snapshot of
    /// the blocked set so a concurrent listing cannot change it midway.
    pub(crate) fn all_blocked(&self, tools: &[Tool]) -> bool {
        if self.gate_saturated() {
            return true;
        }
        let blocked = self.descriptor_gate.blocked.read();
        tools
            .iter()
            .all(|t| blocked.contains_key(&name_key(&t.name)))
    }

    /// Whether a served list may carry `tool`.
    pub(crate) fn is_blocked_tool(&self, tool: &str) -> bool {
        self.gate_saturated() || self.is_withheld_name(tool)
    }

    /// Whether `tool` is in the blocked-name map. The map is keyed by digest;
    /// an empty map (the usual state) answers without hashing the name, which
    /// every `tools/call` asks several times (NFR.WORKLOAD.1).
    fn is_withheld_name(&self, tool: &str) -> bool {
        let blocked = self.descriptor_gate.blocked.read();
        !blocked.is_empty() && blocked.contains_key(&name_key(tool))
    }

    /// Bytes held in the gate's keys (test support for the memory bound).
    #[cfg(test)]
    pub(crate) fn descriptor_gate_key_bytes(&self) -> usize {
        let blocked: usize =
            self.descriptor_gate.blocked.read().len() * std::mem::size_of::<NameKey>();
        let logged: usize = self
            .descriptor_gate
            .logged
            .lock()
            .iter()
            .map(|(digest, _)| digest.len())
            .sum();
        blocked + logged
    }

    /// The operator pins for this backend.
    pub(crate) fn flagged_tool_pins(&self) -> &BTreeMap<String, String> {
        &self.config.allow_flagged_tools
    }

    /// Prepare a direct `tools/list` the drain already judged.
    ///
    /// Not judged again: this list has been through credential redaction, which
    /// can remove the text a finding rests on and changes the digest a pin
    /// matches. The drain judged the raw list and already dropped what it
    /// withheld; the header exclusion and annotations still apply here, and
    /// names blocked for the backend are dropped as a backstop (#1441).
    pub(crate) fn prepare_judged_tools(&self, tools: &mut Vec<Tool>) {
        let _ = super::prepare_tool_metadata(
            &self.name,
            self.flagged_tool_pins(),
            Judging::AlreadyJudged,
            tools,
        );
        tools.retain(|tool| !self.is_blocked_tool(&tool.name));
    }
}
