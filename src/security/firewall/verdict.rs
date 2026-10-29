// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Firewall verdict predicates and the rule helpers that pick an action.

use super::{CompiledRule, Finding, FirewallAction, FirewallRule, FirewallVerdict, ScanType};
use crate::error::rpc_codes::INVALID_REQUEST;
use crate::security::Severity;
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

impl FirewallVerdict {
    /// Construct an unconditional allow verdict (used when scanning is disabled).
    pub(super) fn allow() -> Self {
        Self {
            allowed: true,
            action: FirewallAction::Allow,
            findings: Vec::new(),
            anomaly_score: None,
        }
    }

    /// Returns `true` when the block was triggered solely by anomaly detection
    /// (OWASP ASI10 — Rogue Agents), i.e. every blocking finding is a
    /// `SequenceAnomaly` at `Severity::High` or `Severity::Critical`.
    ///
    /// Callers should use JSON-RPC error code `-32002` for anomaly blocks to
    /// distinguish them from generic security blocks (`-32600`).
    pub fn is_anomaly_block(&self) -> bool {
        self.blocked_only_by(|_| false)
    }

    /// [`Self::is_anomaly_block`] widened to relay findings (OWASP ASI10,
    /// COLLUDE.1): every finding is a high or critical `SequenceAnomaly` or a
    /// `CollusionRelay`. Crate-internal so the public meaning stays put.
    pub(crate) fn is_asi10_block(&self) -> bool {
        self.blocked_only_by(|f| f.scan_type == ScanType::CollusionRelay)
    }

    /// The code and message a blocked request answers on every route: an
    /// ASI10 block (OWASP rogue agents) `-32002` "Anomaly detection blocked:
    /// …", any other block `-32600` "Firewall blocked: …". `None` when the
    /// verdict allows. One definition, so `/mcp`, `/mcp/{name}`, stdio and the
    /// dispatch chokepoint cannot word one refusal differently
    /// (route-check-parity P3). The HTTP status stays with each route.
    pub(crate) fn request_refusal(&self) -> Option<(i32, String)> {
        if self.allowed {
            return None;
        }
        let desc = self
            .findings
            .first()
            .map_or("Security firewall blocked this request", |f| {
                f.description.as_str()
            });
        Some(if self.is_asi10_block() {
            (-32002, format!("Anomaly detection blocked: {desc}"))
        } else {
            (INVALID_REQUEST, format!("Firewall blocked: {desc}"))
        })
    }

    /// Whether the finding a refusal words (the first) came from a content scan
    /// of the arguments, not from a stateful control. A stateful control's
    /// text carries counts and scores only; a content scan's names the
    /// argument and the pattern it matched.
    pub(crate) fn refusal_words_content(&self) -> bool {
        self.findings.first().is_some_and(|finding| {
            // Exhaustive on purpose: a new scan type must choose a side here.
            match finding.scan_type {
                ScanType::BudgetExceeded
                | ScanType::CrossTenantReach
                | ScanType::SequenceAnomaly
                | ScanType::CollusionRelay => false,
                ScanType::Credentials
                | ScanType::Pii
                | ScanType::PromptInjection
                | ScanType::ShellInjection
                | ScanType::PathTraversal
                | ScanType::SqlInjection
                | ScanType::MemoryPoisoning
                | ScanType::PathOutsideRoot => true,
            }
        })
    }

    fn blocked_only_by(&self, also: impl Fn(&Finding) -> bool) -> bool {
        !self.allowed
            && !self.findings.is_empty()
            && self.findings.iter().all(|f| {
                (f.scan_type == ScanType::SequenceAnomaly && f.severity >= Severity::High)
                    || also(f)
            })
    }
}

// ─── Rule helpers ─────────────────────────────────────────────────────────────

pub(super) fn compile_rule(rule: &FirewallRule) -> CompiledRule {
    // The guarantee is the load: `FirewallConfig::validate` refuses an invalid
    // glob while the firewall is on. Should one get here anyway (an embedder
    // that skips the load), the rule is a refused shape, below.
    let pattern = glob::Pattern::new(&rule.tool_match).ok();
    let globs = |list: &[String]| list.iter().map(|g| glob::Pattern::new(g).ok()).collect();
    // The scopes are refused at load too: an empty `servers`, `keys` or
    // `except` list, a glob that does not parse (`match` or a scope's), or an
    // exception setting no field. A shape that got here anyway fails closed: the rule
    // blocks its finding types on every call. Covering no call would not do:
    // a later `allow` rule would then decide, and neither would keeping a
    // `warn` or `allow` rule's action.
    let unparsed = |glob: Option<&String>| glob.is_some_and(|g| glob::Pattern::new(g).is_err());
    let refused_shape = pattern.is_none()
        || rule
            .servers
            .as_ref()
            .is_some_and(|l| l.is_empty() || l.iter().any(|g| unparsed(Some(g))))
        || rule.keys.as_ref().is_some_and(Vec::is_empty)
        || rule.except.as_ref().is_some_and(Vec::is_empty)
        || rule.except.iter().flatten().any(|entry| {
            (entry.server.is_none() && entry.tool.is_none() && entry.key.is_none())
                || unparsed(entry.server.as_ref())
                || unparsed(entry.tool.as_ref())
        });
    if refused_shape {
        return CompiledRule {
            pattern: glob::Pattern::new("*").ok(),
            action: FirewallAction::Block,
            scans: rule.scan.clone(),
            servers: None,
            keys: None,
            except: Vec::new(),
            reason: rule.reason.clone(),
        };
    }
    CompiledRule {
        pattern,
        action: rule.action,
        scans: rule.scan.clone(),
        servers: rule.servers.as_ref().map(|l| globs(l)),
        keys: rule.keys.clone(),
        except: rule
            .except
            .iter()
            .flatten()
            .map(|entry| CompiledException {
                server: ExceptGlob::of(entry.server.as_deref()),
                tool: ExceptGlob::of(entry.tool.as_deref()),
                key: entry.key.clone(),
            })
            .collect(),
        reason: rule.reason.clone(),
    }
}

/// One compiled `except` entry.
#[derive(Debug, Clone)]
pub(super) struct CompiledException {
    server: ExceptGlob,
    tool: ExceptGlob,
    key: Option<String>,
}

/// One glob field of an `except` entry.
#[derive(Debug, Clone)]
enum ExceptGlob {
    /// Not set: any value matches.
    Any,
    /// Set; `None` held a glob that did not parse (refused at load) and
    /// matches nothing.
    Set(Option<glob::Pattern>),
}

impl ExceptGlob {
    fn of(glob: Option<&str>) -> Self {
        glob.map_or(Self::Any, |g| Self::Set(glob::Pattern::new(g).ok()))
    }
}

/// Whether `rule`'s `match` glob covers `tool`, ignoring its scopes.
#[cfg(test)]
pub(super) fn rule_matches(rule: &CompiledRule, tool: &str) -> bool {
    glob_covers(rule.pattern.as_ref(), tool)
}

fn glob_covers(glob: Option<&glob::Pattern>, name: &str) -> bool {
    glob.is_some_and(|p| p.matches(name))
}

fn server_covered(globs: &[Option<glob::Pattern>], server: ServerOf<'_>) -> bool {
    match server {
        ServerOf::Backend(name) => globs.iter().any(|g| glob_covers(g.as_ref(), name)),
        ServerOf::NoBackend => false,
    }
}

impl CompiledException {
    /// Every field the entry sets matches the call. `key` is the one concrete
    /// key being resolved (`None`: no key).
    fn matches(&self, target: RuleTarget<'_>, key: Option<&str>) -> bool {
        let server = match &self.server {
            ExceptGlob::Any => true,
            ExceptGlob::Set(g) => server_covered(std::slice::from_ref(g), target.server),
        };
        let tool = match &self.tool {
            ExceptGlob::Any => true,
            ExceptGlob::Set(g) => glob_covers(g.as_ref(), target.tool),
        };
        server && tool && self.key.as_deref().is_none_or(|k| key == Some(k))
    }
}

/// Whether `rule` applies to `target`, resolving with the one concrete `key`.
pub(super) fn rule_applies(rule: &CompiledRule, target: RuleTarget<'_>, key: Option<&str>) -> bool {
    glob_covers(rule.pattern.as_ref(), target.tool)
        && rule
            .servers
            .as_deref()
            .is_none_or(|globs| server_covered(globs, target.server))
        && rule
            .keys
            .as_deref()
            .is_none_or(|keys| key.is_some_and(|k| keys.iter().any(|named| named == k)))
        && !rule.except.iter().any(|entry| entry.matches(target, key))
}

/// The first rule that applies to `target` (with the concrete `key`) and
/// whose `scan` list holds `scan_type`; an empty list holds every type.
pub(super) fn first_matching_rule_action(
    rules: &[CompiledRule],
    target: RuleTarget<'_>,
    key: Option<&str>,
    scan_type: ScanType,
) -> Option<FirewallAction> {
    rules
        .iter()
        .find(|rule| {
            rule_applies(rule, target, key)
                && (rule.scans.is_empty() || rule.scans.contains(&scan_type))
        })
        .map(|rule| rule.action)
}

/// The concrete keys `target` is resolved under: its own, none, or for a key
/// that is not known, every key a rule names plus none (the strongest of
/// those outcomes is taken).
pub(super) fn candidate_keys<'a>(
    rules: &'a [CompiledRule],
    target: RuleTarget<'a>,
) -> Vec<Option<&'a str>> {
    match target.key {
        KeyOf::Key(k) => vec![Some(k)],
        KeyOf::NoKey => vec![None],
        KeyOf::NotKnown => {
            let mut named: Vec<Option<&str>> = rules
                .iter()
                .flat_map(|rule| {
                    rule.keys
                        .iter()
                        .flatten()
                        .map(String::as_str)
                        .chain(rule.except.iter().filter_map(|e| e.key.as_deref()))
                })
                .map(Some)
                .collect();
            named.push(None);
            named.sort_unstable();
            named.dedup();
            named
        }
    }
}

pub(super) const fn default_action_for_severity(severity: Severity) -> FirewallAction {
    match severity {
        Severity::Critical | Severity::High => FirewallAction::Block,
        Severity::Medium => FirewallAction::Warn,
        Severity::Low => FirewallAction::Allow,
    }
}

pub(super) const fn decide_firewall_action(
    matching_rule_action: Option<FirewallAction>,
    highest_severity: Option<Severity>,
) -> FirewallAction {
    match highest_severity {
        None => FirewallAction::Allow,
        Some(severity) => match matching_rule_action {
            Some(action) => action,
            None => default_action_for_severity(severity),
        },
    }
}
