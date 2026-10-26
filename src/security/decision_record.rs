// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision behind a recorded call: written into the transparency-log
//! record when the call is recorded, read back by the activity receipt.
//!
//! Strings and booleans only, so the record re-serialises byte for byte and
//! the existing entry hash and signature cover it. No caller-supplied text and
//! no configured secret ever enters it: the config is named by a keyed
//! revision id, rules by keyed ids, findings by type, severity and location.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The record field the decision object lives under.
pub(crate) const FIELD: &str = "decision";

/// Which check decided the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionKind {
    Firewall,
    ToolPolicy,
    BackendScope,
    ClientToolScope,
    Mtls,
    AgentScope,
    Ssrf,
    Grant,
    CostBudget,
    AdminCapability,
    RoutingProfile,
    KillSwitch,
    CapabilityDisabled,
    DescriptorBlock,
    Attestation,
    ResponseGate,
    Syntax,
    NotRedecided,
    DefaultAllow,
}

/// What the tool's own annotations say the call could change. A claim by the
/// tool, never a gateway guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Effect {
    ReadOnly,
    MayWrite,
    Undeclared,
}

/// Whether the call was decided for itself, or carried an earlier decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Decided {
    Fresh,
    CacheHitCopied,
    CacheHitNotRedecided,
    Replayed,
}

/// One request-side finding: type, severity and location only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DecisionFinding {
    pub scan_type: String,
    pub severity: String,
    pub location: String,
}

/// The decision object as written and as read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Decision {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_restart: Vec<String>,
    pub kind: DecisionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// `None`: the request check did not run. `Some(empty)`: it ran clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings: Option<Vec<DecisionFinding>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub findings_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
    pub decided: Decided,
}

/// Which check decided one call, as its gates noted it: the first refusal,
/// else the earliest explicit allow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Noted {
    refusal: Option<(DecisionKind, Option<String>)>,
    allow: Option<(DecisionKind, Option<String>)>,
}

impl Noted {
    /// A call answered without deciding it again (a replay, a cache hit).
    pub(crate) fn not_redecided() -> Self {
        let mut noted = Self::default();
        noted.allowed(DecisionKind::NotRedecided, None);
        noted
    }

    /// Whether a gate refused.
    pub(crate) const fn has_refusal(&self) -> bool {
        self.refusal.is_some()
    }

    /// The gate that refused; only the first one counts.
    pub(crate) fn refused(&mut self, kind: DecisionKind, rule_id: Option<String>) {
        self.refusal.get_or_insert((kind, rule_id));
    }

    /// An explicit allow; only the earliest in check order counts.
    pub(crate) fn allowed(&mut self, kind: DecisionKind, rule_id: Option<String>) {
        self.allow.get_or_insert((kind, rule_id));
    }

    /// The decision object for this call under the published config `live`.
    pub(crate) fn decision(
        &self,
        decided: Decided,
        live: Option<&crate::config_reload::LiveConfig>,
    ) -> Decision {
        let (kind, rule_id) = self
            .refusal
            .clone()
            .or_else(|| self.allow.clone())
            .unwrap_or((DecisionKind::DefaultAllow, None));
        let applied = live.and_then(crate::config_reload::LiveConfig::applied_now);
        let config_revision = applied.as_ref().map(|a| a.revision.clone());
        let running_revision = live
            .and_then(crate::config_reload::LiveConfig::running_revision)
            .filter(|running| config_revision.as_deref() != Some(*running))
            .map(str::to_owned);
        Decision {
            v: 1,
            config_revision,
            running_revision,
            pending_restart: applied
                .map(|a| a.pending_restart.iter().map(|f| (*f).to_owned()).collect())
                .unwrap_or_default(),
            kind,
            rule_id,
            grant_id: None,
            findings: None,
            findings_truncated: false,
            effect: None,
            decided,
        }
    }
}

/// The decision a record carries; `None` for a record written before this
/// field existed ("no evidence recorded"), and for one that does not parse,
/// never an error.
pub(crate) fn decision_evidence(entry: &Value) -> Option<Decision> {
    serde_json::from_value(entry.get(FIELD)?.clone()).ok()
}

/// Whether `entry` was decided by the rule `rule_id`. Exact match only; a
/// record with no rule id matches nothing.
pub(crate) fn matches_rule(entry: &Value, rule_id: &str) -> bool {
    entry
        .get(FIELD)
        .and_then(|d| d.get("rule_id"))
        .and_then(Value::as_str)
        .is_some_and(|id| id == rule_id)
}

/// The receipt's line for which rule decided. Never blank, never a guess.
pub(crate) fn rule_line(decision: &Decision) -> &'static str {
    match (decision.kind, decision.rule_id.is_some()) {
        (DecisionKind::DefaultAllow, _) => "allowed: no rule restricted this call",
        (DecisionKind::NotRedecided, _) => "not decided again for this call",
        (_, true) => "decided by the rule named below",
        (_, false) => "rule not recorded for this check",
    }
}

/// The receipt's line for the request findings: "not recorded" (no evidence,
/// or the check did not run) is never shown as "none".
pub(crate) fn findings_line(decision: Option<&Decision>) -> &'static str {
    match decision.and_then(|d| d.findings.as_ref()) {
        None => "findings not recorded by this gateway version",
        Some(found) if found.is_empty() => "none",
        Some(_) => "listed below",
    }
}

#[cfg(test)]
#[path = "decision_record_tests.rs"]
mod tests;
