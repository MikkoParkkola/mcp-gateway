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
    /// The backend's `allowed_tools` list leaves the tool out.
    AllowedTools,
    Attestation,
    ResponseGate,
    Syntax,
    NotRedecided,
    DefaultAllow,
    /// A refusal whose check noted no kind: never `default_allow`.
    Unrecorded,
    /// The target matches nothing: no backend or tool by that name.
    NotFound,
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
    /// What the request check raised about the request itself. `None`: it did
    /// not run. `Some(empty)`: it ran clean. What reached the caller is the
    /// delivery record's (`response_findings`), never this object's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_findings: Option<Vec<DecisionFinding>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_findings_truncated: bool,
    /// What the tool declares the call could change, as the deciding check
    /// read it. What the gateway did to the answer is the delivery record's
    /// (`response_effect`), never this object's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_effect: Option<Effect>,
    pub decided: Decided,
}

/// Whether the record being written is of a refused call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Refused, with the record's outcome (named in the guard's message).
    Yes(crate::security::audit::AuditOutcome),
    No,
}

impl Refused {
    /// From the record's outcome: denied and invalid are refusals.
    pub(crate) const fn of(outcome: crate::security::audit::AuditOutcome) -> Self {
        use crate::security::audit::AuditOutcome;
        match outcome {
            AuditOutcome::Denied(_) | AuditOutcome::Invalid(_) => Self::Yes(outcome),
            _ => Self::No,
        }
    }
}

/// Which check decided one call, as its gates noted it: the first refusal,
/// else the earliest explicit allow.
///
/// One pointer wide, boxed only once a gate notes something: it rides in the
/// task-local call and route scopes, which move it in and out on every poll,
/// and a call that is simply allowed notes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Noted(Option<Box<NotedChecks>>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NotedChecks {
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

    fn refusal(&self) -> Option<&(DecisionKind, Option<String>)> {
        self.0.as_ref()?.refusal.as_ref()
    }

    fn checks(&mut self) -> &mut NotedChecks {
        self.0.get_or_insert_with(Box::default)
    }

    /// Whether a gate refused.
    pub(crate) fn has_refusal(&self) -> bool {
        self.refusal().is_some()
    }

    /// The check that refused, if one did.
    pub(crate) fn refusal_kind(&self) -> Option<DecisionKind> {
        self.refusal().map(|(kind, _)| *kind)
    }

    /// The check a request's memo kept for this target: it names the refusal
    /// the record's outcome code came from, so it wins over any later note.
    pub(crate) fn refused_by_memo(&mut self, kind: DecisionKind) {
        self.checks().refusal = Some((kind, None));
    }

    /// The gate that refused; only the first one counts.
    pub(crate) fn refused(&mut self, kind: DecisionKind, rule_id: Option<String>) {
        self.checks().refusal.get_or_insert((kind, rule_id));
    }

    /// An explicit allow; only the earliest in check order counts.
    pub(crate) fn allowed(&mut self, kind: DecisionKind, rule_id: Option<String>) {
        self.checks().allow.get_or_insert((kind, rule_id));
    }

    /// The decision object for this call under the published config `live`.
    ///
    /// A refused call that noted no check records `unrecorded`, never an
    /// allow; in a debug build that is a failure, so a refusal site that forgot to
    /// note its kind cannot ship silently.
    pub(crate) fn decision(
        &self,
        decided: Decided,
        refused: Refused,
        live: Option<&crate::config_reload::LiveConfig>,
    ) -> Decision {
        let (kind, rule_id) = match (self.refusal(), refused) {
            (Some(refusal), _) => refusal.clone(),
            (None, Refused::No) => self
                .0
                .as_ref()
                .and_then(|checks| checks.allow.clone())
                .unwrap_or((DecisionKind::DefaultAllow, None)),
            // Kani's assert macros drop the message, so `outcome` reads as
            // unused in its build only.
            #[cfg_attr(
                kani,
                allow(unused_variables, reason = "used only in the debug_assert message")
            )]
            (None, Refused::Yes(outcome)) => {
                // Every debug build, integration tests included; never a
                // release build, which records `unrecorded` instead.
                debug_assert!(
                    self.has_refusal(),
                    "a refused call ({outcome:?}) noted no check (MIK-8914.API2A.7)"
                );
                (DecisionKind::Unrecorded, None)
            }
        };
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
            request_findings: None,
            request_findings_truncated: false,
            declared_effect: None,
            decided,
        }
    }
}

#[cfg(test)]
#[path = "decision_record_tests.rs"]
mod tests;
