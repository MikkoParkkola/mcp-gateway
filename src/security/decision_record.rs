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
    /// A stored task result is not served under the bindings that produced
    /// it: no recorded targets, no recorded bindings, or a binding that has
    /// changed since.
    Provenance,
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

/// Where a declared effect came from: always a claim, never a gateway
/// guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectSource {
    /// The backend tool's own `readOnlyHint`.
    ToolAnnotation,
    /// The operator's capability definition.
    CapabilityDefinition,
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
    /// Who declared `declared_effect`; present exactly when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_effect_source: Option<EffectSource>,
    pub decided: Decided,
}

/// The decision object version this gateway writes: version 2 records carry
/// the declared effect.
pub(crate) const DECISION_VERSION: u8 = 2;

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
/// else the earliest explicit allow; plus the declared effect, which every
/// decision carries whichever check won.
///
/// One pointer wide, boxed only once a gate notes something: it rides in the
/// task-local call and route scopes, which move it in and out on every poll,
/// and a call that is simply allowed notes nothing.
/// A refusing check and the configured rule that made it, when one did.
pub(crate) type Refusal = (DecisionKind, Option<crate::security::rule_id::RuleId>);

/// A check's outcome with the refusing check's pair: its plain
/// form notes the pair; a stored read records it.
pub(crate) type Explained = std::result::Result<(), (crate::Error, Refusal)>;

/// The refusal a refused stored-task delivery's record names:
/// the check that refused it and, when a configured rule decided, that
/// rule's id. Never delivered to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RefusedBy {
    pub kind: DecisionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

impl From<Refusal> for RefusedBy {
    fn from((kind, rule_id): Refusal) -> Self {
        Self {
            kind,
            rule_id: rule_id.map(|id| id.as_str().to_owned()),
        }
    }
}

/// How strongly a check's allow names the call's decider: lower wins, and
/// two notes of the same rank keep the earlier one. Declared in rank order,
/// so the derived `Ord` is the rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AllowRank {
    /// A firewall rule that let through a finding whose default is to block.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    FirewallSoftenedBlock,
    /// A matched identity grant.
    Grant,
    /// A matched mTLS rule that allowed.
    Mtls,
    /// A tool-policy allow-list entry.
    ToolPolicy,
    /// Any other firewall rule that let a finding through.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    FirewallAllow,
    /// A call answered without deciding it again.
    NotRedecided,
}

impl AllowRank {
    /// The decision kind a record names for an allow of this rank.
    pub(crate) const fn kind(self) -> DecisionKind {
        match self {
            Self::FirewallSoftenedBlock | Self::FirewallAllow => DecisionKind::Firewall,
            Self::Grant => DecisionKind::Grant,
            Self::Mtls => DecisionKind::Mtls,
            Self::ToolPolicy => DecisionKind::ToolPolicy,
            Self::NotRedecided => DecisionKind::NotRedecided,
        }
    }
}

/// One check's explicit allow: its rank, the configured rule that allowed
/// and, for a grant, the matched grant's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Allow {
    pub rank: AllowRank,
    pub rule_id: Option<crate::security::rule_id::RuleId>,
    pub grant_id: Option<String>,
}

impl Allow {
    /// An allow of `rank` by `rule_id`, naming no grant.
    pub(crate) const fn by(
        rank: AllowRank,
        rule_id: Option<crate::security::rule_id::RuleId>,
    ) -> Self {
        Self {
            rank,
            rule_id,
            grant_id: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Noted(Option<Box<NotedChecks>>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NotedChecks {
    refusal: Option<Refusal>,
    allow: Option<Allow>,
    effect: Option<(Effect, EffectSource)>,
}

impl Noted {
    /// A call answered without deciding it again (a replay, a cache hit).
    pub(crate) fn not_redecided() -> Self {
        let mut noted = Self::default();
        noted.allowed(Allow::by(AllowRank::NotRedecided, None));
        noted
    }

    fn refusal(&self) -> Option<&Refusal> {
        self.0.as_ref()?.refusal.as_ref()
    }

    fn checks(&mut self) -> &mut NotedChecks {
        self.0.get_or_insert_with(Box::default)
    }

    /// Whether a gate refused.
    pub(crate) fn has_refusal(&self) -> bool {
        self.refusal().is_some()
    }

    /// The check that refused and its rule, if one did.
    pub(crate) fn refusal_pair(&self) -> Option<Refusal> {
        self.refusal().cloned()
    }

    /// The check a request's memo kept for this target: it names the refusal
    /// the record's outcome code came from, so it wins over any later note.
    pub(crate) fn refused_by_memo(&mut self, (kind, rule_id): Refusal) {
        self.checks().refusal = Some((kind, rule_id));
    }

    /// The gate that refused; only the first one counts.
    pub(crate) fn refused(
        &mut self,
        kind: DecisionKind,
        rule_id: Option<crate::security::rule_id::RuleId>,
    ) {
        self.checks().refusal.get_or_insert((kind, rule_id));
    }

    /// An explicit allow: the lowest rank is kept, and of two equal ranks the
    /// earlier note (a later note replaces only on a strictly lower rank).
    pub(crate) fn allowed(&mut self, allow: Allow) {
        let held = &mut self.checks().allow;
        if held.as_ref().is_none_or(|kept| allow.rank < kept.rank) {
            *held = Some(allow);
        }
    }

    /// What the tool declares the call could change, as this call read it.
    pub(crate) fn note_effect(&mut self, effect: Effect, source: EffectSource) {
        self.checks().effect = Some((effect, source));
    }

    /// The notes for a call answered without deciding it again (a cache hit):
    /// no refusal and no allow of its own, but the declared effect this
    /// call's admission established.
    pub(crate) fn as_not_redecided(&self) -> Self {
        let mut noted = Self::not_redecided();
        if let Some(held) = self.0.as_deref() {
            noted.checks().effect = held.effect;
        }
        noted
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
        let ((kind, rule_id), grant_id) = match (self.refusal(), refused) {
            (Some(refusal), _) => (refusal.clone(), None),
            (None, Refused::No) => self
                .0
                .as_ref()
                .and_then(|checks| checks.allow.clone())
                .map_or(((DecisionKind::DefaultAllow, None), None), |allow| {
                    ((allow.rank.kind(), allow.rule_id), allow.grant_id)
                }),
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
                ((DecisionKind::Unrecorded, None), None)
            }
        };
        let applied = live.and_then(crate::config_reload::LiveConfig::applied_now);
        let config_revision = applied.as_ref().map(|a| a.revision.clone());
        let running_revision = live
            .and_then(crate::config_reload::LiveConfig::running_revision)
            .filter(|running| config_revision.as_deref() != Some(*running))
            .map(str::to_owned);
        Decision {
            v: DECISION_VERSION,
            config_revision,
            running_revision,
            pending_restart: applied
                .map(|a| a.pending_restart.iter().map(|f| (*f).to_owned()).collect())
                .unwrap_or_default(),
            kind,
            rule_id: rule_id.map(|id| id.as_str().to_owned()),
            grant_id,
            request_findings: None,
            request_findings_truncated: false,
            declared_effect: self.0.as_deref().and_then(|c| c.effect.map(|(e, _)| e)),
            declared_effect_source: self.0.as_deref().and_then(|c| c.effect.map(|(_, s)| s)),
            decided,
        }
    }
}

#[allow(
    dead_code,
    reason = "the receipt and the Activity rule filter read through it when they land"
)]
#[path = "decision_record_read.rs"]
pub(crate) mod read;

#[cfg(test)]
#[path = "decision_record_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "decision_record_allow_tests.rs"]
mod allow_tests;

#[cfg(test)]
#[path = "decision_record_read_tests.rs"]
mod read_tests;

#[cfg(test)]
#[path = "decision_record_writer_tests.rs"]
mod writer_tests;
