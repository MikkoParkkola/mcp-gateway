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
/// request findings and the declared effect.
pub(crate) const DECISION_VERSION: u8 = 2;

/// Most request findings one record carries; beyond it the record says it
/// was truncated.
pub(crate) const MAX_REQUEST_FINDINGS: usize = 16;

/// The HKDF info a rule-id key is derived with, so rule ids never share a key
/// with config revisions or record principals.
pub(crate) const RULE_ID_TAG: &[u8] = b"decision.rule_id.v1";

/// How specific an affirmative rule is: an allowed call names its most
/// specific one. An order of specificity, not of execution (every check runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AllowRank {
    /// A firewall rule that softened a finding whose default was Block.
    FirewallSoftenedBlock,
    /// A matched identity grant.
    Grant,
    /// A matched mTLS rule.
    MtlsRule,
    /// A tool-policy allow entry.
    ToolPolicyEntry,
    /// A firewall allow rule, including one that only softened a Warn.
    FirewallAllowRule,
}

/// The stable id of one compiled rule: its kind, then the keyed HMAC of its
/// serialised definition, full width.
pub(crate) fn rule_id(
    kind: DecisionKind,
    key: &[u8; 32],
    definition: &serde_json::Value,
) -> String {
    let kind = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mac =
        crate::hashing::hmac_sha256_hex(key, crate::hashing::canonical_json(definition).as_bytes());
    format!("{kind}:{mac}")
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
/// else the most specific affirmative rule (an unranked allow only when no
/// ranked one was noted), plus the request findings and the declared effect,
/// which every decision carries whichever check won.
///
/// One pointer wide, boxed only once a gate notes something: it rides in the
/// task-local call and route scopes, which move it in and out on every poll,
/// and a call that is simply allowed notes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Noted(Option<Box<NotedChecks>>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NotedChecks {
    refusal: Option<(DecisionKind, Option<String>)>,
    allow: Option<NotedAllow>,
    findings: Option<Vec<DecisionFinding>>,
    findings_truncated: bool,
    effect: Option<(Effect, EffectSource)>,
}

/// The allow a call names: its kind, rule id, grant id (a matched grant
/// only), and its rank (`None` for an unranked allow such as a replay).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NotedAllow {
    kind: DecisionKind,
    rule_id: Option<String>,
    grant_id: Option<String>,
    rank: Option<AllowRank>,
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

    /// An unranked allow (a replay, a cache hit): kept only while no allow is
    /// noted, and replaced by any ranked one.
    pub(crate) fn allowed(&mut self, kind: DecisionKind, rule_id: Option<String>) {
        self.checks().allow.get_or_insert(NotedAllow {
            kind,
            rule_id,
            grant_id: None,
            rank: None,
        });
    }

    /// An affirmative rule that allowed the call, ranked: the most specific
    /// one noted is the one recorded, whatever order the checks ran in.
    pub(crate) fn allowed_by(
        &mut self,
        kind: DecisionKind,
        rank: AllowRank,
        rule_id: Option<String>,
        grant_id: Option<String>,
    ) {
        let checks = self.checks();
        // `AllowRank` orders most specific first; an unranked allow loses to
        // any ranked one.
        let wins = checks
            .allow
            .as_ref()
            .is_none_or(|held| held.rank.is_none_or(|held| rank < held));
        if wins {
            checks.allow = Some(NotedAllow {
                kind,
                rule_id,
                grant_id,
                rank: Some(rank),
            });
        }
    }

    /// Request findings raised for this call, projected to type, severity
    /// and location: added to any noted before, de-duplicated, capped.
    pub(crate) fn note_findings(&mut self, findings: impl IntoIterator<Item = DecisionFinding>) {
        let checks = self.checks();
        let held = checks.findings.get_or_insert_with(Vec::new);
        for finding in findings {
            if held.contains(&finding) {
                continue;
            }
            if held.len() == MAX_REQUEST_FINDINGS {
                checks.findings_truncated = true;
                continue;
            }
            held.push(finding);
        }
    }

    /// What the tool declares the call could change, as this call read it.
    pub(crate) fn note_effect(&mut self, effect: Effect, source: EffectSource) {
        self.checks().effect = Some((effect, source));
    }

    /// The notes for a call answered without deciding it again (a cache hit):
    /// no refusal and no allow of its own, but the findings and the declared
    /// effect this call's admission established.
    pub(crate) fn as_not_redecided(&self) -> Self {
        Self::not_redecided()
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
        let checks = self.0.as_deref();
        let (kind, rule_id, grant_id) = match (self.refusal(), refused) {
            (Some((kind, rule_id)), _) => (*kind, rule_id.clone(), None),
            (None, Refused::No) => checks
                .and_then(|checks| checks.allow.as_ref())
                .map_or((DecisionKind::DefaultAllow, None, None), |allow| {
                    (allow.kind, allow.rule_id.clone(), allow.grant_id.clone())
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
                (DecisionKind::Unrecorded, None, None)
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
            rule_id,
            grant_id,
            request_findings: checks.and_then(|checks| checks.findings.clone()),
            request_findings_truncated: checks.is_some_and(|checks| checks.findings_truncated),
            declared_effect: checks.and_then(|checks| checks.effect.map(|(effect, _)| effect)),
            declared_effect_source: checks
                .and_then(|checks| checks.effect.map(|(_, source)| source)),
            decided,
        }
    }
}

#[cfg(test)]
#[path = "decision_record_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "decision_record_writer_tests.rs"]
mod writer_tests;
