// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One content inspection per response artifact, followed by target reduction.

use serde_json::Value;

use super::{
    AnswerPolicies, Finding, FindingLocation, Firewall, FirewallAction, FirewallPolicy,
    FirewallVerdict, ScanType,
};
use crate::protocol::continuation::Keyring;
use crate::security::Severity;
use crate::security::response_policy::{
    InvalidResponseTargets, ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy,
    ResponsePolicyTarget, RuleTarget, ServerOf, TargetOrigin,
};

impl Firewall {
    /// Whether [`Self::check_response_artifact`] scans at all: off, it allows
    /// every artifact unread, which is no scan for a delivery to state.
    pub(crate) const fn scans_responses(&self) -> bool {
        self.config.enabled && self.config.scan_responses
    }

    /// Inspect one artifact and evaluate every authenticated routing target
    /// under each of `policies`, keeping the strongest action (ADR-029,
    /// amended, item 5). Immutable questions may be refused, but are never
    /// silently rewritten.
    pub(crate) fn check_response_artifact<'p>(
        &self,
        policies: impl Into<AnswerPolicies<'p>>,
        response: &mut Value,
        targets: &[ResponsePolicyTarget],
        correlation: &ResponseCorrelation<'_>,
        artifact: ResponseArtifactKind,
        mutation: ResponseMutationPolicy,
    ) -> Result<FirewallVerdict, InvalidResponseTargets> {
        if !self.config.enabled || !self.config.scan_responses {
            return Ok(FirewallVerdict::allow());
        }
        if targets.is_empty() {
            tracing::warn!("Firewall response inspection requires a policy target");
            return Err(InvalidResponseTargets);
        }
        let mut targets = targets.to_vec();
        targets.sort_unstable();
        targets.dedup();

        // Copied only when redaction is not allowed, so a changed protected value can be
        // restored whole before the Block. The routed tools/call pass redacts and never
        // copies (MIK-7917 item 3).
        let original = (mutation != ResponseMutationPolicy::Redact).then(|| response.clone());
        let (per_policy, findings) =
            self.inspect_response_content(policies.into(), response, correlation);
        // Each policy resolves its own findings; the strongest action stands.
        let mut action =
            per_policy
                .iter()
                .fold(FirewallAction::Allow, |combined, (policy, own)| {
                    targets.iter().fold(combined, |combined, target| {
                        strongest_action(
                            combined,
                            Self::resolve_action(
                                policy,
                                RuleTarget {
                                    server: if target.origin == TargetOrigin::NoBackend {
                                        ServerOf::NoBackend
                                    } else {
                                        ServerOf::Backend(&target.server)
                                    },
                                    tool: &target.tool,
                                    key: correlation.key,
                                },
                                own,
                            ),
                        )
                    })
                });
        if let Some(original) = original
            && protected_value_changed(&original, response, mutation)
        {
            *response = original;
            action = FirewallAction::Block;
        }
        let verdict = FirewallVerdict {
            allowed: action != FirewallAction::Block,
            action,
            findings,
            anomaly_score: None,
        };
        if let Some(audit) = &self.audit {
            let recorded: Vec<ResponsePolicyTarget> = targets
                .iter()
                .filter(|t| t.origin != TargetOrigin::Expanded)
                .cloned()
                .collect();
            audit.log_response_artifact(correlation, &recorded, artifact, &verdict);
        }
        Ok(verdict)
    }

    /// Run the existing detectors once; policy target count never multiplies
    /// it. Each policy gets the findings its own redaction switch produces
    /// (ADR-029, amended, item 5, rule 1): with redaction on, the credential
    /// findings and the injection findings on the redacted text; with it off,
    /// the injection findings on the raw text, quote withheld. Only when the
    /// two policies disagree does the injection scan also read a pre-redaction
    /// copy. Returns each policy's findings and their union for the audit.
    fn inspect_response_content<'p>(
        &self,
        policies: AnswerPolicies<'p>,
        response: &mut Value,
        correlation: &ResponseCorrelation<'_>,
    ) -> (Vec<(&'p FirewallPolicy, Vec<Finding>)>, Vec<Finding>) {
        #[cfg(test)]
        self.response_observer
            .inspections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let redacts = policies.redacts();
        let raw = (policies.redaction_disagrees() && self.config.prompt_injection_detection)
            .then(|| response.clone());
        let mut credential = Vec::new();
        // Redact first: an injection finding quotes up to 200 chars of raw
        // text (a value or, since #2114, a key), so it must quote the redacted
        // text or a credential beside the marker reaches the audit log.
        if redacts {
            #[cfg(test)]
            self.response_observer
                .redactions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let own = |value: &str| {
                self.continuations
                    .as_ref()
                    .is_some_and(|state| is_own_continuation(state.keyring(), value))
            };
            credential = self.redactor.scan_and_redact_unless(response, &own);
        }
        // Detection reads what the client receives. With redaction on that is
        // already redacted text; with it off the raw quote is withheld, since
        // masking a 200-char cut can miss a split token.
        let delivered = self.injection_findings(response, correlation, redacts);
        let unredacted = raw.map(|raw| self.injection_findings(&raw, correlation, false));
        let per: Vec<(&'p FirewallPolicy, Vec<Finding>)> = policies
            .each()
            .map(|policy| {
                let findings = match (&unredacted, policy.credential_redaction) {
                    (Some(raw_findings), false) => raw_findings.clone(),
                    (_, true) => credential.iter().chain(&delivered).cloned().collect(),
                    (None, false) => delivered.clone(),
                };
                (policy, findings)
            })
            .collect();
        let mut all = credential;
        all.extend(delivered);
        all.extend(unredacted.unwrap_or_default());
        (per, all)
    }

    /// The prompt-injection findings on `value`, quoted only when `quoted`
    /// (the text was redacted first).
    fn injection_findings(
        &self,
        value: &Value,
        correlation: &ResponseCorrelation<'_>,
        quoted: bool,
    ) -> Vec<Finding> {
        if !self.config.prompt_injection_detection {
            return Vec::new();
        }
        #[cfg(test)]
        self.response_observer
            .prompt_scans
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let matches = self.response_scanner.scan_response(
            correlation.external_server,
            correlation.external_tool,
            value,
        );
        matches
            .into_iter()
            .map(|matched| Finding {
                scan_type: ScanType::PromptInjection,
                severity: Severity::Medium,
                description: matched.pattern_description,
                matched: if quoted {
                    matched.matched_fragment
                } else {
                    QUOTE_WITHHELD.to_owned()
                },
                location: FindingLocation::ResponseContent,
            })
            .collect()
    }
}

/// Whether `value` is a continuation this gateway minted and can still open.
/// Expired, tampered and foreign values are not, so they are redacted as usual.
/// `open` only reads: it consumes no budget, ledger entry or hold.
fn is_own_continuation(keyring: &Keyring, value: &str) -> bool {
    keyring.open_now(value).is_ok()
}

/// Audit text for an injection finding while credential redaction is off.
const QUOTE_WITHHELD: &str = "[quote withheld: credential redaction is off]";

pub(super) fn strongest_action(left: FirewallAction, right: FirewallAction) -> FirewallAction {
    match (left, right) {
        (FirewallAction::Block, _) | (_, FirewallAction::Block) => FirewallAction::Block,
        (FirewallAction::Warn, _) | (_, FirewallAction::Warn) => FirewallAction::Warn,
        _ => FirewallAction::Allow,
    }
}

fn protected_value_changed(
    original: &Value,
    inspected: &Value,
    mutation: ResponseMutationPolicy,
) -> bool {
    match mutation {
        ResponseMutationPolicy::Immutable => original != inspected,
        ResponseMutationPolicy::PreserveInputRequired => {
            crate::security::response_policy::INTERIM_MEMBERS
                .iter()
                .any(|member| original.get(member) != inspected.get(member))
        }
        ResponseMutationPolicy::Redact => false,
    }
}
