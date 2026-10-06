// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One content inspection per response artifact, followed by target reduction.

use serde_json::Value;

use super::{
    Finding, FindingLocation, Firewall, FirewallAction, FirewallVerdict, ScanType, Severity,
};
use crate::protocol::continuation::{Keyring, now_unix_secs};
use crate::security::response_policy::{
    InvalidResponseTargets, ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy,
    ResponsePolicyTarget,
};

impl Firewall {
    /// Inspect one artifact and evaluate every authenticated routing target.
    /// Immutable questions may be refused, but are never silently rewritten.
    pub(crate) fn check_response_artifact(
        &self,
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
        let findings = self.inspect_response_content(response, correlation);
        let mut action = targets
            .iter()
            .fold(FirewallAction::Allow, |combined, target| {
                strongest_action(combined, self.resolve_action(&target.tool, &findings))
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
            audit.log_response_artifact(correlation, &targets, artifact, &verdict);
        }
        Ok(verdict)
    }

    /// Run the existing detectors once; policy target count never multiplies it.
    fn inspect_response_content(
        &self,
        response: &mut Value,
        correlation: &ResponseCorrelation<'_>,
    ) -> Vec<Finding> {
        #[cfg(test)]
        self.response_observer
            .inspections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut findings = Vec::new();
        // Redact first: an injection finding quotes up to 200 chars of raw
        // text (a value or, since #2114, a key), so it must quote the redacted
        // text or a credential beside the marker reaches the audit log.
        if self.config.credential_redaction {
            #[cfg(test)]
            self.response_observer
                .redactions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let own = |value: &str| {
                self.continuations
                    .as_ref()
                    .is_some_and(|state| is_own_continuation(state.keyring(), value))
            };
            findings.extend(self.redactor.scan_and_redact_unless(response, &own));
        }
        if self.config.prompt_injection_detection {
            #[cfg(test)]
            self.response_observer
                .prompt_scans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Detection always reads what the client receives. With redaction
            // on that is already redacted text; with it off the raw quote is
            // withheld, since masking a 200-char cut can miss a split token.
            let matches = self.response_scanner.scan_response(
                correlation.external_server,
                correlation.external_tool,
                response,
            );
            findings.extend(matches.into_iter().map(|matched| Finding {
                scan_type: ScanType::PromptInjection,
                severity: Severity::Medium,
                description: matched.pattern_description,
                matched: if self.config.credential_redaction {
                    matched.matched_fragment
                } else {
                    QUOTE_WITHHELD.to_owned()
                },
                location: FindingLocation::ResponseContent,
            }));
        }
        findings
    }
}

/// Whether `value` is a continuation this gateway minted and can still open.
/// Expired, tampered and foreign values are not, so they are redacted as usual.
/// `open` only reads: it consumes no budget, ledger entry or hold.
fn is_own_continuation(keyring: &Keyring, value: &str) -> bool {
    keyring.open(value, now_unix_secs()).is_ok()
}

/// Audit text for an injection finding while credential redaction is off.
const QUOTE_WITHHELD: &str = "[quote withheld: credential redaction is off]";

fn strongest_action(left: FirewallAction, right: FirewallAction) -> FirewallAction {
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
            original.get("inputRequests") != inspected.get("inputRequests")
                || original.get("requestState") != inspected.get("requestState")
        }
        ResponseMutationPolicy::Redact => false,
    }
}
