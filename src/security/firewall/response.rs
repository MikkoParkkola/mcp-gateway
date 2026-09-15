// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One content inspection per response artifact, followed by target reduction.

use serde_json::Value;

use super::{
    Finding, FindingLocation, Firewall, FirewallAction, FirewallVerdict, ScanType, Severity,
};
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
        if self.config.prompt_injection_detection {
            #[cfg(test)]
            self.response_observer
                .prompt_scans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let matches = self.response_scanner.scan_response(
                correlation.external_server,
                correlation.external_tool,
                response,
            );
            findings.extend(matches.into_iter().map(|matched| Finding {
                scan_type: ScanType::PromptInjection,
                severity: Severity::Medium,
                description: matched.pattern_description,
                matched: matched.matched_fragment,
                location: FindingLocation::ResponseContent,
            }));
        }
        if self.config.credential_redaction {
            #[cfg(test)]
            self.response_observer
                .redactions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            findings.extend(self.redactor.scan_and_redact(response));
        }
        findings
    }
}

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
