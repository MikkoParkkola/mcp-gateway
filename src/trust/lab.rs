// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `CatalogTrustLab` evaluation and certification schema.
//!
//! The lab is an advisory evaluator for candidate MCP servers. It combines
//! TrustCard/CBOM validation, existing MCP tool-poisoning checks, schema-drift
//! comparison, policy thresholds, and safe active-eval planning into one
//! versioned evidence record.

use crate::hashing::canonical_json_sha256;
use crate::protocol::Tool;
use crate::trust::{TrustCard, TrustEvidenceKind, TrustFindingSeverity};
use crate::validator::{Rule, ToolPoisoningRule};
use chrono::{DateTime, Utc};

mod analysis;
mod model;
mod report;
mod runtime_evidence;

pub use model::{
    TrustLabBaseline, TrustLabInput, TrustLabLicenseTier, TrustLabPolicy, TrustLabProfile,
    TrustLabScannerEvidence, TrustLabScannerStatus,
};
pub use report::{
    TrustLabCertification, TrustLabCertificationStatus, TrustLabEvaluation, TrustLabEvidence,
    TrustLabFixtureCall, TrustLabFixtureCallReport, TrustLabFixtureCallStatus,
    TrustLabFixtureExecution, TrustLabPolicyVerdict, TrustLabRemediationAction,
    TrustLabRemediationCategory, TrustLabRemediationOutcome, TrustLabRemediationPlan,
};
use runtime_evidence::runtime_findings;
pub use runtime_evidence::{TrustLabRuntimeEvidence, TrustLabRuntimeProviderPlanEvidence};

use analysis::{
    annotation_findings, evidence_from_findings, findings_from_tool_poisoning_result, lab_finding,
    remediation_plan_from_findings, risk_findings, scanner_status_from_severity,
    schema_drift_findings, score_findings,
};

/// Stable `TrustLab` evaluation schema version.
pub const TRUST_LAB_SCHEMA_VERSION: &str = "trust_lab.v1";

/// Existing scanner adapter id for AX-010 tool-poisoning checks.
pub const TRUST_LAB_TOOL_POISONING_SCANNER: &str = "mcp-gateway.ax010.tool_poisoning";

/// Scanner adapter id for isolated active fixture execution evidence.
pub const TRUST_LAB_ACTIVE_FIXTURE_SCANNER: &str = "mcp-gateway.active_fixture_runtime";

/// `CatalogTrustLab` evaluator with a policy threshold.
#[derive(Debug, Clone)]
pub struct CatalogTrustLab {
    policy: TrustLabPolicy,
}

impl CatalogTrustLab {
    /// Create a lab from a policy.
    #[must_use]
    pub const fn new(policy: TrustLabPolicy) -> Self {
        Self { policy }
    }

    /// Return the policy used by this lab.
    #[must_use]
    pub const fn policy(&self) -> &TrustLabPolicy {
        &self.policy
    }

    /// Evaluate a `TrustCard` with the current clock and no baseline.
    #[must_use]
    pub fn evaluate_card(&self, card: &TrustCard) -> TrustLabEvaluation {
        self.evaluate_card_with_baseline_at(card, None, Utc::now())
    }

    /// Evaluate a `TrustCard` at a specific time and optional baseline.
    #[must_use]
    pub fn evaluate_card_with_baseline_at(
        &self,
        card: &TrustCard,
        baseline: Option<&TrustLabBaseline>,
        evaluated_at: DateTime<Utc>,
    ) -> TrustLabEvaluation {
        let validated_card = card.clone().with_validation();
        let mut findings = validated_card.findings.clone();
        let mut scanners = vec![TrustLabScannerEvidence::from_findings(
            "mcp-gateway.trust_card_validator",
            "TrustCard validator",
            "1",
            &validated_card.findings,
        )];

        findings.extend(risk_findings(&validated_card));

        if let Some(baseline) = baseline {
            let drift_findings = schema_drift_findings(&validated_card, baseline);
            scanners.push(TrustLabScannerEvidence::from_findings(
                "mcp-gateway.schema_drift",
                "Schema drift detector",
                "1",
                &drift_findings,
            ));
            findings.extend(drift_findings);
        }

        let runtime = TrustLabRuntimeEvidence::static_advisory();
        let score = score_findings(&findings);
        let policy_verdict = self.policy.verdict(score, &findings);
        let remediation_plan = remediation_plan_from_findings(&findings, policy_verdict);
        let certification = TrustLabCertification::new(
            &validated_card,
            &self.policy,
            score,
            policy_verdict,
            evaluated_at,
        );

        TrustLabEvaluation {
            schema_version: TRUST_LAB_SCHEMA_VERSION.to_string(),
            evaluated_at,
            input: TrustLabInput::from_card(&validated_card, baseline),
            runtime,
            scanners,
            evidence: evidence_from_findings(&findings),
            findings,
            score,
            policy_verdict,
            remediation_plan,
            certification,
        }
    }

    /// Evaluate a `TrustCard` and attach active runtime fixture evidence.
    #[must_use]
    pub fn evaluate_card_with_runtime_at(
        &self,
        card: &TrustCard,
        baseline: Option<&TrustLabBaseline>,
        evaluated_at: DateTime<Utc>,
        runtime: TrustLabRuntimeEvidence,
    ) -> TrustLabEvaluation {
        let validated_card = card.clone().with_validation();
        let mut evaluation =
            self.evaluate_card_with_baseline_at(&validated_card, baseline, evaluated_at);
        self.attach_runtime_evidence(&mut evaluation, &validated_card, runtime, evaluated_at);
        evaluation
    }

    /// Evaluate one protocol tool through `TrustCard` plus scanner adapters.
    #[must_use]
    pub fn evaluate_tool_at(
        &self,
        server_name: impl Into<String>,
        tool: &Tool,
        baseline: Option<&TrustLabBaseline>,
        evaluated_at: DateTime<Utc>,
    ) -> TrustLabEvaluation {
        let card = TrustCard::from_tool(server_name, tool);
        let mut evaluation = self.evaluate_card_with_baseline_at(&card, baseline, evaluated_at);

        let mut tool_findings = annotation_findings(tool);
        let scanner_result = ToolPoisoningRule.check(tool);
        match scanner_result {
            Ok(result) => {
                tool_findings.extend(findings_from_tool_poisoning_result(&result));
                evaluation.scanners.push(TrustLabScannerEvidence {
                    scanner_id: TRUST_LAB_TOOL_POISONING_SCANNER.to_string(),
                    name: "AX-010 Tool Poisoning Detection".to_string(),
                    version: "1".to_string(),
                    status: scanner_status_from_severity(result.severity),
                    score: scanner_score_percent(result.score),
                    findings_count: result.issues.len(),
                });
            }
            Err(err) => {
                tool_findings.push(lab_finding(
                    "TRUSTLAB_SCANNER_ERROR",
                    TrustFindingSeverity::Warn,
                    "scanner.ax010",
                    format!("Tool-poisoning scanner did not complete: {err}"),
                    "Rerun the evaluation and inspect the tool descriptor manually.",
                    TrustEvidenceKind::Observed,
                ));
                evaluation.scanners.push(TrustLabScannerEvidence {
                    scanner_id: TRUST_LAB_TOOL_POISONING_SCANNER.to_string(),
                    name: "AX-010 Tool Poisoning Detection".to_string(),
                    version: "1".to_string(),
                    status: TrustLabScannerStatus::Warn,
                    score: 60,
                    findings_count: 1,
                });
            }
        }

        evaluation
            .evidence
            .extend(evidence_from_findings(&tool_findings));
        evaluation.findings.extend(tool_findings);
        evaluation.score = score_findings(&evaluation.findings);
        evaluation.policy_verdict = self.policy.verdict(evaluation.score, &evaluation.findings);
        evaluation.remediation_plan =
            remediation_plan_from_findings(&evaluation.findings, evaluation.policy_verdict);
        evaluation.certification = TrustLabCertification::new(
            &card.with_validation(),
            &self.policy,
            evaluation.score,
            evaluation.policy_verdict,
            evaluated_at,
        );
        evaluation
    }

    /// Produce an active-eval plan that can only invoke declared-safe fixtures.
    #[must_use]
    pub fn plan_active_fixture_calls(
        fixtures: &[TrustLabFixtureCall],
    ) -> Vec<TrustLabFixtureCallReport> {
        fixtures
            .iter()
            .map(|fixture| {
                let arguments_digest_sha256 = canonical_json_sha256(&fixture.arguments);
                TrustLabFixtureCallReport {
                    tool_name: fixture.tool_name.clone(),
                    arguments_digest_sha256,
                    declared_safe: fixture.declared_safe,
                    invoked: fixture.declared_safe,
                    status: if fixture.declared_safe {
                        TrustLabFixtureCallStatus::Planned
                    } else {
                        TrustLabFixtureCallStatus::Skipped
                    },
                    result_digest_sha256: None,
                    error: None,
                    skipped_reason: if fixture.declared_safe {
                        None
                    } else {
                        Some("fixture was not explicitly declared safe".to_string())
                    },
                }
            })
            .collect()
    }

    /// Execute declared-safe fixture calls through an isolated runner.
    ///
    /// This method deliberately refuses to invoke fixtures unless both
    /// conditions are true: the fixture is explicitly declared safe and the
    /// caller reports an isolated runtime. The actual runner is injected so
    /// CLI, tests, and future `RuntimeProvider` integration can share the same
    /// fail-closed evidence model.
    #[must_use]
    pub fn run_active_fixture_calls<F>(
        provider: impl Into<String>,
        isolated: bool,
        fixtures: &[TrustLabFixtureCall],
        mut runner: F,
    ) -> TrustLabRuntimeEvidence
    where
        F: FnMut(&TrustLabFixtureCall) -> TrustLabFixtureExecution,
    {
        let fixture_calls = fixtures
            .iter()
            .map(|fixture| {
                let arguments_digest_sha256 = canonical_json_sha256(&fixture.arguments);
                if !fixture.declared_safe {
                    return TrustLabFixtureCallReport {
                        tool_name: fixture.tool_name.clone(),
                        arguments_digest_sha256,
                        declared_safe: false,
                        invoked: false,
                        status: TrustLabFixtureCallStatus::Skipped,
                        result_digest_sha256: None,
                        error: None,
                        skipped_reason: Some(
                            "fixture was not explicitly declared safe".to_string(),
                        ),
                    };
                }

                if !isolated {
                    return TrustLabFixtureCallReport {
                        tool_name: fixture.tool_name.clone(),
                        arguments_digest_sha256,
                        declared_safe: true,
                        invoked: false,
                        status: TrustLabFixtureCallStatus::Skipped,
                        result_digest_sha256: None,
                        error: None,
                        skipped_reason: Some("runtime isolation was not enabled".to_string()),
                    };
                }

                let execution = runner(fixture);
                TrustLabFixtureCallReport {
                    tool_name: fixture.tool_name.clone(),
                    arguments_digest_sha256,
                    declared_safe: true,
                    invoked: true,
                    status: if execution.passed {
                        TrustLabFixtureCallStatus::Passed
                    } else {
                        TrustLabFixtureCallStatus::Failed
                    },
                    result_digest_sha256: execution.output.as_ref().map(canonical_json_sha256),
                    error: execution.error,
                    skipped_reason: None,
                }
            })
            .collect::<Vec<_>>();
        let active_eval = fixture_calls.iter().any(|report| report.invoked);
        let safe_fixture_only = fixture_calls.iter().all(|report| report.declared_safe);

        TrustLabRuntimeEvidence {
            provider: provider.into(),
            isolated,
            active_eval,
            safe_fixture_only,
            fixture_calls,
            runtime_provider_plan: None,
        }
    }

    /// Attach a dry-run active fixture plan without invoking a candidate server.
    ///
    /// This is intended for CLI and CI evidence before a live `RuntimeProvider`
    /// runner is available. It proves the fixture set and fail-closed
    /// eligibility decisions, but keeps the evaluation provisional through a
    /// warning finding until a real isolated runner executes the calls.
    #[must_use]
    pub fn dry_run_active_fixture_calls(
        provider: impl Into<String>,
        isolated: bool,
        fixtures: &[TrustLabFixtureCall],
    ) -> TrustLabRuntimeEvidence {
        let fixture_calls = fixtures
            .iter()
            .map(|fixture| {
                let arguments_digest_sha256 = canonical_json_sha256(&fixture.arguments);
                if !fixture.declared_safe {
                    return TrustLabFixtureCallReport {
                        tool_name: fixture.tool_name.clone(),
                        arguments_digest_sha256,
                        declared_safe: false,
                        invoked: false,
                        status: TrustLabFixtureCallStatus::Skipped,
                        result_digest_sha256: None,
                        error: None,
                        skipped_reason: Some(
                            "fixture was not explicitly declared safe".to_string(),
                        ),
                    };
                }

                if !isolated {
                    return TrustLabFixtureCallReport {
                        tool_name: fixture.tool_name.clone(),
                        arguments_digest_sha256,
                        declared_safe: true,
                        invoked: false,
                        status: TrustLabFixtureCallStatus::Skipped,
                        result_digest_sha256: None,
                        error: None,
                        skipped_reason: Some("runtime isolation was not enabled".to_string()),
                    };
                }

                TrustLabFixtureCallReport {
                    tool_name: fixture.tool_name.clone(),
                    arguments_digest_sha256,
                    declared_safe: true,
                    invoked: false,
                    status: TrustLabFixtureCallStatus::DryRun,
                    result_digest_sha256: None,
                    error: None,
                    skipped_reason: Some(
                        "dry-run evidence only; fixture was not invoked".to_string(),
                    ),
                }
            })
            .collect::<Vec<_>>();
        let active_eval = false;
        let safe_fixture_only = fixture_calls.iter().all(|report| report.declared_safe);

        TrustLabRuntimeEvidence {
            provider: provider.into(),
            isolated,
            active_eval,
            safe_fixture_only,
            fixture_calls,
            runtime_provider_plan: None,
        }
    }

    fn attach_runtime_evidence(
        &self,
        evaluation: &mut TrustLabEvaluation,
        card: &TrustCard,
        runtime: TrustLabRuntimeEvidence,
        evaluated_at: DateTime<Utc>,
    ) {
        let runtime_findings = runtime_findings(&runtime);
        if !runtime.fixture_calls.is_empty() {
            evaluation
                .scanners
                .push(TrustLabScannerEvidence::from_findings(
                    TRUST_LAB_ACTIVE_FIXTURE_SCANNER,
                    "Active fixture runtime",
                    "1",
                    &runtime_findings,
                ));
        }
        evaluation
            .evidence
            .extend(evidence_from_findings(&runtime_findings));
        evaluation.findings.extend(runtime_findings);
        evaluation.runtime = runtime;
        evaluation.score = score_findings(&evaluation.findings);
        evaluation.policy_verdict = self.policy.verdict(evaluation.score, &evaluation.findings);
        evaluation.remediation_plan =
            remediation_plan_from_findings(&evaluation.findings, evaluation.policy_verdict);
        evaluation.certification = TrustLabCertification::new(
            card,
            &self.policy,
            evaluation.score,
            evaluation.policy_verdict,
            evaluated_at,
        );
    }
}

fn scanner_score_percent(score: f64) -> u8 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (score.clamp(0.0, 1.0) * 100.0).round() as u8
    }
}

impl Default for CatalogTrustLab {
    fn default() -> Self {
        Self::new(TrustLabPolicy::default())
    }
}

#[cfg(test)]
mod tests;
