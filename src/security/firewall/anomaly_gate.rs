// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The anomaly step of [`Firewall::check_request`]: score, then learn only
//! what the firewall admits (#1756).

use super::anomaly::{Observation, Scoring};
use super::{Finding, FindingLocation, Firewall, ScanType, Severity};

/// What the anomaly step decided about one request.
pub(super) struct AnomalyGate<'a> {
    /// The score, when the call could be scored.
    pub(super) score: Option<f64>,
    /// No caller identity to key on: refused unscored, beyond any rule.
    pub(super) blind: bool,
    /// At or above the block threshold: refused, beyond any rule.
    pub(super) forced_block: bool,
    /// Learned by [`Firewall::learn`] only if the request is admitted.
    scoring: Option<Scoring<'a>>,
}

impl Firewall {
    /// Score the call against the caller's own history, pushing findings.
    ///
    /// The identity is the caller's control identity: after MCP 2026-07-28
    /// there is no session, so a per-request key would see a first call every
    /// time. Empty is not an identity (every stateless caller would share one
    /// bucket), so the caller passes `None` and the call is refused unscored:
    /// a detector with nothing to key on cannot protect, and allowing the call
    /// anyway is the failure that reads as success.
    pub(super) fn score_anomaly(
        &self,
        session_id: &str,
        identity: Option<&str>,
        server: &str,
        tool: &str,
        findings: &mut Vec<Finding>,
    ) -> AnomalyGate<'_> {
        let Some(detector) = self.anomaly.as_ref() else {
            return AnomalyGate {
                score: None,
                blind: false,
                forced_block: false,
                scoring: None,
            };
        };
        let (observation, scoring) = detector.begin(identity, server, tool);
        let matched = format!("{server}:{tool}");
        let mut gate = AnomalyGate {
            score: observation.score(),
            blind: false,
            forced_block: false,
            scoring,
        };
        match observation {
            Observation::WarmingUp => {}
            Observation::Unobservable => {
                tracing::warn!(
                    server = server,
                    tool = tool,
                    "OWASP ASI10: anomaly detection has no caller identity to key on; \
                     refusing rather than passing the call unscored"
                );
                gate.blind = true;
                findings.push(Finding {
                    scan_type: ScanType::SequenceAnomaly,
                    severity: Severity::High,
                    description:
                        "Anomaly detection has no caller identity to key on; call refused unscored"
                            .to_string(),
                    matched,
                    location: FindingLocation::SequenceAnomaly,
                });
            }
            Observation::Scored(score) => {
                let block_at = self.config.anomaly_block_threshold;
                if block_at.is_some_and(|t| score >= t) {
                    tracing::warn!(
                        session_id = %crate::gateway::session_id::session_fp(session_id),
                        server = server,
                        tool = tool,
                        anomaly_score = score,
                        "OWASP ASI10: rogue-agent anomaly blocked (score {score:.2})"
                    );
                    // Forced past the rules: an operator who set a block
                    // threshold asked for blocks, and no Allow rule softens one.
                    gate.forced_block = true;
                    findings.push(Finding {
                        scan_type: ScanType::SequenceAnomaly,
                        severity: Severity::High,
                        description: format!(
                            "Anomaly detection triggered: unusual tool sequence blocked \
                             (score {score:.2} ≥ block_threshold {:.2})",
                            block_at.unwrap_or(1.0),
                        ),
                        matched,
                        location: FindingLocation::SequenceAnomaly,
                    });
                } else if score >= self.config.anomaly_threshold {
                    findings.push(Finding {
                        scan_type: ScanType::SequenceAnomaly,
                        severity: Severity::Low,
                        description: format!("Unusual tool sequence (anomaly score: {score:.2})"),
                        matched,
                        location: FindingLocation::SequenceAnomaly,
                    });
                }
            }
        }
        gate
    }

    /// Learn an admitted call. A refused call is dropped unlearned, so a
    /// blocked retry can never train itself into acceptance.
    pub(super) fn learn(&self, gate: AnomalyGate<'_>, admitted: bool) {
        if let (true, Some(detector), Some(scoring)) =
            (admitted, self.anomaly.as_ref(), gate.scoring)
        {
            detector.commit(scoring);
        }
    }
}
