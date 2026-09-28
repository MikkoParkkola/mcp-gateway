// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The client's copy of a context-integrity classification (#2204).
//!
//! A finding's `evidence` can hold the matched text itself. Once enforcement
//! has withheld or rewritten a result, handing that text back in the metadata
//! would deliver exactly what was withheld. The delivered copy is therefore
//! built with the evidence replaced, and the untouched evidence goes to the
//! gateway's own log, which is the operator's record of what matched.

use crate::context_integrity::{ContextIntegrityClassification, ContextIntegrityEvaluation};

/// What a delivered finding says in place of its evidence.
const WITHHELD: &str = "withheld";

/// The classification the client receives. Unchanged when enforcement did not
/// apply: the content itself was delivered, so its evidence reveals nothing new.
pub(super) fn delivered(evaluation: &ContextIntegrityEvaluation) -> ContextIntegrityClassification {
    if !evaluation.policy.enforcement_applied || evaluation.classification.findings.is_empty() {
        return evaluation.classification.clone();
    }
    let mut classification = evaluation.classification.clone();
    let evidence: Vec<(String, &str)> = evaluation
        .classification
        .findings
        .iter()
        .map(|finding| {
            (
                format!("{:?}", finding.classifier),
                finding.evidence.as_str(),
            )
        })
        .collect();
    tracing::warn!(
        target: "context_integrity",
        server = %evaluation.provenance.server,
        tool = %evaluation.provenance.tool,
        invocation_id = %evaluation.provenance.invocation_id,
        decision = ?evaluation.policy.decision,
        findings = ?evidence,
        "context integrity withheld a result; the matched evidence is recorded here, not delivered"
    );
    for finding in &mut classification.findings {
        finding.evidence = WITHHELD.to_string();
    }
    classification
}
