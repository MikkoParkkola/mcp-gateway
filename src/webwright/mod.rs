//! Webwright + botnaut-client spike (MIK-5205) — cross-runtime skill
//! portability and the bnaut-memory wedge.
//!
//! Microsoft Research's Webwright (MIT) is a memoryless browser-automation
//! agent: "a terminal, a browser, and a model".  Every session restarts from
//! zero.  **That memorylessness is the wedge.**  This module models the spike
//! that bolts the botnaut-client platform stack onto a Webwright-style run:
//!
//! - [`agent`] — the memoryless [`WebwrightAgent`] and the
//!   [`MemoryAugmentedAgent`] that wraps it with hebb-recall and attestation.
//! - [`memory`] — the embedded [`HebbMemory`] (bnaut-memory): recall cache,
//!   decision-pins, and a session-boundary-surviving snapshot.
//! - [`attest`] — bnaut-attestation run identity propagation into the
//!   mcp-gateway trace and decision-pins.
//! - [`artifact`] — the run-artifact-first [`ArtifactBundle`].
//! - [`skills`] — the cross-runtime `skills/webwright/` portability check.
//! - [`verdict`] — the gate verdict and platform-reuse provenance.
//! - [`deploy`] — post-deploy telemetry confirmation.
//!
//! [`SpikeReport`] runs the whole flow end-to-end and exposes the gate inputs.

pub mod agent;
pub mod artifact;
pub mod attest;
pub mod deploy;
pub mod memory;
pub mod skills;
pub mod verdict;

pub use agent::{BrowserTask, MemoryAugmentedAgent, RunOutcome, WebwrightAgent};
pub use artifact::{Artifact, ArtifactBundle, ArtifactKind};
pub use attest::{GatewaySpan, GatewayTrace, RunIdentity};
pub use deploy::{DEPLOY_TARGET_BRANCH, DeployTelemetry, confirmation_window};
pub use memory::{DecisionPin, HebbMemory, WEBWRIGHT_SPIKE_TAG};
pub use skills::{CrossRuntimeReport, LoadResult, Runtime, SkillFolder};
pub use verdict::{GateInputs, GateVerdict, Provenance};

use chrono::Utc;

use crate::attestation::BnautAttestationSigner;

/// End-to-end result of running the spike on one task, with everything needed
/// to evaluate the gate verdict (AC.6).
#[derive(Debug, Clone)]
pub struct SpikeReport {
    /// The first (executed) run's outcome.
    pub first_run: RunOutcome,
    /// The second (recalled) run's outcome.
    pub second_run: RunOutcome,
    /// Whether attestation propagated to both the gateway trace and the pins.
    pub attestation_propagates: bool,
    /// Whether hebb-recall short-circuited the second run.
    pub hebb_short_circuits: bool,
    /// Whether the end-to-end run produced a full deliverable bundle.
    pub end_to_end_complete: bool,
    /// The gate inputs derived from the run.
    pub gate_inputs: GateInputs,
    /// The gate verdict.
    pub verdict: GateVerdict,
}

/// Run the full spike on `task`: execute once under the augmented agent,
/// re-run to exercise hebb-recall, verify attestation propagation, and
/// evaluate the gate verdict.
///
/// `signing_key` is bnaut-attestation key material and `agent_identity` is the
/// operator the run acts on behalf of.
#[must_use]
pub fn run_spike(task: &BrowserTask, signing_key: &[u8], agent_identity: &str) -> SpikeReport {
    let signer = BnautAttestationSigner::new(signing_key.to_vec(), "webwright-spike");
    let mut agent = MemoryAugmentedAgent::new("opus-4.7", signer, agent_identity);
    let now = Utc::now();

    let first_run = agent.run(task, now);
    let second_run = agent.run(task, now);

    // Attestation propagates iff the run identity shows up on the gateway trace
    // AND in a decision-pin under the webwright-spike tag.
    let pins = agent.memory().pins_with_tag(WEBWRIGHT_SPIKE_TAG);
    let attestation_propagates = pins.iter().any(|pin| {
        !pin.token_id.is_empty() && !agent.trace_spans_for_token(&pin.token_id).is_empty()
    });

    let hebb_short_circuits = !first_run.from_cache && second_run.from_cache;
    let end_to_end_complete = first_run.bundle.is_complete();

    let gate_inputs = GateInputs {
        attestation_propagates,
        hebb_short_circuits,
        end_to_end_complete,
    };
    let verdict = GateVerdict::evaluate(gate_inputs);

    SpikeReport {
        first_run,
        second_run,
        attestation_propagates,
        hebb_short_circuits,
        end_to_end_complete,
        gate_inputs,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_spike_passes_gate_and_files_epic() {
        let task = BrowserTask::brave_search_stats_scrape();
        let report = run_spike(&task, b"spike-key", "operator");
        assert!(report.attestation_propagates);
        assert!(report.hebb_short_circuits);
        assert!(report.end_to_end_complete);
        assert_eq!(report.verdict, GateVerdict::FileProductionizationEpic);
    }
}
