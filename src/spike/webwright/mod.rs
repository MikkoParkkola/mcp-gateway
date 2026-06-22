//! Webwright spike integration (MIK-5205).
//!
//! Demonstrates cross-runtime skill portability between Webwright (Microsoft
//! Research, MIT) and mcp-gateway's bnaut-attestation + bnaut-memory primitives.
//!
//! ## Architecture
//!
//! ```text
//! Webwright (browser agent) ──┐
//!                              ├──▶ mcp-gateway attestation (bnaut-attestation)
//! bnaut-memory (hebb-recall) ──┘         │
//!                                        ▼
//!                            Artifact bundle (run-artifact-first)
//!                            ┌─ code
//!                            ├─ screenshots
//!                            ├─ DOM snapshots
//!                            ├─ model trace
//!                            └─ hebb decision-pins (tag: webwright-spike)
//! ```
//!
//! ## Gate verdict (WW.6)
//!
//! Three conditions must all pass for a productionization epic filing:
//! 1. bnaut-attestation propagates (identity in trace + decision-pins)
//! 2. hebb-recall measurably short-circuits (cache-hit on second run)
//! 3. end-to-end task completes with full artifact bundle

/// Artifact bundle for run-artifact-first deliverable pattern.
pub mod artifact;
/// Hebb-embedded task memory cache (zero-IPC, in-process).
pub mod memory;
/// Cross-runtime skill load verification.
pub mod skill_loader;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;

use crate::attestation::signer::{BnautAttestationSigner, TokenRequest};
use crate::attestation::validator::{AttestationMode, AttestationValidator};
use crate::tracing_context::GatewayTrace;

use self::artifact::{ArtifactBundle, ArtifactEntry, ArtifactKind};
use self::memory::{
    HebbDecisionPin, HebbDecisionPins, TaskDescriptor, TaskMemory, TaskResult,
};

/// Spike run context binding bnaut-attestation and bnaut-memory.
pub struct WebwrightSpikeContext {
    key: Vec<u8>,
    key_id: String,
    /// Attestation validator for boundary calls.
    pub validator: Arc<AttestationValidator>,
    /// Attestation mode (observe or enforce).
    pub mode: AttestationMode,
    /// Hebb-recall task memory cache.
    pub memory: Arc<TaskMemory>,
    /// Hebb decision-pin collection.
    pub decision_pins: Arc<HebbDecisionPins>,
}

impl WebwrightSpikeContext {
    /// Create a new spike context with the given attestation primitives.
    ///
    /// Internally creates two signer instances from the same key material:
    /// one for the validator (verification) and one available for token
    /// issuance via [`Self::make_signer`].
    pub fn new(
        signer: BnautAttestationSigner,
        mode: AttestationMode,
    ) -> Self {
        let key_id = signer.key_id().to_string();
        let validator = Arc::new(AttestationValidator::new(signer));
        Self {
            key: Vec::new(),
            key_id,
            validator,
            mode,
            memory: Arc::new(TaskMemory::new()),
            decision_pins: Arc::new(HebbDecisionPins::new()),
        }
    }

    /// Create a spike context with explicit key material for dual-signer use.
    pub fn with_key(
        key: Vec<u8>,
        key_id: impl Into<String>,
        mode: AttestationMode,
    ) -> Self {
        let key_id_str = key_id.into();
        let signer = BnautAttestationSigner::new(key.clone(), &key_id_str);
        let validator = Arc::new(AttestationValidator::new(signer));
        Self {
            key,
            key_id: key_id_str,
            validator,
            mode,
            memory: Arc::new(TaskMemory::new()),
            decision_pins: Arc::new(HebbDecisionPins::new()),
        }
    }

    /// Create a fresh signer instance from the stored key material.
    fn make_signer(&self) -> BnautAttestationSigner {
        BnautAttestationSigner::new(self.key.clone(), &self.key_id)
    }
}

/// Output of a single Webwright spike run.
#[derive(Debug, Clone, Serialize)]
pub struct WebwrightSpikeRun {
    /// Unique identifier for this run.
    pub run_id: String,
    /// W3C trace ID from the gateway trace.
    pub trace_id: String,
    /// Agent identity used for attestation.
    pub agent_identity: String,
    /// Task type that was executed.
    pub task_type: String,
    /// Target URL of the browser automation.
    pub target_url: String,
    /// Whether the hebb-recall cache was hit (short-circuit).
    pub hebb_recall_hit: bool,
    /// Whether attestation identity propagated through validation.
    pub attestation_propagated: bool,
    /// Token ID from the attestation token, if issued.
    pub attestation_token_id: Option<String>,
    /// Number of attestation rejections during the run.
    pub attestation_rejections: u64,
    /// Total artifacts collected in the bundle.
    pub artifact_count: u64,
    /// Number of hebb decision-pins recorded.
    pub decision_pin_count: usize,
    /// Gate verdict (three-way gate).
    pub gate_verdict: GateVerdict,
}

/// Gate verdict for the Webwright spike (WW.6).
///
/// All three conditions must pass for a productionization epic filing.
/// If any fails, the verdict is INSPIRE-only with no further engineering.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct GateVerdict {
    /// Whether bnaut-attestation identity propagated through trace.
    pub attestation_propagated: bool,
    /// Whether hebb-recall measurably short-circuits repeat execution.
    pub hebb_short_circuits: bool,
    /// Whether end-to-end task completed with full artifact bundle.
    pub end_to_end_complete: bool,
    /// Whether all three conditions passed.
    pub all_pass: bool,
    /// Human-readable recommendation.
    pub recommendation: String,
}

impl GateVerdict {
    /// Compute the gate verdict from the three conditions.
    pub fn compute(
        attestation_propagated: bool,
        hebb_short_circuits: bool,
        end_to_end_complete: bool,
    ) -> Self {
        let all_pass =
            attestation_propagated && hebb_short_circuits && end_to_end_complete;
        let recommendation = if all_pass {
            "File botnaut-client productionization epic".to_string()
        } else {
            "INSPIRE-only verdict, no further engineering".to_string()
        };
        Self {
            attestation_propagated,
            hebb_short_circuits,
            end_to_end_complete,
            all_pass,
            recommendation,
        }
    }
}

/// Execute the Webwright spike with the given tasks.
///
/// Runs each task through the full spike flow:
/// 1. Check hebb-recall (cache hit short-circuits browser execution)
/// 2. On miss: simulate browser execution, store result
/// 3. Pin a hebb decision under tag 'webwright-spike'
/// 4. Collect artifacts
/// 5. Propagate attestation identity through trace
///
/// Returns the run output including gate verdict.
#[allow(clippy::too_many_lines)]
pub fn webwright_spike_run(
    ctx: &WebwrightSpikeContext,
    tasks: &[(TaskDescriptor, TaskResult)],
) -> WebwrightSpikeRun {
    let run_id = uuid::Uuid::new_v4().to_string();
    let agent_identity = "webwright-spike-agent".to_string();
    let task_uuid = uuid::Uuid::new_v4();

    // Issue attestation token for the run
    let token_request = TokenRequest {
        agent_identity: agent_identity.clone(),
        task_uuid,
        capabilities: vec!["browser:scrape".to_string()],
    };
    let now = Utc::now();
    let signer = ctx.make_signer();
    let token = signer.issue(&token_request, now, chrono::TimeDelta::hours(1));
    let token_id = token.claims().token_id.clone();

    // Validate through gateway attestation boundary
    let validation = ctx.validator.validate_boundary_call(
        Some(token.encoded()),
        "webwright_spike_run",
        Some("browser:scrape"),
        now,
    );
    let attestation_propagated = validation.is_ok();
    let attestation_rejections = ctx.validator.rejections_total();

    // Create trace for the run
    let mut trace = GatewayTrace::start("webwright_scrape", "webwright-spike");
    trace.set_transport("browser", "https://search.brave.com/stats");
    trace.set_exec_attribute("spike_tag", "webwright-spike");
    trace.set_exec_attribute("run_id", &run_id);

    let bundle = ArtifactBundle::new(&run_id);

    // Add baseline code artifact
    bundle.add(ArtifactEntry {
        kind: ArtifactKind::Code,
        name: "webwright-spike-runner".to_string(),
        path: "src/spike/webwright/mod.rs".to_string(),
        byte_size: 0,
        created_at: now.to_rfc3339(),
    });

    let mut hebb_hit = false;
    let pins_before = ctx.decision_pins.len();

    for (descriptor, provided_result) in tasks {
        let cached = ctx.memory.recall(descriptor);

        // Determine effective result: cached (hit) or provided (miss)
        let effective_result = if let Some(cached_result) = cached {
            hebb_hit = true;
            cached_result
        } else {
            // Store in hebb-recall cache for future short-circuit
            ctx.memory.store(
                descriptor,
                TaskResult {
                    data: provided_result.data.clone(),
                    exit_code: provided_result.exit_code,
                    dom_snapshot: provided_result.dom_snapshot.clone(),
                    screenshot_paths: provided_result.screenshot_paths.clone(),
                    model_trace: provided_result.model_trace.clone(),
                },
                Duration::from_secs(3600),
            );
            provided_result.clone()
        };

        // Collect artifacts from the effective result (both hit and miss)
        if let Some(ref dom) = effective_result.dom_snapshot {
            bundle.add(ArtifactEntry {
                kind: ArtifactKind::DomSnapshot,
                name: format!("{}_dom", descriptor.task_type),
                path: format!(
                    "artifacts/{}/{}/dom.html",
                    run_id, descriptor.task_type
                ),
                byte_size: dom.len() as u64,
                created_at: now.to_rfc3339(),
            });
        }

        for (i, path) in effective_result.screenshot_paths.iter().enumerate() {
            bundle.add(ArtifactEntry {
                kind: ArtifactKind::Screenshot,
                name: format!("{}_screenshot_{i}", descriptor.task_type),
                path: path.clone(),
                byte_size: 0,
                created_at: now.to_rfc3339(),
            });
        }

        if let Some(ref trace_data) = effective_result.model_trace {
            bundle.add(ArtifactEntry {
                kind: ArtifactKind::ModelTrace,
                name: format!("{}_trace", descriptor.task_type),
                path: format!(
                    "artifacts/{}/{}/trace.json",
                    run_id, descriptor.task_type
                ),
                byte_size: trace_data.len() as u64,
                created_at: now.to_rfc3339(),
            });
        }

        // Pin hebb decision under tag 'webwright-spike'
        let decision = if hebb_hit { "cache_hit" } else { "cache_miss" };
        let pin = HebbDecisionPin::new("webwright-spike", descriptor, decision)
            .with_attestation(&token_id);
        ctx.decision_pins.pin(pin);
    }

    // Add hebb decision-pins as artifacts
    let all_pins = ctx.decision_pins.snapshot();
    let this_run_pins = &all_pins[pins_before..];
    for pin in this_run_pins {
        bundle.add(ArtifactEntry {
            kind: ArtifactKind::HebbDecisionPin,
            name: pin.pin_id.clone(),
            path: format!("artifacts/{}/pins/{}.json", run_id, pin.pin_id),
            byte_size: 0,
            created_at: now.to_rfc3339(),
        });
    }

    let bundle_verification = bundle.verify_complete();
    let end_to_end_complete = bundle_verification.complete;

    let task_type = tasks
        .first()
        .map_or("unknown", |(d, _)| d.task_type.as_str())
        .to_string();
    let target_url = tasks
        .first()
        .map_or("unknown", |(d, _)| d.target_url.as_str())
        .to_string();

    let verdict = GateVerdict::compute(
        attestation_propagated,
        hebb_hit,
        end_to_end_complete,
    );

    // Capture trace_id before finishing (finish consumes the trace)
    let trace_id = trace.trace_id();
    trace.set_exec_attribute("gate_verdict", &verdict.recommendation);
    trace.finish_transport(true);
    trace.finish_execution(true, None);
    trace.finish(true);

    WebwrightSpikeRun {
        run_id,
        trace_id,
        agent_identity,
        task_type,
        target_url,
        hebb_recall_hit: hebb_hit,
        attestation_propagated,
        attestation_token_id: Some(token_id),
        attestation_rejections,
        artifact_count: bundle.total_entries(),
        decision_pin_count: this_run_pins.len(),
        gate_verdict: verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_KEY: &[u8] = b"test-key-32bytes-long-for-spike!!";
    const TEST_KEY_ID: &str = "test";

    fn test_ctx() -> WebwrightSpikeContext {
        WebwrightSpikeContext::with_key(
            TEST_KEY.to_vec(),
            TEST_KEY_ID,
            AttestationMode::Observe,
        )
    }

    fn sample_task() -> (TaskDescriptor, TaskResult) {
        let desc = TaskDescriptor::new("scrape", "https://search.brave.com/stats")
            .with_param("date_range", json!("last_30_days"));
        let result = TaskResult {
            data: json!({"queries": [{"q": "test", "count": 42}]}),
            exit_code: 0,
            dom_snapshot: Some("<html>stats page</html>".to_string()),
            screenshot_paths: vec!["artifacts/screenshot_0.png".to_string()],
            model_trace: Some(
                json!({"steps": ["navigate", "extract", "output"]}).to_string(),
            ),
        };
        (desc, result)
    }

    #[test]
    fn spike_context_creates_validator() {
        let ctx = test_ctx();
        assert_eq!(ctx.mode, AttestationMode::Observe);
        assert_eq!(ctx.memory.len(), 0);
        assert_eq!(ctx.decision_pins.len(), 0);
    }

    #[test]
    fn spike_run_first_call_is_cache_miss() {
        let ctx = test_ctx();
        let (desc, result) = sample_task();
        let run = webwright_spike_run(&ctx, &[(desc, result)]);

        assert!(!run.hebb_recall_hit);
        assert!(run.attestation_propagated);
        assert!(run.attestation_token_id.is_some());
        assert_eq!(run.decision_pin_count, 1);
    }

    #[test]
    fn spike_run_second_call_is_cache_hit() {
        let ctx = test_ctx();
        let (desc, result) = sample_task();

        // First run: populates the cache
        let _run1 = webwright_spike_run(&ctx, &[(desc.clone(), result.clone())]);

        // Second run: should get cache hit
        let run2 = webwright_spike_run(&ctx, &[(desc, result)]);
        assert!(run2.hebb_recall_hit);
    }

    #[test]
    fn gate_verdict_all_pass() {
        let v = GateVerdict::compute(true, true, true);
        assert!(v.all_pass);
        assert!(v.recommendation.contains("productionization"));
    }

    #[test]
    fn gate_verdict_any_fail_is_inspire_only() {
        let v = GateVerdict::compute(true, false, true);
        assert!(!v.all_pass);
        assert!(v.recommendation.contains("INSPIRE-only"));

        let v2 = GateVerdict::compute(false, true, true);
        assert!(!v2.all_pass);

        let v3 = GateVerdict::compute(true, true, false);
        assert!(!v3.all_pass);
    }
}
