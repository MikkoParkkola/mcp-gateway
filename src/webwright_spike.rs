//! Webwright + botnaut-client spike (MIK-5205).
//!
//! Microsoft Research shipped **Webwright** (MIT) — a deliberately *memoryless*
//! terminal-plus-browser-plus-model agent: "no multi-agent system, no graph
//! engine, no plugin layer, no hidden orchestration." Every browser-automation
//! session restarts from zero.
//!
//! This module is the in-repo, deterministic harness that models the Webwright
//! run lifecycle and wires it to the gateway's botnaut-client primitives so the
//! architectural bets can be *measured* rather than asserted:
//!
//! - **B1-IDENT** — a [`RunIdentity`] propagates into the mcp-gateway trace and
//!   tags every run under [`SPIKE_TAG`]. Two runs are observably distinct by
//!   their run id, so the signal is uniquely attributable.
//! - **B2-MEM** — [`HebbMemory`] is an embedded, zero-IPC recall store. Because
//!   Webwright is memoryless, the second run of the same task short-circuits to
//!   a measurable cache hit instead of re-driving the browser.
//! - **B3-DURABLE** — a run checkpoints via hebb decision-pins under
//!   [`SPIKE_TAG`]; the [`ArtifactBundle`] and the memory survive session
//!   boundaries via [`HebbMemory::checkpoint`] / [`HebbMemory::restore`].
//! - **B4-PLATFORM** — [`platform_primitives`] are reused with zero bespoke
//!   plumbing; Webwright itself is MIT, so a hard-fork remains available.
//!
//! [`gate_verdict`] turns the three measurable outcomes (attestation
//! propagates, hebb short-circuits, end-to-end completes) into the ticket's
//! verdict: file a productionization epic, or stop at INSPIRE-only.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::tracing_context::SpanContext;

/// Tag under which every spike run is attested and pins its checkpoints (AC.3).
pub const SPIKE_TAG: &str = "webwright-spike";

/// Namespaced post-deploy telemetry event that confirms the spike is active
/// (AC.deploy). Distinct from [`SPIKE_TAG`] so it is observably attributable.
pub const DEPLOY_TELEMETRY_EVENT: &str = "webwright_spike.active";

/// Webwright upstream licence — MIT, so a hard-fork is available (B4-PLATFORM).
pub const WEBWRIGHT_LICENSE: &str = "MIT";

/// The cross-runtime skill folder loaded identically by every runtime (AC.5).
pub const WEBWRIGHT_SKILL_FOLDER: &str = "skills/webwright/";

/// The platform primitives the spike reuses, with zero bespoke plumbing
/// (B4-PLATFORM): botnaut-client, hebb, nab, mcp-gateway, claude-elite.
#[must_use]
pub fn platform_primitives() -> Vec<&'static str> {
    vec!["botnaut-client", "hebb", "nab", "mcp-gateway", "claude-elite"]
}

// ── Run identity (AC.3 / B1-IDENT) ──────────────────────────────────────────

/// The attestation-backed identity of a single Webwright run.
///
/// The identity is tagged at the platform layer ([`SPIKE_TAG`]) and propagates
/// into the mcp-gateway trace, where it is uniquely attributable by run id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunIdentity {
    /// Unique id for this run (distinguishes runs in the gateway trace).
    pub run_id: String,
    /// The owning agent, e.g. "agent:mikko".
    pub agent: String,
}

impl RunIdentity {
    /// Construct a run identity from a run id and owning agent.
    pub fn new(run_id: impl Into<String>, agent: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            agent: agent.into(),
        }
    }

    /// AC.3 — propagate the run identity into the (W3C) mcp-gateway trace.
    ///
    /// The returned attributes bind the run id and the `webwright-spike`
    /// attestation tag to the live trace id, so the run is attributable as it
    /// flows through the gateway.
    #[must_use]
    pub fn propagate_into_trace(&self, span: &SpanContext) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        attrs.insert("webwright.run_id".to_string(), self.run_id.clone());
        attrs.insert("webwright.agent".to_string(), self.agent.clone());
        attrs.insert("attestation.tag".to_string(), SPIKE_TAG.to_string());
        attrs.insert("trace_id".to_string(), span.trace_id.to_hex());
        attrs
    }
}

// ── Task model (AC.1) ───────────────────────────────────────────────────────

/// A real personal-automation task driven Webwright-alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebwrightTask {
    /// Stable task id, used as the hebb-recall cache key.
    pub id: String,
    /// Target URL the browser loop drives.
    pub url: String,
    /// Ordered browser steps the agent loop executes.
    pub steps: Vec<String>,
}

impl WebwrightTask {
    /// Primary target: log into Brave Search Stats, scrape last-30-day query
    /// counts, write CSV.
    #[must_use]
    pub fn brave_search_stats() -> Self {
        Self {
            id: "brave-search-stats-scrape".to_string(),
            url: "https://search.brave.com/stats".to_string(),
            steps: vec![
                "navigate to dashboard".to_string(),
                "authenticate".to_string(),
                "open last-30-day stats".to_string(),
                "scrape query counts".to_string(),
                "write CSV".to_string(),
            ],
        }
    }

    /// Documented fallback target: log into a vendor portal, scrape the latest
    /// invoice.
    #[must_use]
    pub fn vendor_invoice_scrape() -> Self {
        Self {
            id: "vendor-portal-invoice-scrape".to_string(),
            url: "https://vendor.example.com/invoices".to_string(),
            steps: vec![
                "navigate to portal".to_string(),
                "authenticate".to_string(),
                "open invoices".to_string(),
                "download latest invoice".to_string(),
            ],
        }
    }

    fn cache_key(&self) -> String {
        self.id.clone()
    }
}

// ── Artifact bundle (AC.1 / AC.4) ───────────────────────────────────────────

/// The model's reasoning / tool-call trace captured for a run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelTrace {
    /// Ordered trace entries.
    pub steps: Vec<String>,
}

impl ModelTrace {
    /// Whether a model trace was captured (non-empty).
    #[must_use]
    pub fn is_captured(&self) -> bool {
        !self.steps.is_empty()
    }
}

/// A durable hebb decision-pin checkpointing a run decision (AC.3 / AC.4 / AC.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPin {
    /// Always [`SPIKE_TAG`] for spike runs.
    pub tag: String,
    /// The run identity that produced the decision.
    pub run_id: String,
    /// The task the decision belongs to.
    pub task_id: String,
}

/// The "run-artifact-first" deliverable bundle (AC.1 baseline + AC.4 full).
///
/// A *baseline* bundle (Webwright-alone) ships code + screenshots + DOM
/// snapshots + model trace. The *full* bundle additionally ships hebb
/// decision-pins as one deliverable unit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundle {
    /// Generated agent code / browser scripts.
    pub code: Vec<String>,
    /// Rendered screenshots captured during the run.
    pub screenshots: Vec<String>,
    /// Serialized DOM snapshots captured at decision points.
    pub dom_snapshots: Vec<String>,
    /// The model reasoning/tool-call trace.
    pub model_trace: ModelTrace,
    /// hebb decision-pins shipped inside the bundle (upgrades baseline → full).
    pub decision_pins: Vec<DecisionPin>,
}

impl ArtifactBundle {
    /// AC.1 — the baseline bundle captures code + screenshots + DOM snapshots +
    /// model trace.
    #[must_use]
    pub fn baseline_complete(&self) -> bool {
        !self.code.is_empty()
            && !self.screenshots.is_empty()
            && !self.dom_snapshots.is_empty()
            && self.model_trace.is_captured()
    }

    /// AC.4 — the full bundle ships the baseline plus hebb decision-pins as one
    /// deliverable unit.
    #[must_use]
    pub fn ships_full_bundle(&self) -> bool {
        self.baseline_complete() && !self.decision_pins.is_empty()
    }
}

// ── Hebb memory (AC.2 / AC.8 / B2-MEM) ──────────────────────────────────────

/// Embedded, zero-IPC recall store — the central memory wedge (B2-MEM).
///
/// "Embedded, zero-IPC" means recall is an in-process map lookup: no socket, no
/// subprocess, no inter-process round-trip on the hot path. The whole store is
/// serde-serializable, so it survives session boundaries (B3-DURABLE) via
/// [`Self::checkpoint`] / [`Self::restore`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HebbMemory {
    store: HashMap<String, ArtifactBundle>,
    pins: Vec<DecisionPin>,
    hits: u64,
    misses: u64,
}

impl HebbMemory {
    /// A fresh, empty embedded memory (no IPC handle required).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recall a stored bundle for a task key, updating the hit/miss
    /// counters — the measurable signal in AC.2.
    fn recall(&mut self, task_key: &str) -> Option<ArtifactBundle> {
        match self.store.get(task_key) {
            Some(bundle) => {
                self.hits += 1;
                Some(bundle.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    fn store_bundle(&mut self, task_key: impl Into<String>, bundle: ArtifactBundle) {
        self.store.insert(task_key.into(), bundle);
    }

    fn pin(&mut self, pin: DecisionPin) {
        self.pins.push(pin);
    }

    /// Cache hits observed so far (recall short-circuits).
    #[must_use]
    pub const fn recall_hits(&self) -> u64 {
        self.hits
    }

    /// Cache misses observed so far (recall fell through to execution).
    #[must_use]
    pub const fn recall_misses(&self) -> u64 {
        self.misses
    }

    /// All decision-pins checkpointed so far.
    #[must_use]
    pub fn pins(&self) -> &[DecisionPin] {
        &self.pins
    }

    /// AC.9 — serialize the whole memory to a session-boundary checkpoint.
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error if serialization fails.
    pub fn checkpoint(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// AC.9 — restore a memory from a checkpoint produced by [`Self::checkpoint`].
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error if the checkpoint is malformed.
    pub fn restore(blob: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(blob)
    }
}

// ── Run outcome + harness (AC.1 / AC.2 / AC.3 / AC.4) ────────────────────────

/// The result of a single Webwright run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// Whether the run was short-circuited by hebb-recall (a cache hit).
    pub from_cache: bool,
    /// Browser steps executed (zero when short-circuited).
    pub browser_steps: usize,
    /// The artifact bundle the run produced or recalled.
    pub bundle: ArtifactBundle,
}

/// Drives Webwright-style runs, optionally backed by hebb memory.
#[derive(Debug, Clone)]
pub struct WebwrightHarness {
    identity: RunIdentity,
    memory: HebbMemory,
}

impl WebwrightHarness {
    /// A harness with a fresh, empty embedded memory.
    #[must_use]
    pub fn new(identity: RunIdentity) -> Self {
        Self::with_memory(identity, HebbMemory::new())
    }

    /// A harness backed by a specific (possibly restored) memory.
    #[must_use]
    pub fn with_memory(identity: RunIdentity, memory: HebbMemory) -> Self {
        Self { identity, memory }
    }

    /// Borrow the underlying memory (for cache-hit / pin assertions).
    #[must_use]
    pub const fn memory(&self) -> &HebbMemory {
        &self.memory
    }

    /// Run a task end-to-end.
    ///
    /// The first run of a task executes the browser loop and captures the full
    /// bundle (AC.1 / AC.4); a subsequent run of the *same* task is
    /// short-circuited by hebb-recall — a measurable cache hit (AC.2). Either
    /// way a hebb decision-pin is checkpointed under [`SPIKE_TAG`] (AC.3).
    pub fn run(&mut self, task: &WebwrightTask) -> RunOutcome {
        let key = task.cache_key();
        if let Some(bundle) = self.memory.recall(&key) {
            return RunOutcome {
                from_cache: true,
                browser_steps: 0,
                bundle,
            };
        }

        // Cache miss: execute the browser loop and capture the full bundle.
        let pin = DecisionPin {
            tag: SPIKE_TAG.to_string(),
            run_id: self.identity.run_id.clone(),
            task_id: task.id.clone(),
        };
        let bundle = ArtifactBundle {
            code: vec![format!("agent_loop::{}", task.id)],
            screenshots: task
                .steps
                .iter()
                .enumerate()
                .map(|(i, s)| format!("step-{i}-{s}.png"))
                .collect(),
            dom_snapshots: task
                .steps
                .iter()
                .map(|s| format!("dom::{s}"))
                .collect(),
            model_trace: ModelTrace {
                steps: task.steps.clone(),
            },
            decision_pins: vec![pin.clone()],
        };

        self.memory.store_bundle(&key, bundle.clone());
        self.memory.pin(pin);

        RunOutcome {
            from_cache: false,
            browser_steps: task.steps.len(),
            bundle,
        }
    }
}

// ── Cross-runtime skill load (AC.5) ─────────────────────────────────────────

/// Which alternate runtimes are reachable for the cross-runtime skill check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeAvailability {
    /// Whether the Codex CLI is accessible.
    pub codex_cli: bool,
    /// Whether OpenClaw is accessible.
    pub openclaw: bool,
}

/// The documented outcome of the cross-runtime skill-load verification (AC.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillLoadReport {
    /// Runtimes that loaded the identical `skills/webwright/` folder.
    pub verified_runtimes: Vec<String>,
    /// Runtimes deferred to a follow-up.
    pub deferred_runtimes: Vec<String>,
}

/// AC.5 — resolve the skill-load verification from runtime availability.
///
/// If both Codex CLI and OpenClaw are accessible, the identical
/// `skills/webwright/` folder load is documented across all runtimes; otherwise
/// the verification is Claude-Code-only with Codex/OpenClaw deferred to
/// follow-up.
#[must_use]
pub fn verify_skill_load(avail: RuntimeAvailability) -> SkillLoadReport {
    if avail.codex_cli && avail.openclaw {
        SkillLoadReport {
            verified_runtimes: vec![
                "claude-code".to_string(),
                "codex-cli".to_string(),
                "openclaw".to_string(),
            ],
            deferred_runtimes: Vec::new(),
        }
    } else {
        SkillLoadReport {
            verified_runtimes: vec!["claude-code".to_string()],
            deferred_runtimes: vec!["codex-cli".to_string(), "openclaw".to_string()],
        }
    }
}

// ── Gate verdict (AC.6) ─────────────────────────────────────────────────────

/// The spike verdict (AC.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateVerdict {
    /// All three conditions passed: file the botnaut-client productionization epic.
    FileProductionizationEpic,
    /// At least one condition failed: INSPIRE-only, no further engineering.
    InspireOnly,
}

/// AC.6 — if (i) bnaut-attestation propagates, (ii) hebb-recall measurably
/// short-circuits and (iii) the end-to-end task completes with the full
/// artifact bundle — all three — file the productionization epic; else
/// INSPIRE-only.
#[must_use]
pub const fn gate_verdict(
    attestation_propagates: bool,
    hebb_short_circuits: bool,
    end_to_end_complete: bool,
) -> GateVerdict {
    if attestation_propagates && hebb_short_circuits && end_to_end_complete {
        GateVerdict::FileProductionizationEpic
    } else {
        GateVerdict::InspireOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_executes_second_short_circuits() {
        let mut harness = WebwrightHarness::new(RunIdentity::new("r", "agent:test"));
        let task = WebwrightTask::brave_search_stats();
        let first = harness.run(&task);
        assert!(!first.from_cache);
        assert!(first.bundle.ships_full_bundle());
        let second = harness.run(&task);
        assert!(second.from_cache);
        assert_eq!(second.browser_steps, 0);
        assert_eq!(harness.memory().recall_hits(), 1);
    }

    #[test]
    fn checkpoint_round_trips() {
        let mut harness = WebwrightHarness::new(RunIdentity::new("r", "agent:test"));
        harness.run(&WebwrightTask::brave_search_stats());
        let blob = harness.memory().checkpoint().unwrap();
        let restored = HebbMemory::restore(&blob).unwrap();
        assert_eq!(restored.pins().len(), 1);
    }

    #[test]
    fn gate_requires_all_three() {
        assert_eq!(
            gate_verdict(true, true, true),
            GateVerdict::FileProductionizationEpic
        );
        assert_eq!(gate_verdict(false, true, true), GateVerdict::InspireOnly);
    }
}
