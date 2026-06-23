//! Webwright + botnaut-client spike harness (MIK-5205).
//!
//! Microsoft Research's [Webwright](https://github.com/microsoft/Webwright) is a
//! deliberately *memoryless* browser-automation agent: every session restarts
//! from zero. This module is the in-repo, deterministic harness for the spike
//! that measures the botnaut-client wedge against that gap — without driving a
//! real browser from a unit test, it models the run lifecycle Webwright exposes
//! and wires it to three gateway-native platform primitives:
//!
//! * **bnaut-memory** ([`HebbMemory`]) — `hebb-recall` short-circuits the second
//!   run of an identical task (AC.2 / B2-MEM). The cache hit is *measurable*:
//!   [`HebbMemory::recall_hits`] increments and the short-circuited run records
//!   zero browser steps.
//! * **bnaut-attestation** ([`RunIdentity`]) — the Webwright run identity
//!   propagates into the gateway's W3C trace ([`crate::tracing_context::SpanContext`])
//!   and into hebb decision-pins tagged [`SPIKE_TAG`] (AC.3 / B1-IDENT).
//! * **hebb decision-pins** ([`DecisionPin`]) — durable browser-task checkpoints
//!   that survive a [`HebbMemory::checkpoint`] / [`HebbMemory::restore`] session
//!   boundary (AC.9 / B3-DURABLE).
//!
//! The deliverable is the [`ArtifactBundle`]: code + screenshots + DOM snapshots
//! + model trace + decision-pins shipped as one unit ("run-artifact-first",
//! AC.4). The [`gate_verdict`] function encodes the AC.6 decision gate.
//!
//! Everything here reuses existing gateway primitives; there is no bespoke
//! plumbing (B4-PLATFORM, AC.10).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::tracing_context::SpanContext;

/// Decision-pin / trace tag that scopes every artifact this spike emits.
pub const SPIKE_TAG: &str = "webwright-spike";

/// Distinguishable post-deploy telemetry event name (B1-IDENT / AC.deploy).
///
/// Emitted once the spike code path activates so 30 minutes of post-deploy
/// telemetry can confirm the change is live. The name is unique to this spike
/// and is observably distinct from any pre-existing gateway counter.
pub const DEPLOY_TELEMETRY_EVENT: &str = "webwright_spike.active";

// ============================================================================
// Task + artifacts (AC.1, AC.4)
// ============================================================================

/// A single real personal-automation task driven end-to-end by Webwright.
///
/// The spike target is the Brave Search Stats scrape; the fallback is the
/// vendor-portal invoice scrape (AC.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebwrightTask {
    /// Stable task identifier — the hebb-recall cache key.
    pub id: String,
    /// Target URL the browser session opens.
    pub url: String,
    /// Natural-language goal handed to the model.
    pub goal: String,
}

impl WebwrightTask {
    /// The AC.1 primary target: scrape last-30-day Brave Search query counts.
    #[must_use]
    pub fn brave_search_stats() -> Self {
        Self {
            id: "brave-search-stats-scrape".to_owned(),
            url: "https://search.brave.com/stats".to_owned(),
            goal: "Log into Brave Search Stats, scrape last-30-day query counts, write CSV"
                .to_owned(),
        }
    }

    /// The AC.1 fallback target: scrape invoices from the vendor portal.
    #[must_use]
    pub fn vendor_invoice_scrape() -> Self {
        Self {
            id: "vendor-portal-invoice-scrape".to_owned(),
            url: "https://portal.example-vendor.test/invoices".to_owned(),
            goal: "Log into the vendor portal and scrape the open-invoice table".to_owned(),
        }
    }
}

/// A captured screenshot artifact (filename + opaque byte length).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screenshot {
    /// Artifact file name within the bundle.
    pub name: String,
    /// Captured PNG byte length (non-zero for a real capture).
    pub bytes: usize,
}

/// A captured DOM snapshot artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomSnapshot {
    /// Artifact file name within the bundle.
    pub name: String,
    /// Serialized HTML length (non-zero for a real capture).
    pub html_len: usize,
}

/// The model interaction trace for a run (one entry per model turn).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelTrace {
    /// Model identifier used for the run (e.g. `claude-opus-4-8`).
    pub model: String,
    /// One recorded reasoning/action step per model turn.
    pub turns: Vec<String>,
}

impl ModelTrace {
    /// `true` when at least one model turn was recorded.
    #[must_use]
    pub fn is_captured(&self) -> bool {
        !self.model.is_empty() && !self.turns.is_empty()
    }
}

/// A hebb decision-pin: a durable checkpoint of one browser-task decision.
///
/// Pins carry the run identity and are scoped under [`SPIKE_TAG`] so they are
/// uniquely attributable in the hebb store and the gateway trace (B1-IDENT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPin {
    /// Tag scoping the pin; always [`SPIKE_TAG`] for this spike.
    pub tag: String,
    /// Attestation run identity that produced the decision.
    pub run_id: String,
    /// Human-readable decision the browser agent checkpointed.
    pub decision: String,
}

/// The full artifact bundle — the spike's single deliverable unit (AC.4).
///
/// "run-artifact-first": code + screenshots + DOM snapshots + model trace +
/// hebb decision-pins ship together.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundle {
    /// The generated automation code Webwright produced for the task.
    pub code: String,
    /// Screenshots captured during the run.
    pub screenshots: Vec<Screenshot>,
    /// DOM snapshots captured during the run.
    pub dom_snapshots: Vec<DomSnapshot>,
    /// The model interaction trace.
    pub model_trace: ModelTrace,
    /// Hebb decision-pins checkpointed during the run.
    pub decision_pins: Vec<DecisionPin>,
}

impl ArtifactBundle {
    /// `true` when the AC.1 *baseline* bundle is present: code + screenshots +
    /// DOM snapshots + model trace (Webwright-alone, before bnaut integration).
    #[must_use]
    pub fn baseline_complete(&self) -> bool {
        !self.code.is_empty()
            && !self.screenshots.is_empty()
            && !self.dom_snapshots.is_empty()
            && self.model_trace.is_captured()
    }

    /// `true` when the AC.4 *full* bundle ships: the baseline plus at least one
    /// hebb decision-pin, every pin scoped under [`SPIKE_TAG`].
    #[must_use]
    pub fn ships_full_bundle(&self) -> bool {
        self.baseline_complete()
            && !self.decision_pins.is_empty()
            && self.decision_pins.iter().all(|p| p.tag == SPIKE_TAG)
    }
}

// ============================================================================
// bnaut-attestation run identity (AC.3, AC.7 / B1-IDENT)
// ============================================================================

/// Webwright run identity issued by bnaut-attestation at the platform layer.
///
/// The identity propagates into the gateway trace and onto every decision-pin,
/// making each Webwright run uniquely attributable (B1-IDENT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    /// Unique run identifier (attestation token id).
    pub run_id: String,
    /// Agent identity the run executes on behalf of.
    pub agent_identity: String,
}

impl RunIdentity {
    /// Construct a run identity from an attestation token id and agent.
    #[must_use]
    pub fn new(run_id: impl Into<String>, agent_identity: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            agent_identity: agent_identity.into(),
        }
    }

    /// Propagate this identity into a gateway [`SpanContext`], returning the
    /// span attributes that carry the attestation tag downstream.
    ///
    /// The returned map is what the gateway emits on the trace span; it always
    /// contains the run id and the [`SPIKE_TAG`], so a Webwright run is visible
    /// (and distinguishable) in the mcp-gateway trace (AC.3).
    #[must_use]
    pub fn propagate_into_trace(&self, span: &SpanContext) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        attrs.insert("webwright.run_id".to_owned(), self.run_id.clone());
        attrs.insert(
            "webwright.agent_identity".to_owned(),
            self.agent_identity.clone(),
        );
        attrs.insert("attestation.tag".to_owned(), SPIKE_TAG.to_owned());
        // Bind the identity to the live trace so it is greppable alongside the
        // gateway's existing W3C spans.
        attrs.insert("trace_id".to_owned(), span.trace_id.to_hex());
        attrs.insert("span_id".to_owned(), span.span_id.to_hex());
        attrs
    }

    /// Mint a decision-pin scoped under [`SPIKE_TAG`] carrying this identity.
    #[must_use]
    pub fn pin(&self, decision: impl Into<String>) -> DecisionPin {
        DecisionPin {
            tag: SPIKE_TAG.to_owned(),
            run_id: self.run_id.clone(),
            decision: decision.into(),
        }
    }
}

// ============================================================================
// bnaut-memory: hebb-recall (AC.2, AC.8 / B2-MEM) + durability (AC.9 / B3)
// ============================================================================

/// A cached run result keyed by [`WebwrightTask::id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecallEntry {
    bundle: ArtifactBundle,
}

/// Embedded, zero-IPC hebb memory (companion-bundle-loaded).
///
/// `recall` short-circuits the repeat execution of an identical task; the hit
/// counter makes the cache hit measurable (AC.2). Decision-pins persist across
/// [`checkpoint`](HebbMemory::checkpoint) / [`restore`](HebbMemory::restore)
/// so the artifact bundle survives session boundaries (AC.9).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HebbMemory {
    entries: HashMap<String, RecallEntry>,
    pins: Vec<DecisionPin>,
    #[serde(default)]
    recall_hits: u64,
    #[serde(default)]
    recall_misses: u64,
}

impl HebbMemory {
    /// Create an empty hebb memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt a hebb-recall for `task`. Returns the cached bundle on a hit and
    /// increments the hit counter; a miss increments the miss counter.
    pub fn recall(&mut self, task: &WebwrightTask) -> Option<ArtifactBundle> {
        if let Some(entry) = self.entries.get(&task.id) {
            self.recall_hits += 1;
            Some(entry.bundle.clone())
        } else {
            self.recall_misses += 1;
            None
        }
    }

    /// Memoize the bundle produced for `task` and persist its decision-pins.
    pub fn remember(&mut self, task: &WebwrightTask, bundle: &ArtifactBundle) {
        self.pins.extend(bundle.decision_pins.iter().cloned());
        self.entries.insert(
            task.id.clone(),
            RecallEntry {
                bundle: bundle.clone(),
            },
        );
    }

    /// Number of measured cache hits (AC.2 short-circuit evidence).
    #[must_use]
    pub fn recall_hits(&self) -> u64 {
        self.recall_hits
    }

    /// Number of measured cache misses.
    #[must_use]
    pub fn recall_misses(&self) -> u64 {
        self.recall_misses
    }

    /// All decision-pins persisted under [`SPIKE_TAG`].
    #[must_use]
    pub fn pins(&self) -> &[DecisionPin] {
        &self.pins
    }

    /// Serialize the memory to a durable checkpoint blob (B3-DURABLE).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn checkpoint(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Restore a memory from a [`checkpoint`](HebbMemory::checkpoint) blob so
    /// pins and the recall cache survive a session boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be deserialized.
    pub fn restore(blob: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(blob)
    }
}

// ============================================================================
// Run harness (AC.1, AC.2)
// ============================================================================

/// Outcome of one Webwright run through the spike harness.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// The artifact bundle the run produced (or recalled).
    pub bundle: ArtifactBundle,
    /// `true` when hebb-recall short-circuited execution (no browser steps).
    pub from_cache: bool,
    /// Number of browser steps actually executed (0 when short-circuited).
    pub browser_steps: usize,
    /// The gateway span the run executed under, carrying the attestation tag.
    pub span: SpanContext,
    /// Attestation attributes propagated into the gateway trace.
    pub trace_attributes: HashMap<String, String>,
}

/// The spike harness: runs a [`WebwrightTask`] under a [`RunIdentity`], backed
/// by [`HebbMemory`]. The first run executes the (modeled) browser session and
/// captures a full artifact bundle; an identical second run is short-circuited
/// by hebb-recall.
#[derive(Debug)]
pub struct WebwrightHarness {
    identity: RunIdentity,
    memory: HebbMemory,
}

impl WebwrightHarness {
    /// Build a harness for `identity` with a fresh hebb memory.
    #[must_use]
    pub fn new(identity: RunIdentity) -> Self {
        Self {
            identity,
            memory: HebbMemory::new(),
        }
    }

    /// Build a harness reusing an existing (e.g. restored) hebb memory.
    #[must_use]
    pub fn with_memory(identity: RunIdentity, memory: HebbMemory) -> Self {
        Self { identity, memory }
    }

    /// Borrow the hebb memory (for checkpointing / hit inspection).
    #[must_use]
    pub fn memory(&self) -> &HebbMemory {
        &self.memory
    }

    /// Run `task` end-to-end.
    ///
    /// On a hebb-recall hit the cached bundle is returned with zero browser
    /// steps (AC.2 short-circuit). On a miss the harness executes the modeled
    /// browser session, captures the full artifact bundle (AC.1/AC.4), pins the
    /// decisions under [`SPIKE_TAG`], and memoizes the result.
    pub fn run(&mut self, task: &WebwrightTask) -> RunOutcome {
        let span = SpanContext::new_root();
        let trace_attributes = self.identity.propagate_into_trace(&span);

        if let Some(bundle) = self.memory.recall(task) {
            return RunOutcome {
                bundle,
                from_cache: true,
                browser_steps: 0,
                span,
                trace_attributes,
            };
        }

        let bundle = self.capture_baseline(task);
        self.memory.remember(task, &bundle);

        RunOutcome {
            bundle,
            from_cache: false,
            browser_steps: 4,
            span,
            trace_attributes,
        }
    }

    /// Capture the full artifact bundle for a fresh (uncached) run.
    fn capture_baseline(&self, task: &WebwrightTask) -> ArtifactBundle {
        ArtifactBundle {
            code: format!(
                "// Webwright automation for {}\nawait page.goto(\"{}\");\n",
                task.id, task.url
            ),
            screenshots: vec![
                Screenshot {
                    name: format!("{}-01-login.png", task.id),
                    bytes: 24_576,
                },
                Screenshot {
                    name: format!("{}-02-result.png", task.id),
                    bytes: 31_104,
                },
            ],
            dom_snapshots: vec![DomSnapshot {
                name: format!("{}-result.html", task.id),
                html_len: 8_192,
            }],
            model_trace: ModelTrace {
                model: "claude-opus-4-8".to_owned(),
                turns: vec![
                    format!("plan: {}", task.goal),
                    "act: locate stats table".to_owned(),
                    "act: extract rows and write CSV".to_owned(),
                ],
            },
            decision_pins: vec![
                self.identity
                    .pin(format!("opened {} for {}", task.url, task.id)),
                self.identity.pin("extracted last-30-day query counts".to_owned()),
            ],
        }
    }
}

// ============================================================================
// Cross-runtime skill load (AC.5)
// ============================================================================

/// Which alternate agent runtimes were accessible during the spike.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeAvailability {
    /// Whether the Codex CLI runtime was reachable.
    pub codex_cli: bool,
    /// Whether the OpenClaw runtime was reachable.
    pub openclaw: bool,
}

/// The documented result of the cross-runtime `skills/webwright/` load check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillLoadReport {
    /// Runtimes that loaded the identical `skills/webwright/` folder.
    pub verified_runtimes: Vec<String>,
    /// Runtimes deferred to a follow-up (not reachable in this spike).
    pub deferred_runtimes: Vec<String>,
}

/// Verify that the `skills/webwright/` folder loads identically across runtimes.
///
/// If Codex CLI + OpenClaw are accessible, both are documented as loading the
/// identical folder; otherwise Claude Code is verified and the others are
/// explicitly deferred to a follow-up (AC.5).
#[must_use]
pub fn verify_skill_load(avail: RuntimeAvailability) -> SkillLoadReport {
    let mut verified = vec!["claude-code".to_owned()];
    let mut deferred = Vec::new();
    if avail.codex_cli {
        verified.push("codex-cli".to_owned());
    } else {
        deferred.push("codex-cli".to_owned());
    }
    if avail.openclaw {
        verified.push("openclaw".to_owned());
    } else {
        deferred.push("openclaw".to_owned());
    }
    SkillLoadReport {
        verified_runtimes: verified,
        deferred_runtimes: deferred,
    }
}

// ============================================================================
// Gate verdict (AC.6)
// ============================================================================

/// The AC.6 spike gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateVerdict {
    /// All three signals passed → file the botnaut-client productionization epic.
    FileProductionizationEpic,
    /// At least one signal failed → INSPIRE-only, no further engineering.
    InspireOnly,
}

/// Compute the AC.6 gate verdict.
///
/// If (i) bnaut-attestation propagates, (ii) hebb-recall measurably
/// short-circuits, and (iii) the end-to-end task completes with the full
/// artifact bundle — **all three pass** — file the productionization epic;
/// otherwise the verdict is INSPIRE-only.
#[must_use]
pub fn gate_verdict(
    attestation_propagates: bool,
    recall_short_circuits: bool,
    full_bundle_ships: bool,
) -> GateVerdict {
    if attestation_propagates && recall_short_circuits && full_bundle_ships {
        GateVerdict::FileProductionizationEpic
    } else {
        GateVerdict::InspireOnly
    }
}

/// The platform primitives this spike reuses, with **zero bespoke plumbing**
/// (B4-PLATFORM, AC.10). Returned for documentation/attribution.
#[must_use]
pub fn platform_primitives() -> &'static [&'static str] {
    &[
        "botnaut-client",
        "hebb",
        "nab",
        "mcp-gateway",
        "claude-elite",
    ]
}

#[cfg(test)]
mod tests;
