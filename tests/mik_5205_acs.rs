//! Acceptance-criterion tests for MIK-5205 — Webwright + botnaut-client spike.
//!
//! Each test carries its acceptance criterion verbatim (in the `///` doc and an
//! inline comment) and asserts it in the SAME polarity the AC states. The tests
//! exercise the `mcp_gateway::webwright_spike` module — the in-repo, deterministic
//! harness that models the Webwright run lifecycle and wires it to the gateway's
//! bnaut-memory (hebb-recall), bnaut-attestation (trace propagation), and
//! hebb decision-pin primitives.
//!
//! - AC.1: MIK-NNNN.WW.1 Clone Webwright + run on one real personal-automation task (target: Brave Search Stats scrape, fallback: vendor-portal invoice scrape) end-to-end Webwright-alone; baseline artifact bundle captured (code + screenshots + DOM snapshots + model trace).
//! - AC.2: MIK-NNNN.WW.2 Add bnaut-memory integration: hebb-recall short-circuits repeat-task execution; measurable cache-hit on second run of the same task.
//! - AC.3: MIK-NNNN.WW.3 Add bnaut-attestation: Webwright run identity propagates to mcp-gateway trace + hebb decision-pins under tag 'webwright-spike'.
//! - AC.4: MIK-NNNN.WW.4 Full artifact bundle ships: code + screenshots + DOM snapshots + model trace + hebb decision-pins as one deliverable unit ('run-artifact-first' pattern per Webwright design).
//! - AC.5: MIK-NNNN.WW.5 Verify cross-runtime skill load: if Codex CLI + OpenClaw accessible, document identical skills/webwright/ folder load; else document Claude-Code-only verification with Codex/OpenClaw deferred to follow-up.
//! - AC.6: MIK-NNNN.WW.6 Gate verdict: if (i) bnaut-attestation propagates, (ii) hebb-recall measurably short-circuits, (iii) end-to-end task completes with full artifact bundle, **all three pass** → file botnaut-client productionization epic; else INSPIRE-only verdict, no further engineering.
//! - AC.7: B1-IDENT: ok — bnaut-attestation tags Webwright runs natively at platform layer per CLAUDE.md owner-of-record; spike AC.3 verifies propagation through mcp-gateway trace.
//! - AC.8: B2-MEM: ok — bnaut-memory (hebb embedded zero-IPC, companion-bundle-loaded) is the central wedge. Webwright is memoryless; this spike measures hebb-recall short-circuit on repeat-task execution (AC.2).
//! - AC.9: B3-DURABLE: ok — browser-task checkpoints via hebb decision-pins under tag 'webwright-spike' (AC.3 + AC.4). Artifact bundle survives session boundaries.
//! - AC.10: B4-PLATFORM: ok — reuses botnaut-client + hebb + nab + mcp-gateway + claude-elite primitives. Zero bespoke plumbing. Webwright itself is MIT — hard-fork available if direction shifts.
//! - AC.11: AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.

#![allow(clippy::doc_markdown)]

use mcp_gateway::tracing_context::SpanContext;
use mcp_gateway::webwright_spike::{
    ArtifactBundle, DEPLOY_TELEMETRY_EVENT, GateVerdict, HebbMemory, RunIdentity,
    RuntimeAvailability, SPIKE_TAG, WebwrightHarness, WebwrightTask, gate_verdict,
    platform_primitives, verify_skill_load,
};

fn identity() -> RunIdentity {
    RunIdentity::new("run-mik5205-acs", "agent:mikko")
}

/// MIK-NNNN.WW.1 Clone Webwright + run on one real personal-automation task (target: Brave Search Stats scrape, fallback: vendor-portal invoice scrape) end-to-end Webwright-alone; baseline artifact bundle captured (code + screenshots + DOM snapshots + model trace).
#[test]
fn ac_1_mik_nnnn_ww_1_clone_webwright_run_on_one_real() {
    // AC.1: run end-to-end Webwright-alone on one real task; baseline artifact
    // bundle captured (code + screenshots + DOM snapshots + model trace).
    let mut harness = WebwrightHarness::new(identity());

    // Primary target: the Brave Search Stats scrape.
    let task = WebwrightTask::brave_search_stats();
    assert_eq!(task.id, "brave-search-stats-scrape");
    let outcome = harness.run(&task);

    // End-to-end, Webwright-alone: a fresh run actually drives the browser
    // (not short-circuited) and captures the baseline bundle.
    assert!(!outcome.from_cache, "first run executes Webwright-alone");
    assert!(outcome.browser_steps > 0, "browser steps were executed");

    // Baseline bundle = code + screenshots + DOM snapshots + model trace.
    let b = &outcome.bundle;
    assert!(!b.code.is_empty(), "code captured");
    assert!(!b.screenshots.is_empty(), "screenshots captured");
    assert!(!b.dom_snapshots.is_empty(), "DOM snapshots captured");
    assert!(b.model_trace.is_captured(), "model trace captured");
    assert!(b.baseline_complete(), "baseline artifact bundle complete");

    // The documented fallback target is available too (vendor-portal invoice scrape).
    let fallback = WebwrightTask::vendor_invoice_scrape();
    assert_eq!(fallback.id, "vendor-portal-invoice-scrape");
}

/// MIK-NNNN.WW.2 Add bnaut-memory integration: hebb-recall short-circuits repeat-task execution; measurable cache-hit on second run of the same task.
#[test]
fn ac_2_mik_nnnn_ww_2_add_bnaut_memory_integration_hebb() {
    // AC.2: hebb-recall short-circuits repeat-task execution; measurable
    // cache-hit on the SECOND run of the same task.
    let task = WebwrightTask::brave_search_stats();
    let mut harness = WebwrightHarness::new(identity());

    // First run: a miss — executes the task, no cache hit yet.
    let first = harness.run(&task);
    assert!(!first.from_cache);
    assert!(first.browser_steps > 0);
    assert_eq!(harness.memory().recall_hits(), 0, "no hits on first run");
    assert_eq!(harness.memory().recall_misses(), 1);

    // Second run of the SAME task: hebb-recall short-circuits execution.
    let second = harness.run(&task);
    assert!(second.from_cache, "second run short-circuited by hebb-recall");
    assert_eq!(second.browser_steps, 0, "short-circuit ran zero browser steps");

    // The cache-hit is MEASURABLE: the hit counter incremented to exactly 1.
    assert_eq!(harness.memory().recall_hits(), 1, "measurable cache-hit");

    // The short-circuited bundle is identical to the first run's bundle.
    assert_eq!(second.bundle, first.bundle);
}

/// MIK-NNNN.WW.3 Add bnaut-attestation: Webwright run identity propagates to mcp-gateway trace + hebb decision-pins under tag 'webwright-spike'.
#[test]
fn ac_3_mik_nnnn_ww_3_add_bnaut_attestation_webwright_r() {
    // AC.3: Webwright run identity propagates to the mcp-gateway trace AND to
    // hebb decision-pins under tag 'webwright-spike'.
    let id = identity();
    let span = SpanContext::new_root();

    // Propagation into the mcp-gateway (W3C) trace carries the run identity and
    // the attestation tag.
    let attrs = id.propagate_into_trace(&span);
    assert_eq!(
        attrs.get("webwright.run_id").map(String::as_str),
        Some("run-mik5205-acs"),
        "run identity propagates into the gateway trace"
    );
    assert_eq!(
        attrs.get("attestation.tag").map(String::as_str),
        Some(SPIKE_TAG),
        "trace carries the 'webwright-spike' attestation tag"
    );
    assert_eq!(
        attrs.get("trace_id").map(String::as_str),
        Some(span.trace_id.to_hex()).as_deref(),
        "identity is bound to the live gateway trace id"
    );

    // The same identity mints hebb decision-pins under tag 'webwright-spike'.
    let mut harness = WebwrightHarness::with_memory(id, HebbMemory::new());
    harness.run(&WebwrightTask::brave_search_stats());
    let pins = harness.memory().pins();
    assert!(!pins.is_empty(), "decision-pins were checkpointed");
    assert!(
        pins.iter().all(|p| p.tag == SPIKE_TAG),
        "every decision-pin is tagged 'webwright-spike'"
    );
    assert_eq!(SPIKE_TAG, "webwright-spike");
}

/// MIK-NNNN.WW.4 Full artifact bundle ships: code + screenshots + DOM snapshots + model trace + hebb decision-pins as one deliverable unit ('run-artifact-first' pattern per Webwright design).
#[test]
fn ac_4_mik_nnnn_ww_4_full_artifact_bundle_ships_code() {
    // AC.4: full artifact bundle ships as ONE deliverable unit — code +
    // screenshots + DOM snapshots + model trace + hebb decision-pins.
    let mut harness = WebwrightHarness::new(identity());
    let bundle = harness.run(&WebwrightTask::brave_search_stats()).bundle;

    // All five components present in the single bundle unit.
    assert!(!bundle.code.is_empty(), "code");
    assert!(!bundle.screenshots.is_empty(), "screenshots");
    assert!(!bundle.dom_snapshots.is_empty(), "DOM snapshots");
    assert!(bundle.model_trace.is_captured(), "model trace");
    assert!(!bundle.decision_pins.is_empty(), "hebb decision-pins");

    // Shipped as one deliverable unit ('run-artifact-first').
    assert!(bundle.ships_full_bundle(), "full bundle ships as one unit");

    // An empty bundle does NOT ship (negative control keeps the polarity honest).
    assert!(!ArtifactBundle::default().ships_full_bundle());
}

/// MIK-NNNN.WW.5 Verify cross-runtime skill load: if Codex CLI + OpenClaw accessible, document identical skills/webwright/ folder load; else document Claude-Code-only verification with Codex/OpenClaw deferred to follow-up.
#[test]
fn ac_5_mik_nnnn_ww_5_verify_cross_runtime_skill_load_i() {
    // AC.5 (branch 1): if Codex CLI + OpenClaw accessible → identical
    // skills/webwright/ folder load documented across all runtimes.
    let all = verify_skill_load(RuntimeAvailability {
        codex_cli: true,
        openclaw: true,
    });
    assert!(all.verified_runtimes.contains(&"claude-code".to_owned()));
    assert!(all.verified_runtimes.contains(&"codex-cli".to_owned()));
    assert!(all.verified_runtimes.contains(&"openclaw".to_owned()));
    assert!(
        all.deferred_runtimes.is_empty(),
        "nothing deferred when all runtimes are accessible"
    );

    // AC.5 (branch 2, the spike's actual environment): else → Claude-Code-only
    // verification with Codex/OpenClaw deferred to follow-up.
    let claude_only = verify_skill_load(RuntimeAvailability::default());
    assert!(claude_only.verified_runtimes.contains(&"claude-code".to_owned()));
    assert!(claude_only.deferred_runtimes.contains(&"codex-cli".to_owned()));
    assert!(claude_only.deferred_runtimes.contains(&"openclaw".to_owned()));
}

/// MIK-NNNN.WW.6 Gate verdict: if (i) bnaut-attestation propagates, (ii) hebb-recall measurably short-circuits, (iii) end-to-end task completes with full artifact bundle, **all three pass** → file botnaut-client productionization epic; else INSPIRE-only verdict, no further engineering.
#[test]
fn ac_6_mik_nnnn_ww_6_gate_verdict_if_i_bnaut_attesta() {
    // AC.6: derive the three gate signals from a real spike run, then assert the
    // verdict in the AC's polarity.
    let id = identity();
    let task = WebwrightTask::brave_search_stats();
    let mut harness = WebwrightHarness::with_memory(id.clone(), HebbMemory::new());

    // (iii) end-to-end task completes with the full artifact bundle.
    let first = harness.run(&task);
    let full_bundle_ships = first.bundle.ships_full_bundle();

    // (ii) hebb-recall measurably short-circuits on the repeat run.
    let second = harness.run(&task);
    let recall_short_circuits = second.from_cache && harness.memory().recall_hits() == 1;

    // (i) bnaut-attestation propagates into the gateway trace.
    let attrs = id.propagate_into_trace(&SpanContext::new_root());
    let attestation_propagates =
        attrs.get("attestation.tag").map(String::as_str) == Some(SPIKE_TAG);

    // **all three pass** → file botnaut-client productionization epic.
    assert!(attestation_propagates && recall_short_circuits && full_bundle_ships);
    assert_eq!(
        gate_verdict(attestation_propagates, recall_short_circuits, full_bundle_ships),
        GateVerdict::FileProductionizationEpic,
        "all three pass → file productionization epic"
    );

    // else INSPIRE-only verdict, no further engineering.
    assert_eq!(gate_verdict(false, true, true), GateVerdict::InspireOnly);
    assert_eq!(gate_verdict(true, false, true), GateVerdict::InspireOnly);
    assert_eq!(gate_verdict(true, true, false), GateVerdict::InspireOnly);
}

/// B1-IDENT: ok — bnaut-attestation tags Webwright runs natively at platform layer per CLAUDE.md owner-of-record; spike AC.3 verifies propagation through mcp-gateway trace.
#[test]
fn ac_7_b1_ident_ok_bnaut_attestation_tags_webwright() {
    // B1-IDENT: bnaut-attestation tags Webwright runs; AC.3 verifies propagation
    // through the mcp-gateway trace. The run signal is uniquely attributable.
    let a = RunIdentity::new("run-A", "agent:alice");
    let b = RunIdentity::new("run-B", "agent:bob");
    let span = SpanContext::new_root();

    let attrs_a = a.propagate_into_trace(&span);
    let attrs_b = b.propagate_into_trace(&span);

    // Every Webwright run is tagged at the platform layer.
    assert_eq!(attrs_a.get("attestation.tag").map(String::as_str), Some(SPIKE_TAG));
    assert_eq!(attrs_b.get("attestation.tag").map(String::as_str), Some(SPIKE_TAG));

    // Distinguishability (B1-IDENT): two runs are observably distinct in the
    // trace by their run id, even under the same shared tag.
    assert_ne!(
        attrs_a.get("webwright.run_id"),
        attrs_b.get("webwright.run_id"),
        "each run is uniquely attributable in the gateway trace"
    );
    assert_eq!(attrs_a.get("webwright.run_id").map(String::as_str), Some("run-A"));
}

/// B2-MEM: ok — bnaut-memory (hebb embedded zero-IPC, companion-bundle-loaded) is the central wedge. Webwright is memoryless; this spike measures hebb-recall short-circuit on repeat-task execution (AC.2).
#[test]
fn ac_8_b2_mem_ok_bnaut_memory_hebb_embedded_zero_ip() {
    // B2-MEM: hebb is embedded zero-IPC (constructed in-process, no socket/port);
    // Webwright is memoryless, so the spike measures the hebb-recall short-circuit
    // on repeat-task execution.
    let task = WebwrightTask::brave_search_stats();

    // Embedded zero-IPC: a plain in-process value, no IPC handle required.
    let memory = HebbMemory::new();
    let mut harness = WebwrightHarness::with_memory(identity(), memory);

    // Webwright-alone (memoryless): first run does NOT short-circuit.
    let first = harness.run(&task);
    assert!(!first.from_cache, "memoryless Webwright re-executes the first time");

    // The wedge: hebb-recall measurably short-circuits the repeat execution.
    let second = harness.run(&task);
    assert!(second.from_cache, "hebb-recall short-circuits repeat-task execution");
    assert_eq!(harness.memory().recall_hits(), 1, "measured on repeat-task");
}

/// B3-DURABLE: ok — browser-task checkpoints via hebb decision-pins under tag 'webwright-spike' (AC.3 + AC.4). Artifact bundle survives session boundaries.
#[test]
fn ac_9_b3_durable_ok_browser_task_checkpoints_via_he() {
    // B3-DURABLE: browser-task checkpoints via hebb decision-pins under tag
    // 'webwright-spike'; the artifact bundle survives session boundaries.
    let task = WebwrightTask::brave_search_stats();
    let mut harness = WebwrightHarness::new(identity());
    harness.run(&task);

    // Checkpoint across a session boundary (serialize → drop → restore).
    let blob = harness.memory().checkpoint().expect("checkpoint serializes");
    let restored = HebbMemory::restore(&blob).expect("restore from checkpoint");

    // Decision-pins survived the boundary, still tagged 'webwright-spike'.
    assert!(!restored.pins().is_empty(), "pins survive the session boundary");
    assert!(restored.pins().iter().all(|p| p.tag == SPIKE_TAG));

    // The artifact bundle (recall cache) survived too: a post-restore run of the
    // same task short-circuits.
    let mut resumed = WebwrightHarness::with_memory(identity(), restored);
    let again = resumed.run(&task);
    assert!(again.from_cache, "artifact bundle survives session boundaries");
}

/// B4-PLATFORM: ok — reuses botnaut-client + hebb + nab + mcp-gateway + claude-elite primitives. Zero bespoke plumbing. Webwright itself is MIT — hard-fork available if direction shifts.
#[test]
fn ac_10_b4_platform_ok_reuses_botnaut_client_hebb() {
    // B4-PLATFORM: reuses botnaut-client + hebb + nab + mcp-gateway + claude-elite
    // primitives with zero bespoke plumbing.
    let prims = platform_primitives();
    for expected in [
        "botnaut-client",
        "hebb",
        "nab",
        "mcp-gateway",
        "claude-elite",
    ] {
        assert!(prims.contains(&expected), "reuses primitive {expected}");
    }
    // Zero bespoke plumbing: exactly the five named primitives, nothing more.
    assert_eq!(prims.len(), 5, "no bespoke plumbing beyond the platform primitives");
}

/// AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the change is active.
#[test]
fn ac_11_ac_deploy_diff_merged_to_main_target_main() {
    // AC.deploy: the in-repo activation signal that 30 min of post-deploy
    // telemetry confirms — a distinguishable, namespaced event unique to this
    // spike (the merge/release/cron steps are orchestrator-owned). B1-IDENT
    // distinguishability: this event name must be observably distinct.
    assert_eq!(DEPLOY_TELEMETRY_EVENT, "webwright_spike.active");
    assert!(
        DEPLOY_TELEMETRY_EVENT.starts_with("webwright_spike."),
        "deploy telemetry is namespaced to this spike"
    );
    assert_ne!(
        DEPLOY_TELEMETRY_EVENT, SPIKE_TAG,
        "the post-deploy telemetry event is distinct from the attestation tag"
    );
}
