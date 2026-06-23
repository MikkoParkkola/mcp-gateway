//! Unit tests for the Webwright + botnaut-client spike harness (MIK-5205).

use super::*;

fn identity() -> RunIdentity {
    RunIdentity::new("run-abc123", "agent:mikko")
}

#[test]
fn baseline_run_captures_full_artifact_bundle() {
    // AC.1: baseline artifact bundle = code + screenshots + DOM snapshots + model trace.
    let mut h = WebwrightHarness::new(identity());
    let outcome = h.run(&WebwrightTask::brave_search_stats());
    assert!(!outcome.from_cache);
    assert!(outcome.browser_steps > 0);
    assert!(outcome.bundle.baseline_complete());
}

#[test]
fn second_run_short_circuits_via_hebb_recall() {
    // AC.2 / AC.8: hebb-recall short-circuits the repeat run; measurable hit.
    let task = WebwrightTask::brave_search_stats();
    let mut h = WebwrightHarness::new(identity());

    let first = h.run(&task);
    assert!(!first.from_cache);
    assert_eq!(h.memory().recall_hits(), 0);
    assert_eq!(h.memory().recall_misses(), 1);

    let second = h.run(&task);
    assert!(second.from_cache);
    assert_eq!(second.browser_steps, 0);
    assert_eq!(h.memory().recall_hits(), 1);
}

#[test]
fn run_identity_propagates_into_gateway_trace() {
    // AC.3 / AC.7: run identity propagates to the mcp-gateway trace under the tag.
    let span = SpanContext::new_root();
    let attrs = identity().propagate_into_trace(&span);
    assert_eq!(attrs.get("webwright.run_id").map(String::as_str), Some("run-abc123"));
    assert_eq!(attrs.get("attestation.tag").map(String::as_str), Some(SPIKE_TAG));
    assert_eq!(attrs.get("trace_id").map(String::as_str), Some(span.trace_id.to_hex()).as_deref());
}

#[test]
fn decision_pins_carry_spike_tag() {
    // AC.3: hebb decision-pins under tag 'webwright-spike'.
    let pin = identity().pin("checkpoint");
    assert_eq!(pin.tag, SPIKE_TAG);
    assert_eq!(pin.run_id, "run-abc123");
}

#[test]
fn full_bundle_ships_all_five_components() {
    // AC.4: code + screenshots + DOM + model trace + decision-pins as one unit.
    let mut h = WebwrightHarness::new(identity());
    let outcome = h.run(&WebwrightTask::brave_search_stats());
    assert!(outcome.bundle.ships_full_bundle());
    assert!(!outcome.bundle.decision_pins.is_empty());
    assert!(outcome.bundle.decision_pins.iter().all(|p| p.tag == SPIKE_TAG));
}

#[test]
fn pins_survive_checkpoint_restore() {
    // AC.9 / B3-DURABLE: artifact bundle survives session boundaries.
    let task = WebwrightTask::brave_search_stats();
    let mut h = WebwrightHarness::new(identity());
    h.run(&task);
    let blob = h.memory().checkpoint().unwrap();

    let restored = HebbMemory::restore(&blob).unwrap();
    assert!(!restored.pins().is_empty());
    assert!(restored.pins().iter().all(|p| p.tag == SPIKE_TAG));

    // Recall still hits after restore — the cache survived too.
    let mut h2 = WebwrightHarness::with_memory(identity(), restored);
    let again = h2.run(&task);
    assert!(again.from_cache);
}

#[test]
fn skill_load_defers_unavailable_runtimes() {
    // AC.5: Claude-Code verified, Codex/OpenClaw deferred when not accessible.
    let report = verify_skill_load(RuntimeAvailability::default());
    assert!(report.verified_runtimes.contains(&"claude-code".to_owned()));
    assert!(report.deferred_runtimes.contains(&"codex-cli".to_owned()));
    assert!(report.deferred_runtimes.contains(&"openclaw".to_owned()));
}

#[test]
fn skill_load_verifies_all_when_runtimes_present() {
    // AC.5: identical skills/webwright/ folder load across all runtimes.
    let report = verify_skill_load(RuntimeAvailability {
        codex_cli: true,
        openclaw: true,
    });
    assert!(report.verified_runtimes.contains(&"codex-cli".to_owned()));
    assert!(report.verified_runtimes.contains(&"openclaw".to_owned()));
    assert!(report.deferred_runtimes.is_empty());
}

#[test]
fn gate_files_epic_when_all_three_pass() {
    // AC.6: all three pass → file botnaut-client productionization epic.
    assert_eq!(
        gate_verdict(true, true, true),
        GateVerdict::FileProductionizationEpic
    );
}

#[test]
fn gate_inspire_only_when_any_signal_fails() {
    // AC.6: else INSPIRE-only verdict, no further engineering.
    assert_eq!(gate_verdict(false, true, true), GateVerdict::InspireOnly);
    assert_eq!(gate_verdict(true, false, true), GateVerdict::InspireOnly);
    assert_eq!(gate_verdict(true, true, false), GateVerdict::InspireOnly);
}

#[test]
fn platform_primitives_are_reused_zero_bespoke() {
    // AC.10 / B4-PLATFORM: reuses botnaut-client + hebb + nab + mcp-gateway + claude-elite.
    let prims = platform_primitives();
    for expected in ["botnaut-client", "hebb", "nab", "mcp-gateway", "claude-elite"] {
        assert!(prims.contains(&expected), "missing primitive {expected}");
    }
}
