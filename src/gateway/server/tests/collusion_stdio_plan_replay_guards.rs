// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4 stdio guard: G25's S leg. The rig is
//! `collusion_stdio_plan_replay`'s, reused.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use super::collusion_stdio_plan_replay::{
    Alpha, OTHER_PROSE, PROSE, WINDOW_SECS, dispatch, keyed_request, relayed_by_bob,
};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// The replay-skipped counter's `reason` count, as the unit rows read it.
#[cfg(feature = "metrics")]
fn skipped_count(reason: &str) -> u64 {
    crate::metrics::install();
    crate::metrics::render()
        .lines()
        .find(|l| {
            l.starts_with("mcp_gateway_collusion_plan_replay_skipped_total")
                && l.contains(&format!("reason=\"{reason}\""))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
}

/// G25 (S): a keyed stdio plan delivered with relay detection off,
/// then the firewall swapped on over the same retained answers
/// (the same `ExecutionAdmission`, as R9s swaps it). The repeat
/// serves the retained answer and renews nothing, counted
/// `reason=absent`; a live delivery on the new gateway then
/// receipts as usual (control).
/// Mutant killed: open the provenance scope only when relay is
/// active (a rebuild at replay would receipt the stored answer:
/// bob would be refused).
#[tokio::test]
async fn g25_a_detection_off_stdio_plan_renews_nothing_once_detection_is_on() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Alpha(Arc::clone(&calls))));
    assert!(registry.register(backend), "premise: the backend registers");
    let off = Arc::new(MetaMcp::new(Arc::clone(&registry)));
    let chain = json!({"chain": [{"tool": "alpha:a", "arguments": {}},
                                 {"tool": "alpha:b", "arguments": {}}]});
    let first = dispatch(&off, &keyed_request(1, "gateway_execute", &chain)).await;
    assert!(
        first.get("error").is_none(),
        "base: delivered with detection off: {first}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise: both steps dispatched"
    );

    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: serde_yaml::from_str("[{match: \"*\", action: allow}]")
                    .expect("the fixture rules parse: fixture"),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec!["alpha:*".to_string()],
                    window_secs: WINDOW_SECS,
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test()
        .keeping_every_kgram(),
    );
    firewall.advance_collusion_clock_for_test(Duration::ZERO);
    let mut on = MetaMcp::new(registry);
    on.share_execution_admission_for_test(Arc::clone(off.execution_admission()));
    on.set_firewall(Some(Arc::clone(&firewall)));
    on.share_keyring_with_for_test(&firewall);
    let on = Arc::new(on);
    #[cfg(feature = "metrics")]
    let absent_before = skipped_count("absent");
    let replay = dispatch(&on, &keyed_request(2, "gateway_execute", &chain)).await;
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_eq!(
        replay["result"], first["result"],
        "premise: retained answer replayed unchanged"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "P2: the replay dispatched nothing"
    );
    for text in [PROSE, OTHER_PROSE] {
        assert!(
            !relayed_by_bob(&firewall, text),
            "the replay renewed a detection-off plan for {text:.40}"
        );
    }
    #[cfg(feature = "metrics")]
    assert!(
        skipped_count("absent") > absent_before,
        "not counted reason=absent"
    );
    let live_args = json!({"server": "alpha", "tool": "a", "arguments": {}});
    // A fresh key: `keyed_request`'s key already holds the chain
    // call, and reusing it for this different request is a 409.
    let mut live_call = keyed_request(3, "gateway_invoke", &live_args);
    live_call["params"]["_meta"]["io.mcp-gateway/idempotency-key"] = json!("stdio-g25-live");
    let live = dispatch(&on, &live_call).await;
    assert!(
        live.get("error").is_none(),
        "control premise: live delivery succeeds: {live}"
    );
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "control: detection on receipts its own deliveries"
    );
}
