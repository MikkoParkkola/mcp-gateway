// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 C2e (option (a), lead ruling 2026-10-11): intake judges a
//! playbook's sanitize exemption on one definition, and the run refuses a
//! different one. Green on the tip, where every playbook run is sanitized;
//! the mutant that skips the comparison in `run_playbook` turns C2e1 red.

use super::*;

/// The refusal `run_playbook` answers when the definition changed.
const CHANGED: &str = "The playbook changed after this call was admitted; retry the call";

/// C2e1: an unkeyed sync run judged exempt (both steps passthrough) whose
/// playbook is reloaded after intake with a step on a non-passthrough backend
/// is refused, and no step runs: the NUL intake let through never reaches a
/// backend that was not judged.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn c2e1_a_sync_run_reloaded_after_intake_is_refused() {
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
    let meta = std::sync::Arc::clone(&fx.state.meta_mcp);
    crate::gateway::meta_mcp::visible::seams::after_route_stage(move || {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(playbook_definition(["alpha-pt", "alpha"]));
        meta.set_playbook_engine(engine);
    });
    let body = run_with_nul(&fx).await;
    assert!(message(&body).contains(CHANGED), "c2e1: {body}");
    assert_eq!(calls(&fx), 0, "c2e1: a step ran");
}

/// C2e4 CONTROL: the same run with no reload runs, and its NUL reaches the
/// passthrough backend.
#[tokio::test]
async fn c2e4_a_sync_run_with_no_reload_runs() {
    let fx = playbook_fixture(["alpha-pt", "alpha-pt"]).await;
    let body = run_with_nul(&fx).await;
    assert!(body.get("error").is_none(), "c2e4: {body}");
    assert!(
        forwarded_nul(&fx),
        "c2e4: the NUL did not reach the backend"
    );
}
