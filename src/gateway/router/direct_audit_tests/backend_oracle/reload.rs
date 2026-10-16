// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 rows where `ghost` flips inside one request (§2a axis T2): the
//! registry is live, so a reload may register or remove it between the route
//! stage (S1), the whole-call gate (S2) and the per-target gate (S3). One
//! judgement per request must hold, and nothing absent may dispatch.

use super::cells::scripted;
use super::*;
use crate::gateway::meta_mcp::withheld_gate::seams;

/// Register `ghost` in `fx`'s registry, counting its calls apart from the
/// fixture's `alpha`/`beta` counter.
fn register_ghost(fx: &Fixture) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let ghost = scripted(GHOST, BackendConfig::default(), &calls);
    assert!(
        fx.state.backends.register(ghost),
        "premise: ghost was not registered"
    );
    calls
}

/// G1 (d4, GPT F2): an all-absent invoke of `ghost:t`. At the `gate_done()`
/// seam `ghost` is registered with a backend that would answer. Only S1's
/// record still says absent, so S3 must read it: the call answers the pinned
/// miss and `ghost` sees no request.
#[tokio::test]
async fn g1_a_name_registered_after_the_gate_is_never_dispatched() {
    let fx = scoped_fixture(MetaMode::Plain).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, counted) = (Arc::clone(&fx.state), Arc::clone(&calls));
    seams::after_gate(move || {
        let ghost = scripted(GHOST, BackendConfig::default(), &counted);
        assert!(
            state.backends.register(ghost),
            "premise: ghost registers at the seam"
        );
    });
    let answered = answer(&fx, Route::Invoke, GHOST).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "G1: ghost was dispatched: {answered:?}"
    );
    assert_eq!(Some(answered), pinned(Route::Invoke), "G1");
}

/// G1k (d5, §2a cell 3): as G1, and the seam also kill-switches `ghost`;
/// `beta` is kill-switched before the call. The kill-switch `find_map`
/// (dispatch_tools_call.rs:461) must skip every absent target, so no cell
/// answers the kill switch's 400.
#[tokio::test]
async fn g1k_a_kill_switch_at_the_seam_gives_no_cell_its_400() {
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(MetaMode::Plain).await;
        fx.state.meta_mcp.kill_switch().kill(WITHHELD);
        let calls = Arc::new(AtomicUsize::new(0));
        if name == GHOST {
            let (state, counted) = (Arc::clone(&fx.state), Arc::clone(&calls));
            seams::after_gate(move || {
                let ghost = scripted(GHOST, BackendConfig::default(), &counted);
                assert!(state.backends.register(ghost), "premise: ghost registers");
                state.meta_mcp.kill_switch().kill(GHOST);
            });
        }
        answers.push((name, answer(&fx, Route::Invoke, name).await));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "G1k: ghost was dispatched");
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "G1k: `{name}` was dispatched"
        );
    }
    assert_cells_equal("G1k", &answers);
    assert_eq!(Some(answers[0].1.clone()), pinned(Route::Invoke), "G1k");
}

/// G0 (lead addendum to d5, CRITICAL fail-open): `ghost` is registered when
/// the request starts, so S1 sees it present and records nothing. It is
/// removed before S2 (the `gate_start()` seam) and restored before S3 (the
/// `gate_done()` seam). S2's live absence lets the call take the early path,
/// which skips signing preparation and admission, so that absence must be
/// recorded for the rest of the request: nothing may reach `ghost`.
#[tokio::test]
async fn g0_a_name_removed_before_s2_and_restored_before_s3_is_never_dispatched() {
    let fx = scoped_fixture(MetaMode::Plain).await;
    let calls = register_ghost(&fx);
    let ghost = fx.state.backends.get(GHOST).expect("ghost");
    let state = Arc::clone(&fx.state);
    seams::before_gate(move || {
        assert!(
            state.backends.remove(GHOST),
            "premise: ghost is removed before S2"
        );
    });
    let state = Arc::clone(&fx.state);
    seams::after_gate(move || {
        assert!(
            state.backends.register(ghost),
            "premise: ghost is restored before S3"
        );
    });
    let answered = answer(&fx, Route::Invoke, GHOST).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "G0: ghost was dispatched after S2 judged it absent: {answered:?}"
    );
}
