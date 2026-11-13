// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T1) on the direct route: a reload between a call's
//! admission and its relay check changes nothing for that call. The witness
//! judges under the generation the request pinned at admission, never one
//! read again later.
//!
//! The hook runs on each route before the first generation read in its
//! handler (`hook_order` pins that). Each row asserts the hook ran and that its reload was
//! the only publish since admission, so the reload is visible only to a read
//! made after the hook.

use std::cell::Cell;
use std::rc::Rc;

use super::catalogue::{Route, prompt_with, read_resource};
use super::catalogue::{assert_catalogue_refused_as, assert_catalogue_sent_as};
use super::meta::meta_fixture;
use super::*;
use crate::security::firewall::relay_witness_hook;

/// Publish the live config with only the collusion action edited.
fn publish(state: &super::super::AppState, action: CollusionAction) {
    let mut config = (*state.live_config.get()).clone();
    config.security.firewall.collusion.action = action;
    state.live_config.set(config);
}

/// The publish count either side of the hook's reload.
#[derive(Default)]
struct Seen {
    /// Visits to the seam before the hook was armed (alice's read passed it).
    visits: Cell<u32>,
    before: Cell<u64>,
    after: Cell<u64>,
}

/// Arm the witness hook to publish `action`, noting the publish count either
/// side of it.
fn arm_reload(fx: &Fixture, action: CollusionAction) -> Rc<Seen> {
    let seen = Rc::new(Seen::default());
    seen.visits.set(relay_witness_hook::reached());
    let (state, probe) = (Arc::clone(&fx.state), Rc::clone(&seen));
    relay_witness_hook::arm(move || {
        probe.before.set(state.live_config.seq());
        publish(&state, action);
        probe.after.set(state.live_config.seq());
    });
    seen
}

/// The hook ran, and nothing was published between admission (`admitted`
/// publishes) and the hook, which published exactly once.
fn assert_ordered(seen: &Seen, admitted: u64) {
    assert!(
        relay_witness_hook::reached() > seen.visits.get(),
        "the witness hook never ran"
    );
    assert_eq!(seen.before.get(), admitted, "a reload preceded the hook");
    assert_eq!(
        seen.after.get(),
        admitted + 1,
        "the hook's reload did not publish"
    );
}

/// Alice is delivered the sensitive read under `block`.
async fn alice_read() -> Fixture {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    fx
}

/// T1a: admitted under `block`, `off` published before the check: the call is
/// still refused. GREEN on base (the startup action is `block`).
#[tokio::test]
async fn t1a_admitted_under_block_a_later_off_still_refuses() {
    let fx = alice_read().await;
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Off);
    let relay = call("send", &json!({"text": PROSE}), None, None);
    assert_refused_as("T1a: ", &fx, &fx.call(Some("b"), &relay).await, 0);
    assert_ordered(&seen, admitted);
}

/// T1b: admitted under `off`, `block` published before the check: the call
/// is still sent. RED on base: the startup action is `block`, so it is
/// refused.
#[tokio::test]
async fn t1b_admitted_under_off_a_later_block_still_sends() {
    let fx = alice_read().await;
    publish(&fx.state, CollusionAction::Off);
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Block);
    let relay = call("send", &json!({"text": PROSE}), None, None);
    assert_sent_as("T1b: ", &fx, &fx.call(Some("b"), &relay).await, 1);
    assert_ordered(&seen, admitted);
}

fn catalogue_setup() -> Setup {
    Setup {
        sources: vec!["alpha:*".to_string()],
        ..Setup::default()
    }
}

/// T1c: as T1a on a `prompts/get` carrying the read text. GREEN on base.
#[tokio::test]
async fn t1c_catalogue_admitted_under_block_a_later_off_still_refuses() {
    let fx = fixture(catalogue_setup()).await;
    read_resource(&fx, Route::Direct, "a").await;
    let forwarded = fx.catalogue();
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Off);
    let answer = prompt_with(&fx, Route::Direct, "b", PROSE).await;
    assert_catalogue_refused_as("T1c: ", &fx, &answer, forwarded);
    assert_ordered(&seen, admitted);
}

/// T1d: as T1b on a `prompts/get`. RED on base: refused under the startup
/// `block`.
#[tokio::test]
async fn t1d_catalogue_admitted_under_off_a_later_block_still_sends() {
    let fx = fixture(catalogue_setup()).await;
    read_resource(&fx, Route::Direct, "a").await;
    let forwarded = fx.catalogue();
    publish(&fx.state, CollusionAction::Off);
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Block);
    let answer = prompt_with(&fx, Route::Direct, "b", PROSE).await;
    assert_catalogue_sent_as("T1d: ", &fx, &answer, forwarded + 1);
    assert_ordered(&seen, admitted);
}

/// T3a: meta `catalogue_refusal`, admitted under `block`, `off` published at
/// the seam: still refused, with status 403. GREEN pin on base.
#[tokio::test]
async fn t3a_meta_catalogue_admitted_under_block_a_later_off_still_refuses() {
    let fx = meta_fixture(catalogue_setup(), None).await;
    read_resource(&fx, Route::Meta, "a").await;
    let forwarded = fx.catalogue();
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Off);
    let answer = prompt_with(&fx, Route::Meta, "b", PROSE).await;
    assert_catalogue_refused_as("T3a: ", &fx, &answer, forwarded);
    assert_eq!(answer.0, 403, "T3a: status: {}", answer.1);
    assert_ordered(&seen, admitted);
}

/// T3b: meta `catalogue_refusal`, admitted under `off`, `block` published at
/// the seam: forwarded. RED on base: refused under the startup `block`.
#[tokio::test]
async fn t3b_meta_catalogue_admitted_under_off_a_later_block_still_sends() {
    let fx = meta_fixture(catalogue_setup(), None).await;
    read_resource(&fx, Route::Meta, "a").await;
    let forwarded = fx.catalogue();
    publish(&fx.state, CollusionAction::Off);
    let admitted = fx.state.live_config.seq();
    let seen = arm_reload(&fx, CollusionAction::Block);
    let answer = prompt_with(&fx, Route::Meta, "b", PROSE).await;
    assert_catalogue_sent_as("T3b: ", &fx, &answer, forwarded + 1);
    assert_ordered(&seen, admitted);
}

/// Publish the live config with `change` applied.
fn edit(state: &super::super::AppState, change: impl FnOnce(&mut crate::config::Config)) {
    let mut config = (*state.live_config.get()).clone();
    change(&mut config);
    state.live_config.set(config);
}

/// P8.4 on the route: an emptied `non_egress` checks the egress again. RED
/// on base: the gate reads the startup list.
#[tokio::test]
async fn p8_4_route_an_emptied_non_egress_checks_the_egress_again() {
    let fx = fixture(Setup {
        non_egress: vec!["alpha:send".to_string()],
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    assert_sent_as(
        "P8.4 route control: ",
        &fx,
        &fx.send(Some("b"), PROSE).await,
        1,
    );
    edit(&fx.state, |c| {
        c.security.firewall.collusion.non_egress.clear();
    });
    assert_refused_as("P8.4 route: ", &fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// P8.5a on the route: `off` at startup, `block` published, then a read and
/// a relay: refused. RED on base: a startup `off` builds no detector.
#[tokio::test]
async fn p8_5a_route_off_then_block_refuses_a_later_relay() {
    let fx = fixture(Setup {
        action: CollusionAction::Off,
        ..Setup::default()
    })
    .await;
    publish(&fx.state, CollusionAction::Block);
    fx.read(Some("a")).await;
    assert_refused_as("P8.5a route: ", &fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// P8.11 on the route: an effective `off` lets a relay through. RED on
/// base: the startup `block` refuses it.
#[tokio::test]
async fn p8_11_route_an_effective_off_sends_the_relay() {
    let fx = alice_read().await;
    publish(&fx.state, CollusionAction::Off);
    assert_sent_as("P8.11 route: ", &fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// SG6 on the route: `observe` at startup, `block` published: refused. RED
/// on base: the startup `observe` lets it through.
#[tokio::test]
async fn sg6_route_observe_then_block_refuses() {
    let fx = fixture(Setup {
        action: CollusionAction::Observe,
        ..Setup::default()
    })
    .await;
    fx.read(Some("a")).await;
    publish(&fx.state, CollusionAction::Block);
    assert_refused_as("SG6 route: ", &fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// SG7: staging follows the firewall, not the action. A read admitted
/// under a startup `off` whose delivery finds `observe` published is held:
/// bob's relay is let through with one audited finding. RED on base: nothing
/// is staged under a startup `off`.
#[tokio::test]
async fn sg7_a_read_admitted_under_off_is_held_once_observe_is_published() {
    let scratch = crate::test_dir_keep::kept_tempdir();
    let log = scratch.path().join("audit.ndjson");
    let fx = fixture(Setup {
        action: CollusionAction::Off,
        audit_log: Some(log.clone()),
        ..Setup::default()
    })
    .await;
    let state = Arc::clone(&fx.state);
    relay_witness_hook::arm(move || publish(&state, CollusionAction::Observe));
    fx.read(Some("a")).await;
    assert_sent_as("SG7: ", &fx, &fx.send(Some("b"), PROSE).await, 1);
    let audited = std::fs::read_to_string(&log).expect("the audit log is written");
    let relays = audited
        .lines()
        .filter(|l| l.contains("collusion_relay"))
        .count();
    assert_eq!(relays, 1, "SG7: not one audited relay finding: {audited}");
}

/// R4.3b: the route's funnel records under the generation its caller
/// captured at delivery. Admitted under a startup `off`, `block` published
/// by the witness hook, `off` published again after the capture: the read is
/// still held, so bob's relay is refused once `block` is back. RED on base:
/// a startup `off` builds no detector.
#[tokio::test]
async fn r4_3b_the_route_funnel_records_under_the_captured_generation() {
    use crate::gateway::meta_mcp::invoke::relay::commit_capture_hook;
    let fx = fixture(Setup {
        action: CollusionAction::Off,
        ..Setup::default()
    })
    .await;
    let (admit, capture) = (Arc::clone(&fx.state), Arc::clone(&fx.state));
    // The publish count each hook's reload left: this row's, in this order.
    let (witnessed, captured) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
    let (w, c) = (Rc::clone(&witnessed), Rc::clone(&captured));
    let start = fx.state.live_config.seq();
    relay_witness_hook::arm(move || {
        publish(&admit, CollusionAction::Block);
        w.set(admit.live_config.seq());
    });
    commit_capture_hook::arm(move || {
        publish(&capture, CollusionAction::Off);
        c.set(capture.live_config.seq());
    });
    fx.read(Some("a")).await;
    assert_eq!(
        witnessed.get(),
        start + 1,
        "the witness hook's reload was not the read's first"
    );
    assert_eq!(
        captured.get(),
        start + 2,
        "the capture hook did not reload after the witness hook"
    );
    publish(&fx.state, CollusionAction::Block);
    assert_refused_as("R4.3b: ", &fx, &fx.send(Some("b"), PROSE).await, 0);
}
