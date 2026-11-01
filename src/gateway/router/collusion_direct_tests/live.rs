// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T1) on the direct route: a reload between a call's
//! admission and its relay check changes nothing for that call. The witness
//! judges under the generation the request pinned at admission, never one
//! read again later.
//!
//! The hook runs immediately before the caller evaluates the generation it
//! hands the witness. Each row asserts the hook ran and that its reload was
//! the only publish since admission, so the reload is visible only to a read
//! made after the hook.

use std::cell::Cell;
use std::rc::Rc;

use super::catalogue::{Route, prompt_with, read_resource};
use super::catalogue::{assert_catalogue_refused, assert_catalogue_sent};
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
    assert_refused(&fx, &fx.call(Some("b"), &relay).await, 0);
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
    assert_sent(&fx, &fx.call(Some("b"), &relay).await, 1);
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
    assert_catalogue_refused(&fx, &answer, forwarded);
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
    assert_catalogue_sent(&fx, &answer, forwarded + 1);
    assert_ordered(&seen, admitted);
}
