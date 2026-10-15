// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8428 Case A: a keyed call on a REST capability account whose lease
//! recheck meets a busy custody AFTER the idempotency reservation and the
//! outer dispatch mark are armed, and BEFORE anything is sent. Nothing
//! reached the vendor, so the key must stay free for the same-key retry. An
//! error raised after the send keeps today's settlement.

use serde_json::{Value, json};

use super::{CapabilityHarness, assert_served, capability_harness, capability_harness_over};
use super::{keyed_meta, send_as};
use super::{refused_as_replay, signed_capability_invoke};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount,
};

/// A synchronous keyed `gateway_invoke` of the capability, as alice.
async fn keyed_call(harness: &CapabilityHarness, key: &str) -> Value {
    let params = json!({"name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
        "_meta": keyed_meta(key)});
    send_as(&harness.router, "tools/call", "gateway_invoke", params).await
}

/// The three lease rechecks a capability dispatch makes before its send, by
/// how many custody releases pass before the `Busy`: the mint's, then one
/// per recheck.
#[derive(Clone, Copy, Debug)]
enum Recheck {
    /// `CapabilityBackend`'s `prepare_account_context`, before isolation.
    InBackend = 1,
    /// The executor's own `prepare_account_context`, before the cache read.
    BeforeCache = 2,
    /// `inject_auth`, the last point before the credential goes on the wire.
    BeforeWire = 3,
}

/// SETTLE.1 / SETTLE.2 at `site`. Primary: after the custody recovers, the
/// SAME key re-enters dispatch and the vendor serves it. A committed
/// reservation, or a retained outer dispatch mark, replays the stale Busy
/// instead and the vendor never sees the retry.
async fn a_recheck_busy_frees_the_key(site: Recheck) {
    let harness = capability_harness(false).await;
    let passed = site as usize;
    harness.account.fail_releases_after_for_test(passed);
    let key = format!("recheck-busy-{site:?}");
    let busy = keyed_call(&harness, &key).await;
    assert_eq!(
        harness.account.peer_requests(),
        0,
        "{site:?} premise: nothing reached the vendor: {busy}"
    );
    assert_eq!(
        harness.account.releases(),
        passed,
        "{site:?} premise: the Busy met this recheck, after the releases before it: {busy}"
    );

    harness.account.fail_custody_for_test(false);
    let retry = keyed_call(&harness, &key).await;
    assert_served(
        &harness,
        0,
        &retry,
        &format!("SETTLE.1 {site:?}: the same-key retry after a pre-send recheck Busy"),
    );
}

#[tokio::test]
async fn a_recheck_busy_in_the_backend_leaves_the_key_free_for_its_retry() {
    a_recheck_busy_frees_the_key(Recheck::InBackend).await;
}

#[tokio::test]
async fn a_recheck_busy_before_the_cache_leaves_the_key_free_for_its_retry() {
    a_recheck_busy_frees_the_key(Recheck::BeforeCache).await;
}

#[tokio::test]
async fn a_recheck_busy_before_the_wire_leaves_the_key_free_for_its_retry() {
    a_recheck_busy_frees_the_key(Recheck::BeforeWire).await;
}

/// SETTLE.4. The vendor answers 400, an error raised after the send. The
/// reservation stays committed: the same-key retry is not dispatched again.
#[tokio::test]
async fn an_error_after_the_send_keeps_the_key_settled() {
    let harness =
        capability_harness_over(CapabilityAccount::start_answering(&[400]).await, false).await;
    let first = keyed_call(&harness, "after-send").await;
    assert_eq!(
        harness.account.peer_requests(),
        1,
        "premise: the request was sent: {first}"
    );
    let retry = keyed_call(&harness, "after-send").await;
    assert_eq!(
        harness.account.peer_requests(),
        1,
        "SETTLE.4: a same-key retry after an error past the send is not dispatched again: {retry}"
    );
}

/// Case A, signed: the mint already spent the call's refund witness, so a
/// recheck Busy does not give the nonce back. The same nonce re-sent is
/// refused as a replay; a fresh nonce reaches the vendor.
#[tokio::test]
async fn a_signed_recheck_busy_keeps_its_nonce_spent() {
    let harness = capability_harness(true).await;
    harness.account.fail_releases_after_for_test(1);
    let busy = signed_capability_invoke(&harness, "recheck-n1").await;
    assert_eq!(
        harness.account.peer_requests(),
        0,
        "premise: nothing reached the vendor: {busy}"
    );
    harness.account.fail_custody_for_test(false);
    let same = signed_capability_invoke(&harness, "recheck-n1").await;
    assert!(
        refused_as_replay(&same),
        "the same nonce is refused as a replay: {same}"
    );
    let fresh = signed_capability_invoke(&harness, "recheck-n2").await;
    assert_served(&harness, 0, &fresh, "a fresh nonce after a recheck Busy");
}
