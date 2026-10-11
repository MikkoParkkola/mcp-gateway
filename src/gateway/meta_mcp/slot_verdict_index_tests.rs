// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), caller-slot index rows: every fill site
//! records the caller's slot, and every removal path forgets it.

use serde_json::json;

use super::slot_verdict_fixture::{
    CallerSlot, Surfaced, TOOL, Warmth, assert_index_covers_populated_slots, call_as_alpha,
    indexed_binding_for, indexed_binding_for_alpha, per_user, valid, warm_by_listing,
};
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// I2a (index write site: catalogue fill; asked by MIK-8350): after ONLY a
/// `gateway_list_tools` fill of alpha's slot, the index names alpha's slot.
/// Red-by-absence: nothing writes the index yet (the read API is a stub).
#[tokio::test]
async fn i2a_index_written_by_catalogue_fill() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "premise: indexed before any fill"
    );
    warm_by_listing(&fx.meta).await;
    assert_eq!(fx.caller.lists(), 1, "premise: alpha's slot was not filled");
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2a: the catalogue fill wrote no index entry"
    );
}

/// I2c (index write site: F13 fill): after ONLY a cold call's F13 fill
/// (argument-key enforcement on), the index names alpha's slot. Red-by-absence.
#[tokio::test]
async fn i2c_index_written_by_f13_fill() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        fx.caller.lists(),
        1,
        "premise: the call did not fill alpha's slot"
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2c: the F13 fill wrote no index entry"
    );
}

/// I2d (index write site: the caller verdict's own fill on the dispatch path,
/// kimi r2 F2; asked by MIK-8350): a call-first caller with argument-key
/// enforcement Off, where F13 does not fill. After that call alone the index
/// names alpha's slot. Red-by-absence: on base nothing fills here at all.
#[tokio::test]
async fn i2d_index_written_by_dispatch_fill() {
    let off = InputSchemaEnforcement::Off;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        off,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2d: the dispatch-path fill wrote no index entry (lists: {})",
        fx.caller.lists()
    );
}

/// I3b (asked by MIK-8350 AC2): revoking alpha's grant
/// (`evict_identity_slots` on alpha's binding prefix) removes alpha's index
/// entry, and beta's entry under another prefix survives. The premise that
/// both are indexed first is what makes this red on the stub: `None` after
/// the revocation alone would pass trivially. Red-by-absence.
#[tokio::test]
async fn i3b_index_entry_removed_on_grant_revocation() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let _beta_upstream = super::slot_verdict_fixture::add_caller(&fx.meta, "beta", &valid());
    warm_by_listing(&fx.meta).await;
    let beta = super::catalogue_per_caller_tests::identity("beta");
    fx.meta
        .list_tools(
            &json!({"server": super::slot_verdict_fixture::BACKEND}),
            None,
            &super::identified_caller(&beta),
        )
        .await
        .expect("beta lists");
    assert_eq!(
        indexed_binding_for(&fx.meta, "alpha").as_deref(),
        Some("alpha@ledger"),
        "I3b premise: alpha is not indexed"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "beta").as_deref(),
        Some("beta@ledger"),
        "I3b premise: beta is not indexed"
    );
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_identity_slots("alpha@") >= 1,
        "premise: alpha's slot not evicted"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "alpha"),
        None,
        "I3b: alpha still indexed"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "beta").as_deref(),
        Some("beta@ledger"),
        "I3b: beta's entry was removed with alpha's"
    );
}

/// I2e (asked by MIK-8350): every fill path a test drives leaves the index
/// covering the slot it filled. One gateway drives the catalogue fill
/// (alpha) and a cold call's F13 fill (beta); a second gateway drives the
/// dispatch-path fill with enforcement Off (alpha again). Red-by-absence on
/// the stub, from the first half; the second half holds vacuously on base,
/// where nothing fills with enforcement Off.
#[tokio::test]
async fn i2e_index_covers_every_populated_slot() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let _beta_upstream = super::slot_verdict_fixture::add_caller(&fx.meta, "beta", &valid());
    let beta = super::catalogue_per_caller_tests::identity("beta");
    let _ = Box::pin(fx.meta.handle_tools_call(
        crate::protocol::RequestId::Number(2),
        TOOL,
        json!({"q": "x"}),
        None,
        super::identified_caller(&beta),
    ))
    .await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.populated_per_user_bindings_for_test().len() >= 2,
        "premise: alpha's and beta's slots are not both populated: {:?}",
        backend.populated_per_user_bindings_for_test()
    );
    assert_index_covers_populated_slots(&fx.meta, "I2e (catalogue + F13)");

    let off = InputSchemaEnforcement::Off;
    let gx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        off,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&gx.meta, TOOL, json!({"q": "x"})).await;
    assert_index_covers_populated_slots(&gx.meta, "I2e (dispatch-path fill)");
}

/// I3 (idle eviction): once alpha's slot is idle-evicted, the index no longer
/// names it. The premise (indexed first) makes this red on the stub.
/// Red-by-absence.
#[tokio::test]
async fn i3_index_entry_removed_on_idle_eviction() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I3 premise: alpha is not indexed"
    );
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_idle_per_user_entries(std::time::Duration::ZERO) >= 1,
        "premise: alpha's slot was not evicted"
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "I3: still indexed"
    );
}

/// I1 (guard, design R3.5, gpt F7): a fill that fails stores nothing, so it
/// writes no index entry. Green on the stub trivially; after the
/// implementation it kills an index written at credential resolution
/// instead of at the slot store (the r2 design gpt rejected).
#[tokio::test]
async fn i1_failed_fill_writes_no_index_entry() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::ColdFailing,
        CLOSED,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert!(fx.caller.lists() >= 1, "premise: no fill was attempted");
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "I1: a failed fill was indexed"
    );
}

/// The discovery surfaces that fill a caller's slot through
/// `backend_tools_for_discovery`.
#[derive(Clone, Copy, Debug)]
enum Discovery {
    Search,
    CodeModeSearch,
    ListAllServers,
}

/// I2f (index write site: an empty fill), on every discovery surface that
/// fills through `backend_tools_for_discovery`: alpha's own catalogue is a
/// complete, successful list of no tools. After ONLY that fill, the index
/// names alpha's slot: an empty catalogue is known, and alpha must not be left
/// on the cold rule's shared view. RED before the fix: discovery turns an
/// empty fill into "nothing fetched" and skips the index write.
#[tokio::test]
async fn i2f_index_written_by_an_empty_fill() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    for surface in [
        Discovery::Search,
        Discovery::CodeModeSearch,
        Discovery::ListAllServers,
    ] {
        let fx = per_user(
            CallerSlot::Valid,
            &valid(),
            Warmth::Cold,
            CLOSED,
            Surfaced::Yes,
        );
        let asked = super::slot_verdict_fixture::serve_alpha_empty(&fx.meta);
        let caller = super::identified_caller(&alpha);
        let found = match surface {
            Discovery::Search => {
                let args = json!({"query": "read"});
                fx.meta.search_tools(&args, None, &caller).await
            }
            Discovery::CodeModeSearch => {
                let args = json!({"query": "read"});
                fx.meta.code_mode_search(&args, None, &caller).await
            }
            Discovery::ListAllServers => fx.meta.list_tools(&json!({}), None, &caller).await,
        };
        assert_eq!(
            asked.lists(),
            1,
            "premise {surface:?}: alpha's empty slot was not filled: {found:?}"
        );
        assert_eq!(
            indexed_binding_for_alpha(&fx.meta).as_deref(),
            Some(super::slot_verdict_fixture::BINDING),
            "I2f {surface:?}: the empty fill wrote no index entry"
        );
    }
}
