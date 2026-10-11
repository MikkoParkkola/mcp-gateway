// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), listing rows: name-only surfaces judge a
//! per-user backend's tools by the caller's own catalogue slot, and withhold
//! them from a caller whose slot is cold.

use serde_json::json;

use super::slot_verdict_fixture::{
    CallerSlot, Surfaced, Warmth, disabled_as_alpha, disabled_for, names_tool, per_user,
    predictions_for_alpha, predicts_tool, surfaced_entry_for_alpha, valid, warm_by_listing,
};
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// L1 (SLOTVIS.1): with alpha's slot warm, a disabled tool alpha's own
/// catalogue withholds or lacks is not named; alpha's valid one is. RED on
/// base: the disabled list judges the shared slot (valid).
#[tokio::test]
async fn l1_disabled_list_judges_the_callers_slot() {
    for (slot, named) in [
        (CallerSlot::Valid, true),
        (CallerSlot::Invalid, false),
        (CallerSlot::Lacks, false),
    ] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let listed = disabled_as_alpha(&fx.meta);
        assert_eq!(names_tool(&listed), named, "L1 {slot:?}: {listed}");
    }
}

/// L6a (SLOTVIS.6 listing clause): alpha's slot is cold (never listed), so
/// the disabled list withholds that backend's tools from alpha, even one its
/// own catalogue would offer. RED on base: the shared slot names it.
#[tokio::test]
async fn l6a_cold_caller_disabled_list_withholds() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L6a: a cold caller is named the tool: {listed}"
    );
}

/// L3c (SLOTVIS.3, counts): with alpha's slot warm, the backend count alpha
/// is given leaves out a tool alpha's catalogue withholds, exactly as one it
/// lacks; alpha's valid tool is counted. RED on base: counts walk the
/// shared snapshot.
#[tokio::test]
async fn l3c_counts_use_the_callers_slot() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let mut totals = Vec::new();
    for slot in [CallerSlot::Valid, CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let (total, _) = fx
            .meta
            .admitted_counts(super::identified_caller(&alpha).scope(), None);
        totals.push(total.phrase());
    }
    assert_eq!(
        totals[1], totals[2],
        "L3c: withheld vs lacked counts differ"
    );
    assert_ne!(totals[0], totals[1], "L3c: the withheld tool is counted");
}

/// L2 (SLOTVIS.2): with alpha's slot warm, a predicted tool alpha's own
/// catalogue withholds or lacks is not predicted to alpha; alpha's valid one
/// is. RED on base: predictions judge the shared slot.
#[tokio::test]
async fn l2_predictions_judge_the_callers_slot() {
    for (slot, predicted) in [
        (CallerSlot::Valid, true),
        (CallerSlot::Invalid, false),
        (CallerSlot::Lacks, false),
    ] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let got = predictions_for_alpha(&fx.meta);
        assert_eq!(predicts_tool(&got), predicted, "L2 {slot:?}: {got:?}");
    }
}

/// L3d (SLOTVIS.3, `list_servers`): with alpha's slot warm, the per-backend
/// `tools_count` alpha is given leaves out a tool its catalogue withholds,
/// exactly as one it lacks; alpha's valid tool is counted. RED on base:
/// `list_servers` walks the shared snapshot (`surfaced.rs:234`).
#[tokio::test]
async fn l3d_list_servers_counts_the_callers_slot() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let mut counts = Vec::new();
    for slot in [CallerSlot::Valid, CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let listed = fx
            .meta
            .list_servers(&super::identified_caller(&alpha), None)
            .await
            .expect("list_servers answers");
        let count = listed.to_string().contains("\"tools_count\":1");
        counts.push((count, listed));
    }
    assert!(
        !counts[0].0,
        "premise: alpha's valid catalogue counts 2: {}",
        counts[0].1
    );
    assert!(
        counts[1].0,
        "L3d Invalid: the withheld tool is counted: {}",
        counts[1].1
    );
    assert!(counts[2].0, "L3d Lacks: {}", counts[2].1);
}

/// L3a (SLOTVIS.3, surfaced list), on a single-user gateway: with alpha's
/// slot warm, the surfaced [`TOOL`] in alpha's `tools/list` is alpha's own
/// Tool. The shared slot holds a DIFFERENT valid schema, so the bytes tell
/// which slot it came from. A tool alpha's catalogue withholds is not listed,
/// exactly as one it lacks. RED on base (measured 2026-10-11): single-user
/// `tools/list` lists the shared Tool (`resolve_surfaced_tool`).
#[tokio::test]
async fn l3a_surfaced_list_takes_the_callers_tool() {
    let shared = json!({"type": "object", "properties": {"z": {"type": "integer"}}});
    let fx = per_user(
        CallerSlot::Valid,
        &shared,
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    fx.meta.set_multi_user(false);
    warm_by_listing(&fx.meta).await;
    let listed =
        surfaced_entry_for_alpha(&fx.meta).expect("premise: alpha's valid tool is not listed");
    assert_eq!(
        listed["inputSchema"],
        valid(),
        "L3a: not alpha's schema: {listed}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &shared, Warmth::Cold, CLOSED, Surfaced::Yes);
        fx.meta.set_multi_user(false);
        warm_by_listing(&fx.meta).await;
        assert_eq!(
            surfaced_entry_for_alpha(&fx.meta),
            None,
            "L3a {slot:?}: listed"
        );
    }
}

/// L3a-multi (guard): on a multi-user gateway an isolated per-user backend's
/// surfaced tool is omitted from `tools/list` altogether (INV-2,
/// `meta_route_isolation_refused`), whatever alpha's slot holds. Green on
/// base; kills a change that lets the caller-slot path bypass INV-2.
#[tokio::test]
async fn l3a_multi_user_keeps_the_isolated_surfaced_tool_out() {
    for slot in [CallerSlot::Valid, CallerSlot::Invalid] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        assert_eq!(
            surfaced_entry_for_alpha(&fx.meta),
            None,
            "L3a-multi {slot:?}: listed"
        );
    }
}

/// L6b (SLOTVIS.6 listing clause): alpha's slot was warm and has been
/// evicted, so it is cold again and the disabled list withholds that
/// backend's tools from alpha. RED on base: the shared slot names it.
#[tokio::test]
async fn l6b_evicted_caller_disabled_list_withholds() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_idle_per_user_entries(std::time::Duration::ZERO) >= 1,
        "premise: alpha's slot was not evicted"
    );
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L6b: an evicted caller is named the tool: {listed}"
    );
}

/// L5 (SLOTVIS.5, parity): with alpha's slot warm, the disabled list and the
/// predictions answer byte-identically whether alpha's catalogue withholds
/// [`TOOL`] (invalid schema) or lacks it. RED on base: the withheld case
/// answers from the shared slot and names the tool.
#[tokio::test]
async fn l5_withheld_answers_exactly_as_lacked() {
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let disabled = disabled_as_alpha(&fx.meta);
        let predicted = predictions_for_alpha(&fx.meta);
        answers.push((disabled, predicted));
    }
    assert_eq!(
        answers[0].0, answers[1].0,
        "L5: disabled list, withheld vs lacked"
    );
    assert_eq!(
        answers[0].1, answers[1].1,
        "L5: predictions, withheld vs lacked"
    );
    // Equal is not enough: on base both answer from the shared slot and name
    // the tool alike. SLOTVIS.5 also says neither names it.
    assert!(
        !names_tool(&answers[0].0),
        "L5: the disabled list names the tool: {}",
        answers[0].0
    );
    assert!(
        !predicts_tool(&answers[0].1),
        "L5: the tool is predicted: {:?}",
        answers[0].1
    );
}

/// L10: two callers on one per-user backend: alpha's catalogue holds
/// [`TOOL`] with an invalid schema, beta's with a valid one, the shared slot
/// valid. alpha is not named the disabled tool; beta is. Neither's entry ever
/// answers for the other. RED on base: alpha is named (the shared slot).
#[tokio::test]
async fn l10_two_callers_judged_each_by_their_own_slot() {
    let fx = per_user(
        CallerSlot::Invalid,
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
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let for_beta = disabled_for(&fx.meta, &super::identified_caller(&beta));
    assert!(
        names_tool(&for_beta),
        "premise: beta's valid tool is not named: {for_beta}"
    );
    let for_alpha = disabled_for(&fx.meta, &super::identified_caller(&alpha));
    assert!(
        !names_tool(&for_alpha),
        "L10: alpha is named a tool its slot withholds: {for_alpha}"
    );
}

/// L9 (case 1, kimi r2 F1): an anonymous caller has no view of a `required`
/// per-user backend, so none of its tools reaches it through the disabled
/// list or the counts. RED on base (measured 2026-10-11): both answer from
/// the shared slot (named; "2 tools").
#[tokio::test]
async fn l9_required_backend_anonymous_caller_sees_none() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let anonymous = super::anonymous_caller();
    let disabled = disabled_for(&fx.meta, &anonymous);
    assert!(
        !names_tool(&disabled),
        "L9: anonymous is named the tool: {disabled}"
    );
    let (total, _) = fx.meta.admitted_counts(anonymous.scope(), None);
    let counted = total.phrase();
    assert!(
        !counted.starts_with('2'),
        "L9: anonymous is counted the tools: {counted}"
    );
}

/// L9-servers (guard): `list_servers` already hides a `required` per-user
/// backend's tools from an anonymous caller (`has_no_view_for`,
/// `tools_count` 0, `tools_known` false). Green on base; keeps the caller-slot
/// change from reopening it.
#[tokio::test]
async fn l9_servers_keep_the_required_backend_hidden() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let servers = fx
        .meta
        .list_servers(&super::anonymous_caller(), None)
        .await
        .expect("list_servers answers")
        .to_string();
    assert!(
        servers.contains("\"tools_count\":0") && servers.contains("\"tools_known\":false"),
        "L9-servers: {servers}"
    );
}

/// L11a: alpha's slot holds a TRUNCATED list (a paging drain past its
/// budget) that lacks [`TOOL`]. A partial list proves nothing about an unseen
/// name, so the count alpha is given is a lower bound ("at least"), never an
/// exact total. RED on base: counts walk the shared snapshot and report an
/// exact "2 tools".
#[tokio::test]
async fn l11a_truncated_caller_slot_counts_at_least() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let fx = per_user(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    backend.mark_per_user_truncated_for_test(super::slot_verdict_fixture::BINDING);
    let (total, _) = fx
        .meta
        .admitted_counts(super::identified_caller(&alpha).scope(), None);
    let phrase = total.phrase();
    assert!(
        phrase.starts_with("at least"),
        "L11a: a truncated caller slot gave an exact count: {phrase}"
    );
}

/// L11b: alpha's slot is filled but empty (a complete list with no tools).
/// The disabled list then names none of that backend's tools to alpha. RED
/// on base: the shared slot names [`TOOL`].
#[tokio::test]
async fn l11b_empty_caller_slot_withholds() {
    let fx = per_user(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    backend.store_per_user_tools_for_test(super::slot_verdict_fixture::BINDING, Vec::new());
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L11b: an empty caller slot named the tool: {listed}"
    );
}

/// L7 (design R4.2, gpt r3 F1): a Passthrough-strategy per-user backend.
/// A passthrough caller's credential reaches the gateway only on the direct
/// route, so no meta-route listing can select that caller's own slot;
/// name-only listings withhold the backend's tools (stated over-withholding;
/// `gateway_list_tools` and search are not name-only). RED on base: the
/// disabled list and the counts read the shared slot.
#[tokio::test]
async fn l7_passthrough_backend_tools_withheld_from_name_only_listings() {
    use super::slot_verdict_fixture::{per_user_backend_with, per_user_on};
    let (backend, caller, shared) = per_user_backend_with(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        |config| {
            if let Some(idp) = config.identity_propagation.as_mut() {
                idp.strategy = crate::identity_propagation::PropagationStrategyKind::Passthrough;
            }
        },
    );
    let fx = per_user_on(backend, caller, shared, Surfaced::Yes);
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L7: a passthrough backend's tool is named: {listed}"
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let (total, _) = fx
        .meta
        .admitted_counts(super::identified_caller(&alpha).scope(), None);
    assert!(
        !total.phrase().starts_with('2'),
        "L7: a passthrough backend's tools are counted: {}",
        total.phrase()
    );
}

/// L7b (test plan L7 second half, gpt tp F13; kills M10): a passthrough
/// fill publishes no index entry, and an entry that reached the index anyway
/// still selects nothing. Every fill site (catalogue, direct-route drain,
/// F13) indexes through `remember_caller_slot`, so the row calls it exactly
/// as the direct-route drain does after alpha's passthrough listing.
#[tokio::test]
async fn l7b_passthrough_fills_publish_no_index_entry() {
    use super::slot_verdict_fixture::{BINDING, per_user_backend_with, per_user_on};
    let (backend, caller, shared) = per_user_backend_with(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        |config| {
            if let Some(idp) = config.identity_propagation.as_mut() {
                idp.strategy = crate::identity_propagation::PropagationStrategyKind::Passthrough;
            }
        },
    );
    let fx = per_user_on(
        std::sync::Arc::clone(&backend),
        caller,
        shared,
        Surfaced::Yes,
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let proof = super::MetaMcp::proof_of(&super::identified_caller(&alpha));
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .iter()
            .any(|b| b == BINDING),
        "premise: alpha's passthrough slot holds a catalogue"
    );
    fx.meta.remember_caller_slot(&backend, proof, Some(BINDING));
    assert!(
        backend.indexed_bindings_for_test().is_empty(),
        "L7b: a passthrough fill published an index entry"
    );
    assert!(
        !names_tool(&disabled_as_alpha(&fx.meta)),
        "L7b: a passthrough backend's tool is named after its fill"
    );
    // An entry that reached the index by any other way: the listing still
    // cannot select a passthrough slot (CallerProof carries no credential).
    let principal = fx
        .meta
        .principal_for(&backend, proof)
        .expect("alpha is a verified principal");
    backend.record_caller_slot(&principal.stable_actor_id(), BINDING);
    assert!(
        !names_tool(&disabled_as_alpha(&fx.meta)),
        "L7b: a listing selected a passthrough slot from the index"
    );
}

/// L3b (SLOTVIS.3): the spec-preview filtered `tools/list` and `tools/resolve`
/// judge a per-user tool by alpha's own warm slot: named when alpha's
/// catalogue offers it, absent when it withholds or lacks it, though the
/// shared slot offers it in every case.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l3b_spec_preview_judges_the_callers_slot() {
    use super::slot_verdict_fixture::TOOL;
    for (slot, named) in [
        (CallerSlot::Valid, true),
        (CallerSlot::Invalid, false),
        (CallerSlot::Lacks, false),
    ] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::No);
        // Single-user: a multi-user gateway leaves an isolated per-user
        // backend out of spec preview altogether (INV-2), as L3a notes.
        fx.meta.set_multi_user(false);
        warm_by_listing(&fx.meta).await;
        let alpha = super::catalogue_per_caller_tests::identity("alpha");
        let caller = super::identified_caller(&alpha);
        let scope = caller.scope();
        let filtered = fx.meta.handle_tools_list_filtered(
            crate::protocol::RequestId::Number(1),
            TOOL,
            None,
            scope,
        );
        let filtered = serde_json::to_value(&filtered).expect("a response serialises");
        let listed = filtered
            .pointer("/result/tools")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL));
        assert_eq!(listed, named, "L3b filtered {slot:?}: {filtered}");
        let resolved = fx
            .meta
            .handle_tools_resolve(
                crate::protocol::RequestId::Number(2),
                Some(&json!({"name": TOOL})),
                None,
                scope,
            )
            .await;
        assert_eq!(
            resolved.error.is_none(),
            named,
            "L3b resolve {slot:?}: {resolved:?}"
        );
    }
}

/// L3b-multi (guard): on a multi-user gateway an isolated per-user backend is
/// left out of the spec-preview filtered `tools/list` and `tools/resolve`
/// for every caller (INV-2, `meta_route_isolation_refused`), whatever alpha's
/// own slot holds. L3b reads the single-user gateway, where the caller's slot
/// decides; this row pins the multi-user behaviour L3b no longer exercises.
/// Green on base by construction; its mutant drops the isolation skip.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l3b_multi_user_keeps_the_isolated_backend_out_of_spec_preview() {
    use super::slot_verdict_fixture::TOOL;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    warm_by_listing(&fx.meta).await;
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let caller = super::identified_caller(&alpha);
    let scope = caller.scope();
    let filtered = fx.meta.handle_tools_list_filtered(
        crate::protocol::RequestId::Number(1),
        TOOL,
        None,
        scope,
    );
    let filtered = serde_json::to_value(&filtered).expect("a response serialises");
    let listed = filtered
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL));
    assert!(
        !listed,
        "L3b-multi: the isolated backend's tool is listed: {filtered}"
    );
    let resolved = fx
        .meta
        .handle_tools_resolve(
            crate::protocol::RequestId::Number(2),
            Some(&json!({"name": TOOL})),
            None,
            scope,
        )
        .await;
    assert!(
        resolved.error.is_some(),
        "L3b-multi: the isolated backend's tool resolves: {resolved:?}"
    );
}

/// L6c (SLOTVIS.6 third clause, control): a cold caller's surfaced list in
/// plain `tools/list` keeps today's shared view. alpha's own catalogue would
/// withhold the tool (invalid schema), but its slot is cold, so the shared
/// entry is listed, by design. Green on base.
#[tokio::test]
async fn l6c_cold_surfaced_list_keeps_the_shared_view() {
    let fx = per_user(
        CallerSlot::Invalid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    // Single-user, as L3a: a multi-user gateway omits the surfaced entry of an
    // isolated per-user backend for every caller (INV-2).
    fx.meta.set_multi_user(false);
    let entry = surfaced_entry_for_alpha(&fx.meta);
    assert!(
        entry.is_some(),
        "L6c: a cold caller's surfaced list dropped the shared entry"
    );
}

/// alpha's plain `tools/list` in session `s1`, and its [`TOOL`] entry if any.
#[cfg(feature = "spec-preview")]
fn promoted_entry_for_alpha(meta: &super::MetaMcp) -> Option<serde_json::Value> {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let response = meta.handle_tools_list_for_session(
        crate::protocol::RequestId::Number(1),
        Some("s1"),
        super::identified_caller(&alpha).scope(),
    );
    let body = serde_json::to_value(&response).expect("a response serialises");
    body.pointer("/result/tools")?
        .as_array()?
        .iter()
        .find(|t| t["name"] == super::slot_verdict_fixture::TOOL)
        .cloned()
}

/// L3e (design R3.3, gpt r3 F4; lead ruling 2026-10-11), single-user as L3a:
/// a tool promoted into alpha's session on a per-user backend is listed as
/// alpha's own Tool while alpha's slot is warm (the shared slot holds a
/// DIFFERENT valid schema), and not at all while it is cold: a promotion
/// never shows the shared catalogue's view of a per-user tool.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l3e_promoted_tool_follows_the_callers_slot() {
    let shared = json!({"type": "object", "properties": {"z": {"type": "integer"}}});
    let promote = |meta: &super::MetaMcp| {
        meta.promote_tool_for_session(
            Some("s1"),
            &format!(
                "{}:{}",
                super::slot_verdict_fixture::BACKEND,
                super::slot_verdict_fixture::TOOL
            ),
        );
    };
    let cold = per_user(
        CallerSlot::Valid,
        &shared,
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    cold.meta.set_multi_user(false);
    promote(&cold.meta);
    assert_eq!(
        promoted_entry_for_alpha(&cold.meta),
        None,
        "L3e: a cold caller's promoted entry shows the shared view"
    );
    let warm = per_user(
        CallerSlot::Valid,
        &shared,
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    warm.meta.set_multi_user(false);
    warm_by_listing(&warm.meta).await;
    promote(&warm.meta);
    let listed =
        promoted_entry_for_alpha(&warm.meta).expect("L3e: alpha's promoted tool is not listed");
    assert_eq!(
        listed["inputSchema"],
        super::slot_verdict_fixture::valid(),
        "L3e: not alpha's schema: {listed}"
    );
}

/// L6a, predictions (SLOTVIS.6): alpha's slot is cold, so the next-tool
/// predictions withhold that backend's tools, though alpha's own catalogue
/// would offer them. RED on base: the shared slot predicts it.
#[tokio::test]
async fn l6a_cold_caller_predictions_withhold() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let got = predictions_for_alpha(&fx.meta);
    assert!(
        !predicts_tool(&got),
        "L6a: a cold caller is predicted the tool: {got:?}"
    );
}

/// L6a, counts: a cold caller is not counted that backend's tools. RED on
/// base: counts walk the shared snapshot ("2 tools").
#[tokio::test]
async fn l6a_cold_caller_counts_withhold() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let (total, _) = fx
        .meta
        .admitted_counts(super::identified_caller(&alpha).scope(), None);
    let phrase = total.phrase();
    assert!(
        !phrase.starts_with('2'),
        "L6a: a cold caller is counted the tools: {phrase}"
    );
}

/// L6a, `list_servers`: a cold caller's `tools_count` leaves out the tools
/// the shared snapshot holds. RED on base: it reports 2.
#[tokio::test]
async fn l6a_cold_caller_list_servers_withholds() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let listed = fx
        .meta
        .list_servers(&super::identified_caller(&alpha), None)
        .await
        .expect("list_servers answers")
        .to_string();
    assert!(
        !listed.contains("\"tools_count\":2"),
        "L6a: a cold caller is counted the shared tools: {listed}"
    );
}

/// L6a, spec-preview: a cold caller's filtered `tools/list` does not name the
/// tool and `tools/resolve` does not find it. RED on base: the shared
/// snapshot goes to `shows_tool`.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l6a_cold_caller_spec_preview_withholds() {
    use super::slot_verdict_fixture::TOOL;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let caller = super::identified_caller(&alpha);
    let scope = caller.scope();
    let filtered = fx.meta.handle_tools_list_filtered(
        crate::protocol::RequestId::Number(1),
        TOOL,
        None,
        scope,
    );
    let filtered = serde_json::to_value(&filtered).expect("a response serialises");
    let listed = filtered
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL));
    assert!(!listed, "L6a filtered: a cold caller is listed: {filtered}");
    let resolved = fx
        .meta
        .handle_tools_resolve(
            crate::protocol::RequestId::Number(2),
            Some(&json!({"name": TOOL})),
            None,
            scope,
        )
        .await;
    assert!(
        resolved.error.is_some(),
        "L6a resolve: a cold caller resolved it: {resolved:?}"
    );
}

/// L9, predictions: an anonymous caller has no view of a `required` per-user
/// backend, so none of its tools is predicted to it. RED on base: the shared
/// slot predicts it.
#[tokio::test]
async fn l9_required_backend_anonymous_caller_is_predicted_none() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let tracker = std::sync::Arc::new(crate::transition::TransitionTracker::new());
    fx.meta
        .set_transition_tracker(std::sync::Arc::clone(&tracker));
    let (from, to) = ("ledger_hub:note", "ledger_hub:read");
    for _ in 0..8 {
        tracker.record_transition("teacher", from);
        tracker.record_transition("teacher", to);
    }
    let anonymous = super::anonymous_caller();
    let got = fx
        .meta
        .record_and_predict(None, Some("anon-session"), from, anonymous.scope());
    assert!(
        !predicts_tool(&got),
        "L9: anonymous is predicted the tool: {got:?}"
    );
}

/// L9, spec-preview: an anonymous caller's filtered `tools/list` does not
/// name a `required` per-user backend's tool and `tools/resolve` does not
/// find it. RED on base: the shared snapshot goes to `shows_tool`.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn l9_required_backend_anonymous_caller_spec_preview_sees_none() {
    use super::slot_verdict_fixture::TOOL;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let anonymous = super::anonymous_caller();
    let scope = anonymous.scope();
    let filtered = fx.meta.handle_tools_list_filtered(
        crate::protocol::RequestId::Number(1),
        TOOL,
        None,
        scope,
    );
    let filtered = serde_json::to_value(&filtered).expect("a response serialises");
    let listed = filtered
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL));
    assert!(!listed, "L9 filtered: anonymous is listed: {filtered}");
    let resolved = fx
        .meta
        .handle_tools_resolve(
            crate::protocol::RequestId::Number(2),
            Some(&json!({"name": TOOL})),
            None,
            scope,
        )
        .await;
    assert!(
        resolved.error.is_some(),
        "L9 resolve: anonymous resolved it: {resolved:?}"
    );
}

/// L9, surfaced list (plan rule: the caller sees NONE of the shared surfaced
/// entry): a SINGLE-USER gateway, an ANONYMOUS caller, a `required` per-user
/// backend whose [`TOOL`] is surfaced. The plain `tools/list` must not carry
/// the shared entry. May expose a real defect: a caller with no view keeping
/// the shared view (compare L6c, which pins that residual for a cold
/// IDENTIFIED caller only).
#[tokio::test]
async fn l9_required_backend_anonymous_caller_surfaced_list_sees_none() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    fx.meta.set_multi_user(false);
    let anonymous = super::anonymous_caller();
    let response = fx.meta.handle_tools_list_for_session(
        crate::protocol::RequestId::Number(1),
        None,
        anonymous.scope(),
    );
    let body = serde_json::to_value(&response).expect("a response serialises");
    let listed = body
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|t| t["name"] == super::slot_verdict_fixture::TOOL)
        });
    assert!(
        !listed,
        "L9 surfaced: an anonymous caller keeps the shared surfaced entry: {body}"
    );
}

/// A fixed catalogue served by one upstream, for a second per-user backend.
struct Fixed(serde_json::Value);

#[async_trait::async_trait]
impl crate::transport::Transport for Fixed {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"tools": self.0}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// L2 with two backends that have different bindings: `ledger_hub` (alpha's
/// slot `alpha@ledger`, valid for `read`) and `vault_hub` (alpha's slot
/// `alpha@vault`, INVALID for `read`); both shared slots hold a valid `read`.
/// The shared tracker has learned that both `read`s follow `ledger_hub:note`.
/// alpha is predicted `ledger_hub:read` and not `vault_hub:read`: each
/// prediction is judged by its own backend's slot, never one slot for both.
#[tokio::test]
async fn l2_predictions_judge_each_backends_slot() {
    use super::slot_verdict_fixture::BACKEND;
    use crate::backend::{Backend, PoolKey};
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    let tool = |schema: &serde_json::Value| -> serde_json::Value {
        json!({"name": "read", "description": "A vault tool.", "inputSchema": schema})
    };
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let vault = std::sync::Arc::new(Backend::new(
        "vault_hub",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "vault".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            input_schema_enforcement: CLOSED,
            ..Default::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    let shared: Vec<crate::protocol::Tool> =
        serde_json::from_value(json!([tool(&valid())])).expect("tools");
    vault.store_shared_tools_for_test(shared);
    vault.set_transport_for_test(std::sync::Arc::new(Fixed(json!([tool(&valid())]))));
    vault.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: "alpha@vault".to_string(),
        },
        std::sync::Arc::new(Fixed(json!([
            tool(&super::slot_verdict_fixture::invalid())
        ]))),
    );
    assert!(fx.meta.backends.register(vault), "second backend registers");
    warm_by_listing(&fx.meta).await;
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    fx.meta
        .list_tools(
            &json!({"server": "vault_hub"}),
            None,
            &super::identified_caller(&alpha),
        )
        .await
        .expect("alpha lists vault_hub");
    let tracker = std::sync::Arc::new(crate::transition::TransitionTracker::new());
    fx.meta
        .set_transition_tracker(std::sync::Arc::clone(&tracker));
    let from = format!("{BACKEND}:note");
    for _ in 0..8 {
        tracker.record_transition("teacher", &from);
        tracker.record_transition("teacher", &format!("{BACKEND}:read"));
        tracker.record_transition("teacher", &from);
        tracker.record_transition("teacher", "vault_hub:read");
    }
    let got = fx.meta.record_and_predict(
        None,
        Some("alpha-session"),
        &from,
        super::identified_caller(&alpha).scope(),
    );
    let predicted = |name: &str| got.iter().any(|p| p["tool"] == name);
    assert!(
        predicted("ledger_hub:read"),
        "premise: alpha's valid ledger tool is not predicted: {got:?}"
    );
    assert!(
        !predicted("vault_hub:read"),
        "L2: vault_hub:read is predicted from the wrong slot: {got:?}"
    );
}
