// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 listing rows, variants by surface: the cold and anonymous
//! variants of the listing rows in `slot_verdict_listing_tests`, one row per
//! surface the test plan names.

use serde_json::json;

use super::slot_verdict_fixture::{
    CallerSlot, Surfaced, Warmth, per_user, predictions_for_alpha, predicts_tool, valid,
    warm_by_listing,
};
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

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
    // Single-user: a multi-user gateway leaves an isolated per-user backend
    // out of spec preview altogether (INV-2), so the row would pass unread.
    fx.meta.set_multi_user(false);
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let caller = super::identified_caller(&alpha);
    let scope = caller.scope();
    let warm = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    warm.meta.set_multi_user(false);
    warm_by_listing(&warm.meta).await;
    assert!(
        spec_lists_tool(&warm.meta, scope),
        "premise: a warm caller is listed in spec preview"
    );
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
    // Single-user, as L6a: spec preview reads the backend at all.
    fx.meta.set_multi_user(false);
    warm_by_listing(&fx.meta).await;
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    assert!(
        spec_lists_tool(&fx.meta, super::identified_caller(&alpha).scope()),
        "premise: alpha, warm, is listed in spec preview"
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

/// alpha's count phrase and its `list_servers` answer, once alpha's warm
/// slot is indexed by a real listing.
async fn counts_as_alpha(fx: &super::slot_verdict_fixture::PerUser) -> (String, serde_json::Value) {
    warm_by_listing(&fx.meta).await;
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let caller = super::identified_caller(&alpha);
    let (total, _) = fx.meta.admitted_counts(caller.scope(), None);
    let listed = fx
        .meta
        .list_servers(&caller, None)
        .await
        .expect("list_servers answers");
    (total.phrase(), listed)
}

/// K1 (known-ness reads the viewed slot): alpha's own slot is warm and its
/// count is exact. Whether the shared slot was ever listed changes nothing
/// alpha is told: the same count phrase, and `tools_known` true. RED before
/// the fix: known-ness reads the shared slot, so with it never listed the
/// count is not exact and `tools_known` is false beside a nonzero count.
#[tokio::test]
async fn k1_known_ness_reads_the_callers_slot_not_the_shared_one() {
    use super::slot_verdict_fixture::{SharedSlot, per_user_shared};
    let listed = counts_as_alpha(&per_user_shared(CallerSlot::Valid, SharedSlot::Listed)).await;
    let unlisted =
        counts_as_alpha(&per_user_shared(CallerSlot::Valid, SharedSlot::NeverListed)).await;
    assert!(
        listed.1.to_string().contains("\"tools_known\":true"),
        "premise: with both slots listed alpha's backend is known: {}",
        listed.1
    );
    assert_eq!(
        unlisted.0, listed.0,
        "K1: the count phrase reads the shared slot"
    );
    assert_eq!(
        unlisted.1, listed.1,
        "K1: list_servers reads the shared slot's known-ness"
    );
}

/// Whether spec preview's filtered `tools/list` names [`TOOL`] to `scope`.
#[cfg(feature = "spec-preview")]
fn spec_lists_tool(meta: &super::MetaMcp, scope: super::InvokeScope<'_>) -> bool {
    use super::slot_verdict_fixture::TOOL;
    let filtered =
        meta.handle_tools_list_filtered(crate::protocol::RequestId::Number(9), TOOL, None, scope);
    serde_json::to_value(&filtered)
        .expect("a response serialises")
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL))
}
