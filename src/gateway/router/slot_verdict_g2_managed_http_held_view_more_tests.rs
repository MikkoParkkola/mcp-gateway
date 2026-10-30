// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The held-view rows on a failed or revoked account read: busy custody at
//! the re-check, a pre-pass that reads no binding, a revoke seen by the
//! re-check, and the optional backend's pin. Uses the parent's helpers.
use super::*;

/// R5: the re-check's custody read is busy, then a publish of the old grant
/// lands, then the listing reads. The per-user backend's tools are hidden
/// for that request; a shared backend's still list. The next request, with
/// custody available, shows the current grant's own tools. RED on base: the
/// busy read records nothing, so the published old slot stands.
#[tokio::test]
async fn r5_a_busy_recheck_hides_per_user_tools_for_the_request() {
    let fx = Arc::new(fixture().await);
    shared_backend(&fx);
    let old = fill_old(&fx, 1).await;
    let new = rotate(&fx, &old).await;
    fx.gateway.fail_custody_for_test(true);
    // Custody recovers inside the seam, so the listing's own reads after the
    // re-check succeed and only the re-check saw busy.
    let (fired, answer) = publish_old_at_recheck(&fx, &old, list_servers_call(2), |fx| {
        fx.gateway.fail_custody_for_test(false);
    })
    .await;
    fx.gateway.fail_custody_for_test(false);
    assert!(
        fired,
        "premise: the after_revalidate seam fired and the old publish ran"
    );
    assert_eq!(
        server_entry(&answer, "shared-ledger").get("tools_known"),
        Some(&json!(true)),
        "R5: a shared backend's tools were hidden by a busy per-user re-check: {answer}"
    );
    let entry = server_entry(&answer, BACKEND);
    assert_eq!(
        entry.get("tools_known"),
        Some(&json!(false)),
        "R5: a busy re-check let the old grant's published catalogue list: {entry}"
    );
    assert_ne!(new, old, "premise: the rotated binding");
    // The next requests, custody available: the current grant's view lists.
    current_grant_lists(&fx, 3, "R5").await;
}

/// H1 setup: the old slot held and current, a `tools/list` parked before its
/// account pre-pass (its re-check has read the held binding), `between` run
/// in that window, then the listing finished.
async fn listing_with_prepass_window(between: impl AsyncFnOnce(&Fx)) -> (Arc<Fx>, Value) {
    let fx = Arc::new(fixture().await);
    fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let (reached, release) = backend.before_listing_prepass.arm();
    let listing = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    reached.notified().await;
    between(&fx).await;
    release.notify_one();
    let answer = listing.await.expect("the listing");
    fx.gateway.fail_custody_for_test(false);
    (fx, answer)
}

/// H1a: re-check reads the old binding, the grant is revoked, the pre-pass
/// reads no view: the listing is cold, never the old catalogue. RED on base.
#[tokio::test]
async fn h1_a_prepass_that_reads_no_view_after_the_recheck_lists_cold() {
    let (fx, answer) = listing_with_prepass_window(async |fx: &Fx| {
        fx.gateway.revoke_operator_grant().await;
    })
    .await;
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H1a: a pre-pass that read no view served the held old catalogue: {answer}"
    );
    fx.gateway.reconnect_operator_grant_for_test().await;
    current_grant_lists(&fx, 3, "H1a").await;
}

/// H1b: re-check reads the old binding, the pre-pass read is busy: the
/// listing is cold for that request. RED on base.
#[tokio::test]
async fn h1_a_busy_prepass_after_the_recheck_lists_cold() {
    let (fx, answer) = listing_with_prepass_window(async |fx: &Fx| {
        fx.gateway.fail_custody_for_test(true);
    })
    .await;
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H1b: a busy pre-pass served the held catalogue unchecked: {answer}"
    );
    current_grant_lists(&fx, 3, "H1b").await;
}

/// H2: the re-check sees the revoke and records no view; a racing publish
/// of the old binding lands after it. The listing never serves it. RED on
/// base: the publish overwrites the no-view entry and nothing judges it.
#[tokio::test]
async fn h2_a_publish_racing_a_seen_revoke_is_not_served() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    fx.gateway.revoke_operator_grant().await;
    let (fired, answer) =
        publish_old_at_recheck(&fx, &old, (2, "tools/list", json!({})), |_| {}).await;
    assert!(
        fired,
        "premise: the after_revalidate seam fired and the old publish ran"
    );
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H2: a publish racing a revoke the re-check saw was served: {answer}"
    );
}

/// H2 through `tools/resolve` (spec preview): the re-check sees the revoke,
/// a publish of the old binding lands after it, and `tools/resolve` (which
/// runs no pre-pass) must not resolve the old slot. Only the re-check's own
/// failed read can make the published slot read cold here.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn h2_tools_resolve_does_not_resolve_a_publish_racing_a_seen_revoke() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    fx.gateway.revoke_operator_grant().await;
    let (fired, answer) = publish_old_at_recheck(
        &fx,
        &old,
        (2, "tools/resolve", json!({"name": TOOL})),
        |_| {},
    )
    .await;
    assert!(
        fired,
        "premise: the after_revalidate seam fired and the old publish ran"
    );
    assert!(
        answer.pointer("/result/tool").is_none(),
        "H2 tools/resolve: a publish racing a revoke the re-check saw resolved: {answer}"
    );
}

/// An optional (`required: false`) per-user backend on the managed account,
/// the operator's slot on it held: no config compiles this (a managed
/// account is always `required`), so it is built directly.
fn optional_backend_held(fx: &Fx) -> (Arc<crate::backend::Backend>, String) {
    let backend = Arc::new(crate::backend::Backend::new(
        "optional-mail",
        crate::config::BackendConfig {
            enabled: true,
            account: Some("work-gmail".to_string()),
            identity_propagation: Some(crate::identity_propagation::IdentityPropagationConfig {
                strategy: crate::identity_propagation::PropagationStrategyKind::Vault,
                audience: "https://optional-mail.invalid/".to_string(),
                required: false,
                session_mode: crate::identity_propagation::SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            transport: crate::config::TransportConfig::Http {
                http_url: "https://optional-mail.invalid/mcp".to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let binding = DirectAccountGateway::operator_binding();
    let tool: crate::protocol::Tool =
        serde_json::from_value(json!({"name": "read", "inputSchema": {"type": "object"}}))
            .expect("a tool");
    backend.store_per_user_tools_for_test(&binding, vec![tool]);
    backend.record_caller_slot(&operator_id(), &binding);
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(binding.clone()),
        "premise: the operator's slot on the optional backend is held"
    );
    assert!(
        fx.gateway.backends().register(Arc::clone(&backend)),
        "premise: the optional backend registers"
    );
    (backend, binding)
}

/// Custody shut down, and the vault's read of the operator unavailable.
async fn custody_unavailable(fx: &Fx) {
    fx.gateway.shut_custody_for_test().await;
    let read = fx
        .state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding_classified(crate::personal_accounts::identity::Principal::SoleOperator)
        .await;
    assert!(
        matches!(read, crate::personal_accounts::ViewBinding::Unavailable(_)),
        "premise: the custody read is unavailable: {read:?}"
    );
}

/// Pin (green on base): an optional per-user backend whose custody read is
/// unavailable is never marked no-view by the re-check. Mutant: drop the
/// required-only rule from the no-view decision.
#[tokio::test]
async fn pin_an_optional_backends_unavailable_read_is_not_no_view() {
    let fx = fixture().await;
    let (backend, _) = optional_backend_held(&fx);
    custody_unavailable(&fx).await;
    fx.meta.revalidate_caller_slots(operator_proof()).await;
    assert!(
        !backend.caller_has_no_view(&operator_id()),
        "pin: an optional backend's unavailable read marked the caller no-view"
    );
}

/// Pin (green on base): a `required` backend whose custody read is
/// unavailable is marked no-view by the re-check, as a revoke is. Mutant:
/// drop Unavailable-as-no-view from the no-view decision.
#[tokio::test]
async fn pin_a_required_backends_unavailable_read_is_no_view() {
    let fx = fixture().await;
    fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    custody_unavailable(&fx).await;
    fx.meta.revalidate_caller_slots(operator_proof()).await;
    assert!(
        backend.caller_has_no_view(&operator_id()),
        "pin: a required backend's unavailable read did not mark the caller no-view"
    );
}

/// Arm the Meta-MCP with one routing profile, `name`, that limits nothing.
fn with_profile(name: &'static str) -> impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp) {
    move |meta| {
        let configs = std::collections::HashMap::from([(
            name.to_string(),
            crate::routing_profile::RoutingProfileConfig::default(),
        )]);
        let placeholder = crate::gateway::meta_mcp::MetaMcp::new(Arc::new(
            crate::backend::BackendRegistry::new(),
        ));
        let owned = std::mem::replace(meta, placeholder);
        *meta = owned.with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &configs, name,
        ));
    }
}

/// R7: after a rotation, a `gateway_set_profile` switch reads its caller's
/// new view for the change notice. That refresh must run the account
/// re-check first, so a publish of the old binding after it is judged
/// against the current grant. RED on base: the refresh runs no re-check, so
/// the `after_revalidate` seam never fires. The view itself is read only for
/// a session holding a listener record, which this fixture does not open.
#[tokio::test]
async fn r7_a_set_profile_refresh_rechecks_the_account_first() {
    let fx = Arc::new(fixture_armed(&Binding::Connected, with_profile("research")).await);
    let old = fill_old(&fx, 1).await;
    rotate(&fx, &old).await;
    let call = json!({"name": "gateway_set_profile", "arguments": {"profile": "research"}});
    let (fired, set) = publish_old_at_recheck(&fx, &old, (2, "tools/call", call), |_| {}).await;
    assert!(
        set.get("error").is_none() && set.pointer("/result/isError") != Some(&json!(true)),
        "premise: the profile switch succeeded, so its refresh runs: {set}"
    );
    assert!(
        fired,
        "R7: the set_profile refresh ran no account re-check (the after_revalidate seam never fired): {set}"
    );
}

/// The design's other half for the same ordering: the held slot is kept for
/// the next request (a failed read is not a finding). RED on base: the
/// re-check forgets any slot its read does not confirm.
#[tokio::test]
async fn an_optional_backends_unavailable_read_keeps_its_held_slot() {
    let fx = fixture().await;
    let (backend, binding) = optional_backend_held(&fx);
    custody_unavailable(&fx).await;
    fx.meta.revalidate_caller_slots(operator_proof()).await;
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(binding),
        "an unavailable read forgot the optional backend's held slot"
    );
}

/// R6a (spec preview): the old grant's slot was published before the
/// rotation; `tools/resolve` after it answers from the current grant's view
/// or cold, never the old slot. RED on base: `tools/resolve` runs no account
/// re-check, so the held slot stands.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn r6_tools_resolve_after_a_rotation_does_not_resolve_the_old_slot() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    rotate(&fx, &old).await;
    let answer = rpc(&fx, 2, "tools/resolve", json!({"name": TOOL})).await;
    assert!(
        answer.pointer("/result/tool").is_none(),
        "R6a: tools/resolve resolved the old grant's slot after the rotation: {answer}"
    );
}

/// R6b (spec preview): after the rotation, a publish of the old binding
/// lands after `tools/resolve`'s account re-check. RED on base: the re-check
/// does not run on `tools/resolve`, so the seam never fires.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn r6_tools_resolve_does_not_resolve_an_old_publish_after_its_recheck() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    rotate(&fx, &old).await;
    let (fired, answer) = publish_old_at_recheck(
        &fx,
        &old,
        (2, "tools/resolve", json!({"name": TOOL})),
        |_| {},
    )
    .await;
    assert!(
        fired,
        "R6b: tools/resolve ran no account re-check (the after_revalidate seam never fired): {answer}"
    );
    assert!(
        answer.pointer("/result/tool").is_none(),
        "R6b: tools/resolve resolved an old publish after its re-check: {answer}"
    );
}

/// Pin 8 (green on base): a `required` managed-account backend whose read is
/// a Bound binding the caller holds is not marked no-view by the re-check,
/// and a listing shows the caller's own catalogue for it. Mutant: the Bound
/// arm of the no-view decision answers no view.
#[tokio::test]
async fn pin8_a_required_backends_bound_read_is_not_no_view() {
    let fx = fixture().await;
    fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    fx.meta.revalidate_caller_slots(operator_proof()).await;
    assert!(
        !backend.caller_has_no_view(&operator_id()),
        "pin8: a Bound read on a required backend marked the caller no-view"
    );
    let listed = rpc(&fx, 2, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&listed, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "pin8: the listing did not show the caller's own catalogue: {listed}"
    );
}

/// R8: the re-check reads the old binding, the grant rotates, and a publish
/// of the new binding lands before the re-check judges. The re-check keeps
/// the concurrently published new slot (it compares what it captured, not
/// the index now), and the next listing shows the current grant's catalogue.
/// A name-only listing: a `tools/list` would refill and republish the slot
/// itself, hiding a forgotten one.
#[tokio::test]
async fn r8_a_recheck_keeps_a_new_slot_published_while_it_was_reading() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    let (reached, release) = seams::after_custody_read();
    let listing = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { list_servers(&fx, 2).await }
    });
    reached.notified().await;
    let new = rotate(&fx, &old).await;
    // A real fill of the new grant's slot, indexed through the writer gate.
    fx.gateway.rearm_operator_slot_at_for_test(&new);
    let filled = rpc(
        &fx,
        3,
        "tools/call",
        json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
    )
    .await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(new.clone()),
        "premise: the new grant's fill was indexed: {filled}"
    );
    release.notify_one();
    listing.await.expect("the listing");
    assert_eq!(
        backend.caller_slot_binding(&operator_id()),
        Some(new),
        "R8: the re-check forgot the new slot published while it was reading"
    );
    current_grant_lists(&fx, 4, "R8").await;
}

/// A deadline that cuts the account pre-pass short fails closed, even over a
/// held slot the re-check just confirmed: the listing's account check did not
/// complete, so the slot reads cold for that request.
#[tokio::test(start_paused = true)]
async fn a_cut_prepass_withholds_a_slot_the_recheck_confirmed() {
    let fx = Arc::new(fixture().await);
    fill_old(&fx, 1).await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    // Armed and never released: the pre-pass never runs, its deadline ends the step.
    let (reached, _held) = backend.before_listing_prepass.arm();
    let listing = tokio::spawn({
        let fx = Arc::clone(&fx);
        async move { rpc(&fx, 2, "tools/list", json!({})).await }
    });
    reached.notified().await;
    let answer = listing.await.expect("the listing");
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "a cut pre-pass served a held slot unchecked: {answer}"
    );
}
