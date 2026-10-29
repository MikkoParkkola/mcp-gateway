// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The held-view rows on a failed or revoked account read: busy custody at
//! the re-check, a pre-pass that reads no binding, a revoke seen by the
//! re-check, and the optional backend's pin. Uses the parent's helpers.
use super::*;

/// A backend with no identity propagation, its shared slot holding one tool.
fn shared_backend(fx: &Fx) -> Arc<crate::backend::Backend> {
    let backend = Arc::new(crate::backend::Backend::new(
        "shared-ledger",
        crate::config::BackendConfig {
            enabled: true,
            transport: crate::config::TransportConfig::Http {
                http_url: "https://shared-ledger.invalid/mcp".to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let tool: crate::protocol::Tool =
        serde_json::from_value(json!({"name": "ledger_read", "inputSchema": {"type": "object"}}))
            .expect("a tool");
    backend.store_shared_tools_for_test(vec![tool]);
    assert!(
        fx.gateway.backends().register(Arc::clone(&backend)),
        "premise: the shared backend registers"
    );
    backend
}

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
    let fired = publish_old_after_revalidate(&fx, &old, |fx| {
        fx.gateway.fail_custody_for_test(false);
    });
    let answer = list_servers(&fx, 2).await;
    fx.gateway.fail_custody_for_test(false);
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
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
    fx.gateway.rearm_operator_slot_at_for_test(&new);
    let next = rpc(&fx, 3, "tools/list", json!({})).await;
    assert!(
        surfaced_on(&next, BACKEND)
            .iter()
            .any(|t| !is_shared_schema(t)),
        "R5: the next request with custody available did not show the current grant's tools: {next}"
    );
}

/// H1 setup: the old slot held and current, a `tools/list` parked before its
/// account pre-pass (its re-check has read the held binding), `between` run
/// in that window, then the listing finished.
async fn listing_with_prepass_window(between: impl AsyncFnOnce(&Fx)) -> Value {
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
    answer
}

/// H1a: re-check reads the old binding, the grant is revoked, the pre-pass
/// reads no view: the listing is cold, never the old catalogue. RED on base.
#[tokio::test]
async fn h1_a_prepass_that_reads_no_view_after_the_recheck_lists_cold() {
    let answer = listing_with_prepass_window(async |fx: &Fx| {
        fx.gateway.revoke_operator_grant().await;
    })
    .await;
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H1a: a pre-pass that read no view served the held old catalogue: {answer}"
    );
}

/// H1b: re-check reads the old binding, the pre-pass read is busy: the
/// listing is cold for that request. RED on base.
#[tokio::test]
async fn h1_a_busy_prepass_after_the_recheck_lists_cold() {
    let answer = listing_with_prepass_window(async |fx: &Fx| {
        fx.gateway.fail_custody_for_test(true);
    })
    .await;
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H1b: a busy pre-pass served the held catalogue unchecked: {answer}"
    );
}

/// H2: the re-check sees the revoke and records no view; a racing publish
/// of the old binding lands after it. The listing never serves it. RED on
/// base: the publish overwrites the no-view entry and nothing judges it.
#[tokio::test]
async fn h2_a_publish_racing_a_seen_revoke_is_not_served() {
    let fx = Arc::new(fixture().await);
    let old = fill_old(&fx, 1).await;
    fx.gateway.revoke_operator_grant().await;
    let fired = publish_old_after_revalidate(&fx, &old, |_| {});
    let answer = rpc(&fx, 2, "tools/list", json!({})).await;
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "premise: the after_revalidate seam fired and the old publish ran"
    );
    assert!(
        surfaced_on(&answer, BACKEND).is_empty(),
        "H2: a publish racing a revoke the re-check saw was served: {answer}"
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
