// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio twins of the cold-listing rows: split out of
//! `slot_verdict_g2_stdio.rs` to keep that file under its size ceiling; they
//! use the parent's fixture.
use super::*;

/// A rotated grant's slot is never a listing view (stdio twin of the HTTP
/// row). The operator's slot is warmed by a real `gateway_list_tools` fill
/// (schema A); the shared slot holds B. After rotation `tools/list` must not
/// serve the old slot, nor the shared view B: the backend has per-user
/// sessions only, so the now-cold caller's view is a fresh fill on the
/// current grant's own slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_list_never_serves_a_rotated_grants_slot_stdio() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = Arc::new(
        gateway
            .take_meta()
            .with_surfaced_tools(vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }]),
    );
    let backend = gateway.backends().get(BACKEND).expect("the backend");
    backend.store_shared_tools_for_test(vec![tool(TOOL, &valid())]);
    let stdio = Stdio {
        gateway,
        meta,
        tasks: None,
    };
    let filled = stdio
        .rpc(
            1,
            "tools/call",
            json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
        )
        .await;
    let old = DirectAccountGateway::operator_binding();
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: a real fill warmed the operator's slot: {filled}"
    );
    assert!(
        !stdio.listed_schema_has_folder(2).await,
        "premise: before rotation tools/list serves the caller's slot (schema A)"
    );
    stdio.gateway.rotate_operator_grant().await;
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: rotation leaves the old slot warm, so this is the listing's check"
    );
    // The rotated grant selects a new slot: attach its upstream there.
    let binding = stdio
        .meta
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    assert_ne!(binding, old, "premise: rotation selects a new slot");
    stdio.gateway.rearm_operator_slot_at_for_test(&binding);
    let fills = stdio.gateway.lists_to(BACKEND);
    assert!(
        !stdio.listed_schema_has_folder(3).await,
        "tools/list served the shared view B to a backend with per-user sessions only"
    );
    assert_eq!(
        stdio.gateway.lists_to(BACKEND),
        fills + 1,
        "the rotated caller's view was not re-established by a fresh fill"
    );
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&binding),
        "the fresh fill did not land on the current grant's own slot"
    );
}

/// SHARED.5 (`tools/list` only, stdio twin): the sole operator's first
/// listing of a backend with per-user sessions only shows its own schema,
/// from one fill of its own slot, and never the shared slot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cold_callers_first_tools_list_shows_its_own_schema_stdio() {
    let stdio = operator_stdio();
    assert!(
        !stdio.listed_schema_has_folder(1).await,
        "a cold caller was shown the shared schema"
    );
    assert_eq!(
        stdio.gateway.lists_to(BACKEND),
        1,
        "one fill of the caller's own slot"
    );
}

/// SHARED.5 (overlap, stdio twin): two overlapping listings of the cold sole
/// operator never show the shared schema, and its slot is filled once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_listings_of_a_cold_caller_fill_once_stdio() {
    let stdio = operator_stdio();
    let (a, b) = tokio::join!(
        stdio.listed_schema_has_folder(1),
        stdio.listed_schema_has_folder(2)
    );
    assert!(!a && !b, "a listing showed the shared schema");
    assert_eq!(
        stdio.gateway.lists_to(BACKEND),
        1,
        "the overlapping listings filled twice"
    );
}
