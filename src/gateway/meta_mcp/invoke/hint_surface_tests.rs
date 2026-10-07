// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7974.REVIVE.1: a circuit-breaker hint names `gateway_revive_server`
//! only to a caller who can list and call it.

use serde_json::Value;

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::recovery::SurfaceRequest;

/// The hint a caller gets for a call to `alpha` while its breaker is open.
async fn breaker_hint(exposed: Option<&[&str]>, is_admin: bool) -> String {
    let (registry, _calls) = counted_backend("alpha");
    registry
        .get("alpha")
        .expect("alpha is registered")
        .trip_circuit_breaker("mik-7974");
    let mut meta = MetaMcp::new(registry);
    if let Some(names) = exposed {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        meta = meta.with_exposed_meta_tools(&names);
    }
    let caller = MetaMcpCallerContext {
        is_admin,
        ..ctx(&AllowAll)
    };
    let answer: Value = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &caller)
        .await
        .expect("a tool result");
    answer["recovery"]["suggest"]
        .as_str()
        .unwrap_or_else(|| panic!("no recovery hint in {answer}"))
        .to_owned()
}

#[tokio::test]
async fn an_admin_who_can_see_revive_is_pointed_at_it() {
    let hint = breaker_hint(None, true).await;
    assert!(hint.contains("`gateway_revive_server`"), "{hint}");
}

#[tokio::test]
async fn a_non_admin_is_not_pointed_at_revive() {
    let hint = breaker_hint(None, false).await;
    assert!(
        !hint.contains("gateway_revive_server") && hint.contains("Wait for the circuit breaker"),
        "REVIVE.1 non-admin: {hint}"
    );
}

#[tokio::test]
async fn revive_hidden_by_exposed_meta_tools_is_not_named() {
    let exposed = [
        "gateway_list_tools",
        "gateway_invoke",
        "gateway_list_servers",
    ];
    let hint = breaker_hint(Some(&exposed), true).await;
    assert!(
        !hint.contains("gateway_revive_server") && hint.contains("Wait for the circuit breaker"),
        "REVIVE.1 hidden: {hint}"
    );
}

/// MIK-7974: a chain step's context keeps the request's surface.
#[test]
fn with_retry_keeps_the_surface_request() {
    let caller = MetaMcpCallerContext {
        surface_request: SurfaceRequest::CodeMode,
        ..ctx(&AllowAll)
    };
    assert_eq!(
        caller
            .with_retry(&crate::protocol::mrtr::NO_RETRY)
            .surface_request,
        SurfaceRequest::CodeMode
    );
}
