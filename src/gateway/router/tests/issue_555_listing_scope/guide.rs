// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 cells for the text a caller is handed rather than asks for: the
//! `initialize` instructions, the gateway guides and `/health`.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{Auth, fixture, fixture_with, rpc};

/// `initialize` params a legacy client sends.
pub(super) fn init() -> Value {
    json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "a3-cell", "version": "1" }
    })
}

async fn instructions(router: &axum::Router, key: &str) -> String {
    let body = rpc(router, Some(key), "initialize", init()).await;
    body["result"]["instructions"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize must carry instructions: {body}"))
        .to_string()
}

/// The routing-guide section, from its header to the end.
fn routing_section(text: &str) -> &str {
    text.find("Routing Guide").map_or("", |at| &text[at..])
}

/// T9 (ports b4323077's three guide cells): the initialize guide and its
/// preamble count follow the caller's scope.
#[tokio::test]
async fn initialize_guide_and_counts_follow_caller_scope() {
    let f = fixture(Auth::Keys).await;

    let alpha_only = instructions(&f.router, "alpha-only").await;
    assert!(
        !alpha_only.contains("caps/"),
        "guide names an unreachable backend: {alpha_only}"
    );
    assert!(
        alpha_only.contains("manages 1 tools across 1 backends"),
        "{alpha_only}"
    );

    let no_open = instructions(&f.router, "nocapopen-key").await;
    assert!(
        !no_open.contains("cap_open"),
        "guide names a withheld capability: {no_open}"
    );
    // alpha_read, beta_tool, cap_hidden: alpha_write is a policy denial and
    // cap_granted belongs to u1.
    assert!(
        no_open.contains("manages 3 tools across 3 backends"),
        "{no_open}"
    );

    // Control: a caller admitted to every capability gets today's guide.
    let caps = f
        .state
        .meta_mcp
        .get_capabilities()
        .expect("capability backend");
    let full = crate::gateway::meta_mcp_helpers::build_routing_instructions(
        &caps.list_capabilities(),
        &caps.name,
    );
    let u1 = instructions(&f.router, "u1").await;
    assert_eq!(
        routing_section(&u1),
        routing_section(&full),
        "control guide changed"
    );
}

/// T17 (green today): the guide resources name no inventory, so two gateways
/// with different catalogues serve them byte for byte.
#[tokio::test]
async fn guide_resources_are_catalogue_independent() {
    let full = fixture(Auth::Keys).await;
    let bare = fixture_with(Auth::Keys, |meta| meta.with_surfaced_tools(Vec::new())).await;
    let listed = rpc(&full.router, Some("open-key"), "resources/list", json!({})).await;
    let uris: Vec<String> = listed["result"]["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .filter(|u| u.starts_with("gateway://guides/"))
        .map(str::to_string)
        .collect();
    assert!(!uris.is_empty(), "the guides must be listed: {listed}");
    for uri in uris {
        let params = json!({ "uri": uri });
        let full_body = rpc(
            &full.router,
            Some("open-key"),
            "resources/read",
            params.clone(),
        )
        .await;
        let bare_body = rpc(&bare.router, Some("open-key"), "resources/read", params).await;
        assert_eq!(full_body, bare_body, "{uri} depends on the catalogue");
    }
}

/// T29: splitting "Cost tracking" keeps the cost-report docs for a caller
/// that is served `gateway_cost_report` and not `gateway_get_stats`.
#[tokio::test]
async fn cost_report_guide_survives_for_non_admin() {
    let f = fixture_with(Auth::Keys, |meta| {
        let config = crate::cost_accounting::config::CostGovernanceConfig::default();
        let registry =
            std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&config));
        let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
            config,
            std::sync::Arc::clone(&registry),
        ));
        meta.with_cost_governance(enforcer, registry)
            .with_expose_stats_tool(true)
    })
    .await;
    let body = rpc(
        &f.router,
        Some("open-key"),
        "resources/read",
        json!({ "uri": "gateway://guides/quickstart" }),
    )
    .await;
    let text = body.to_string();
    assert!(
        text.contains("gateway_cost_report"),
        "cost-report docs dropped: {body}"
    );
    assert!(
        !text.contains("gateway_get_stats"),
        "stats docs served to a non-admin: {body}"
    );
}

/// T27: a non-admin `/health` carries `status` and `version` and nothing else.
#[tokio::test]
async fn health_backend_count_is_admin_only() {
    let get = |router: axum::Router, key: Option<&'static str>| async move {
        let mut request = axum::http::Request::builder().uri("/health");
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = router
            .oneshot(request.body(axum::body::Body::empty()).expect("request"))
            .await
            .expect("health answers");
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice::<Value>(&body).expect("json")
    };
    let keys_of = |body: &Value| -> Vec<String> {
        let mut keys: Vec<String> = body.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        keys
    };
    let anon = fixture(Auth::Off).await;
    let keyed = fixture(Auth::Keys).await;
    for body in [
        get(anon.router.clone(), None).await,
        get(keyed.router.clone(), Some("open-key")).await,
    ] {
        assert_eq!(
            keys_of(&body),
            ["status", "version"],
            "non-admin /health: {body}"
        );
    }
    let admin = get(keyed.router.clone(), Some("admin-key")).await;
    assert!(
        admin["backends"].is_object() || admin["backends"].is_array(),
        "admin control: {admin}"
    );
}
