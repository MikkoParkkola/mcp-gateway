// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 cells for the name-bearing fields the Appendix A sweep found beyond the
//! listing tools: predictions, cost suggestions, disabled capabilities, the
//! stats and webhook tools, profile patterns, the state count and playbook
//! step errors.

use axum::body::to_bytes;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

use super::meta_tools::payload;
use super::{Auth, call_tool, fixture, fixture_with, listed};

/// A legacy-path `tools/call` that carries (and returns) a session id, for
/// the handlers that read per-session state.
async fn session_call(
    router: &axum::Router,
    key: &str,
    session: Option<&str>,
    name: &str,
    arguments: Value,
) -> (Option<String>, Value) {
    let params = json!({ "name": name, "arguments": arguments });
    session_rpc(router, key, session, "tools/call", params).await
}

/// Any legacy-path method, carrying (and returning) a session id.
async fn session_rpc(
    router: &axum::Router,
    key: &str,
    session: Option<&str>,
    method: &str,
    params: Value,
) -> (Option<String>, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {key}"));
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 9, "method": method, "params": params }).to_string(),
        ))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        session,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

fn invoke(server: &str, tool: &str) -> Value {
    json!({ "server": server, "tool": tool, "arguments": { "q": "x" } })
}

/// T20: a prediction never names a tool the caller could not invoke, even
/// when another caller's traffic taught the tracker the transition.
#[tokio::test]
async fn predicted_next_is_scoped() {
    let f = fixture_with(Auth::Keys, |meta| meta).await;
    f.state
        .meta_mcp
        .set_transition_tracker(Arc::new(crate::transition::TransitionTracker::new()));
    let mut admin = None;
    for _ in 0..3 {
        for (server, tool) in [("alpha", "alpha_read"), ("beta", "beta_tool")] {
            let (sid, _) = session_call(
                &f.router,
                "admin-key",
                admin.as_deref(),
                "gateway_invoke",
                invoke(server, tool),
            )
            .await;
            admin = admin.or(sid);
        }
    }
    // Control: the admin's own next call is predicted to go to beta.
    let (_, control) = session_call(
        &f.router,
        "admin-key",
        admin.as_deref(),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        control.to_string().contains("beta_tool"),
        "control prediction: {control}"
    );

    let (_, scoped) = session_call(
        &f.router,
        "alpha-only",
        None,
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        !scoped.to_string().contains("beta_tool"),
        "prediction disclosed beta: {scoped}"
    );
}

/// T21: a cost suggestion never points at a tool the caller could not invoke.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn cost_suggestion_alternative_is_scoped() {
    let f = fixture_with(Auth::Keys, |meta| {
        let config = crate::cost_accounting::config::CostGovernanceConfig {
            enabled: true,
            tool_costs: HashMap::from([
                ("alpha_read".to_string(), 0.01),
                ("beta_tool".to_string(), 0.001),
            ]),
            alternatives: Some(HashMap::from([(
                "lookup".to_string(),
                vec!["alpha_read".to_string(), "beta_tool".to_string()],
            )])),
            ..Default::default()
        };
        let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&config));
        let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
            config,
            Arc::clone(&registry),
        ));
        meta.with_cost_governance(enforcer, registry)
    })
    .await;
    let admin = call_tool(
        &f.router,
        Some("admin-key"),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        admin.to_string().contains("_cost_suggestion"),
        "admin control: {admin}"
    );
    let scoped = call_tool(
        &f.router,
        Some("alpha-only"),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        !scoped.to_string().contains("beta_tool"),
        "suggested an unreachable tool: {scoped}"
    );
}

/// T22: the disabled-capability listing names only capabilities the caller
/// could invoke; its owner still sees why its own capability fails.
#[tokio::test]
async fn disabled_capabilities_are_scoped() {
    let f = fixture(Auth::Keys).await;
    let budget = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    f.state
        .meta_mcp
        .set_capability_budget_config(budget.clone());
    for _ in 0..10 {
        f.state
            .meta_mcp
            .kill_switch()
            .record_capability_failure("caps", "cap_granted", &budget);
    }
    let owner = payload(
        &call_tool(
            &f.router,
            Some("u1"),
            "gateway_list_disabled_capabilities",
            json!({}),
        )
        .await,
    );
    assert!(
        owner.to_string().contains("cap_granted"),
        "owner control: {owner}"
    );
    let other = payload(
        &call_tool(
            &f.router,
            Some("u2"),
            "gateway_list_disabled_capabilities",
            json!({}),
        )
        .await,
    );
    assert!(
        !other.to_string().contains("cap_granted"),
        "disclosed to u2: {other}"
    );
    assert_eq!(
        other["disabled_count"],
        json!(0),
        "count must exclude it: {other}"
    );
}

/// T23: the stats and webhook-status tools read other tenants' traffic, so
/// they are admin-only: withheld from a Standard caller's list and refused
/// by name, listed and dispatched for an admin.
#[tokio::test]
async fn stats_and_webhook_status_are_admin_only() {
    let f = fixture_with(Auth::Keys, |meta| meta.with_expose_stats_tool(true)).await;
    f.state
        .meta_mcp
        .set_webhook_registry(Arc::new(parking_lot::RwLock::new(
            crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
        )));
    let standard = listed(&f.router, Some("open-key")).await;
    let admin = listed(&f.router, Some("admin-key")).await;
    for tool in ["gateway_get_stats", "gateway_webhook_status"] {
        assert!(
            !standard.iter().any(|n| n == tool),
            "{tool} listed to Standard: {standard:?}"
        );
        assert!(
            admin.iter().any(|n| n == tool),
            "{tool} must stay listed to admin: {admin:?}"
        );
        let refused = call_tool(&f.router, Some("open-key"), tool, json!({})).await;
        let text = refused.to_string();
        assert!(
            text.contains("requires admin") || text.contains("Unknown tool"),
            "{tool} served to Standard: {refused}"
        );
        let served = call_tool(&f.router, Some("admin-key"), tool, json!({}))
            .await
            .to_string();
        assert!(
            !served.contains("requires admin") && !served.contains("Unknown tool"),
            "{tool} refused to admin: {served}"
        );
    }
}

/// T24: the profile tools do not hand a Standard caller the filter patterns,
/// which name tools it may not reach.
#[tokio::test]
async fn profile_patterns_hidden_from_non_admin() {
    let f = fixture_with(Auth::Keys, |meta| {
        let narrow = crate::routing_profile::RoutingProfileConfig {
            description: "No beta".to_string(),
            deny_tools: Some(vec!["beta_tool".to_string()]),
            ..Default::default()
        };
        let registry = crate::routing_profile::ProfileRegistry::from_config(
            &HashMap::from([("narrow".to_string(), narrow)]),
            "narrow",
        );
        meta.with_profile_registry(registry)
    })
    .await;
    let (sid, set) = session_call(
        &f.router,
        "open-key",
        None,
        "gateway_set_profile",
        json!({ "profile": "narrow" }),
    )
    .await;
    assert!(
        set.to_string().contains("narrow"),
        "set_profile control: {set}"
    );
    assert!(
        !set.to_string().contains("beta_tool"),
        "set_profile disclosed a pattern: {set}"
    );
    let (_, get) = session_call(
        &f.router,
        "open-key",
        sid.as_deref(),
        "gateway_get_profile",
        json!({}),
    )
    .await;
    assert!(
        !get.to_string().contains("beta_tool"),
        "get_profile disclosed a pattern: {get}"
    );
    let (_, admin) = session_call(
        &f.router,
        "admin-key",
        None,
        "gateway_get_profile",
        json!({}),
    )
    .await;
    assert!(
        admin.to_string().contains("beta_tool"),
        "admin control: {admin}"
    );
}

/// T26: `set_state` counts only capabilities the caller could invoke. Every
/// fixture capability is visible in every state, and `cap_granted` is u1's.
#[tokio::test]
async fn set_state_visible_tools_counts_admitted() {
    let f = fixture(Auth::Keys).await;
    let count = |body: &Value| payload(body)["visible_tools"].as_u64();
    let (_, owner) = session_call(
        &f.router,
        "u1",
        None,
        "gateway_set_state",
        json!({ "state": "s" }),
    )
    .await;
    assert_eq!(count(&owner), Some(3), "owner control: {owner}");
    let (_, other) = session_call(
        &f.router,
        "u2",
        None,
        "gateway_set_state",
        json!({ "state": "s" }),
    )
    .await;
    assert_eq!(
        count(&other),
        Some(2),
        "u2 was counted u1's capability: {other}"
    );
}

/// T30: a refused playbook step is recorded without naming its target.
#[tokio::test]
async fn playbook_step_refusal_names_nothing_withheld() {
    let f = fixture(Auth::Keys).await;
    let definition: crate::playbook::PlaybookDefinition = serde_yaml::from_str(
        "name: probe\ndescription: probe\non_error: continue\nsteps:\n  \
         - name: hidden\n    server: beta\n    tool: beta_tool\n    arguments: {}\n  \
         - name: open\n    server: alpha\n    tool: alpha_read\n    arguments: {}\n",
    )
    .expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    f.state.meta_mcp.set_playbook_engine(engine);
    let run = |key: &'static str| {
        let router = f.router.clone();
        async move {
            payload(
                &call_tool(
                    &router,
                    Some(key),
                    "gateway_run_playbook",
                    json!({ "name": "probe", "arguments": {} }),
                )
                .await,
            )
        }
    };
    let scoped = run("alpha-only").await;
    let reason = scoped["step_errors"]["hidden"]
        .as_str()
        .unwrap_or_else(|| panic!("step must fail: {scoped}"));
    assert_eq!(reason, "step not permitted for this caller", "{scoped}");
    assert!(
        !scoped.to_string().contains("beta"),
        "step error named the target: {scoped}"
    );
}

/// T5 (promoted variant): a tool promoted into a session's `tools/list` is
/// listed only while the caller could still invoke it. Here the session's
/// profile is narrowed after the promotion.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn promoted_tool_is_listed_only_while_invocable() {
    let f = fixture_with(Auth::Keys, |meta| {
        let narrow = crate::routing_profile::RoutingProfileConfig {
            deny_tools: Some(vec!["alpha_read".to_string()]),
            ..Default::default()
        };
        let profiles = HashMap::from([
            (
                "open".to_string(),
                crate::routing_profile::RoutingProfileConfig::default(),
            ),
            ("narrow".to_string(), narrow),
        ]);
        meta.with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles, "open",
        ))
    })
    .await;
    let key = "open-key";
    let (sid, promoted) = session_call(
        &f.router,
        key,
        None,
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        promoted.get("error").is_none(),
        "the promoting call must succeed: {promoted}"
    );
    let sid = sid.expect("a legacy call gets a session id");
    let (_, set) = session_call(
        &f.router,
        key,
        Some(&sid),
        "gateway_set_profile",
        json!({ "profile": "narrow" }),
    )
    .await;
    assert!(set.get("error").is_none(), "{set}");
    let (_, call) = session_call(
        &f.router,
        key,
        Some(&sid),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        super::refused(&call) || call.to_string().contains("profile"),
        "control: now refused: {call}"
    );
    let (_, listing) = session_rpc(&f.router, key, Some(&sid), "tools/list", json!({})).await;
    let names: Vec<&str> = listing["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list: {listing}"))
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        !names.contains(&"alpha_read"),
        "a promoted tool the caller can no longer invoke is listed: {names:?}"
    );
}
