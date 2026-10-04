// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

// ============================================================================
// MIK-7332.DISCOVERY.1 — authorization-derived exposure, tiered disclosure,
// schema validity and configured surfaced tools together on the served
// consumer surface, with the disclosed set matching the invocable set.
// ============================================================================

/// A backend transport that answers both `tools/list` (from a fixed
/// catalogue, to warm the cache real `tools/list` handling reads) and
/// `tools/call` (counting the calls that actually reach it), so one fixture
/// can prove a tool's disclosure and its invocation agree.
struct ServedSurfaceTransport {
    list_response: JsonRpcResponse,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for ServedSurfaceTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        match method {
            "tools/list" => Ok(self.list_response.clone()),
            "tools/call" => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(JsonRpcResponse::success_serialized(
                    RequestId::Number(1),
                    json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                ))
            }
            other => panic!("unexpected method {other}"),
        }
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

async fn served_surface_backend(
    name: &str,
    tools: Vec<Tool>,
    calls: Arc<AtomicUsize>,
) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let list_response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools,
            next_cursor: None,
        },
    );
    let transport: Arc<dyn Transport> = Arc::new(ServedSurfaceTransport {
        list_response,
        calls,
    });
    backend.set_transport_for_test(transport);
    backend.get_tools_shared().await.unwrap();
    backend
}

/// Traditional-mode surface: `tools/list` composes the meta-tool exposure
/// allow-list, the routing profile, configured surfaced tools and the
/// trust-card schema projection in one response
/// (`MetaMcp::handle_tools_list_for_session`). This asserts the disclosed
/// set is exactly what the same fixture's `tools/call` will actually run —
/// for BOTH directions: a hidden tool must refuse, and a disclosed one must
/// not be accidentally refused too.
#[allow(clippy::too_many_lines)] // one end-to-end trace; splitting it would hide the sequence
#[tokio::test]
async fn mik_7332_discovery_1_listed_set_matches_invocable_set() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let valid_schema = json!({
        "type": "object",
        "properties": { "q": { "type": "string" } },
        "required": ["q"]
    });
    let _ = registry.register(
        served_surface_backend(
            "alpha",
            vec![
                tool(
                    "public_tool",
                    "A publicly surfaced tool.",
                    valid_schema.clone(),
                ),
                tool(
                    "denied_tool",
                    "A tool the default profile denies.",
                    valid_schema,
                ),
            ],
            Arc::clone(&calls),
        )
        .await,
    );

    let mut profiles: HashMap<String, RoutingProfileConfig> = HashMap::new();
    profiles.insert(
        "restricted".to_string(),
        RoutingProfileConfig {
            description: "Denies denied_tool".to_string(),
            deny_tools: Some(vec!["denied_tool".to_string()]),
            ..Default::default()
        },
    );
    let profile_registry = ProfileRegistry::from_config(&profiles, "restricted");

    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_profile_registry(profile_registry)
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "alpha".to_string(),
                tool: "public_tool".to_string(),
            },
            SurfacedToolConfig {
                server: "alpha".to_string(),
                tool: "denied_tool".to_string(),
            },
        ])
        .with_exposed_meta_tools(&[
            "gateway_invoke".to_string(),
            "gateway_search_tools".to_string(),
        ]);

    // --- Disclosure: tools/list ---
    let listed = meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    );
    let tools = listed
        .result
        .expect("tools/list must return a result")
        .get("tools")
        .cloned()
        .expect("result must have a tools array");
    let tools = tools.as_array().expect("tools must be an array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();

    assert!(
        names.contains(&"public_tool"),
        "the allowed surfaced tool must be listed: {names:?}"
    );
    assert!(
        !names.contains(&"denied_tool"),
        "the profile-denied surfaced tool must NOT be listed: {names:?}"
    );
    assert!(
        names.contains(&"gateway_invoke") && names.contains(&"gateway_search_tools"),
        "exposed meta-tools must be listed: {names:?}"
    );
    assert!(
        !names.contains(&"gateway_list_servers"),
        "a meta-tool outside the exposure allow-list must NOT be listed: {names:?}"
    );

    // --- Schema validity, on the SAME response ---
    let public_entry = tools
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some("public_tool"))
        .expect("public_tool must be in the listing");
    let input_schema = public_entry
        .get("inputSchema")
        .expect("published tool must carry inputSchema");
    if let Err(err) = jsonschema::meta::validate(input_schema) {
        panic!("public_tool's published inputSchema is not valid JSON Schema 2020-12: {err}");
    }
    assert!(
        public_entry
            .get("trustCard")
            .and_then(|tc| tc.get("schemaBounds"))
            .is_some(),
        "a backend-forwarded descriptor must carry the schema-bounds verdict beside it: {public_entry:?}"
    );

    // --- Invocation permission: the hidden meta-tool must refuse exactly
    // like an unrecognised name, and the surfaced-but-denied tool must
    // refuse without ever reaching the backend. ---
    let hidden_meta = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "gateway_list_servers",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let hidden_err = hidden_meta.error.expect("a hidden meta-tool must refuse");
    assert_eq!(hidden_err.code, -32601);
    assert!(
        hidden_err
            .message
            .ends_with("Unknown tool: gateway_list_servers"),
        "{}",
        hidden_err.message
    );

    let unrecognised = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "gateway_zzz_nonexistent",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let un_err = unrecognised.error.expect("a nonexistent tool must refuse");
    assert_eq!(
        un_err.code, hidden_err.code,
        "a hidden tool and a genuinely nonexistent one must refuse identically"
    );
    assert!(
        un_err
            .message
            .ends_with("Unknown tool: gateway_zzz_nonexistent"),
        "{}",
        un_err.message
    );

    let denied_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(4),
        "denied_tool",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    assert!(
        denied_call.error.is_some(),
        "a tool hidden from discovery by the routing profile must not be invocable directly: {denied_call:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the denied call must never reach the backend"
    );

    let allowed_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(5),
        "public_tool",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    assert!(
        allowed_call.error.is_none(),
        "the listed, allowed surfaced tool must actually run: {allowed_call:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must reach the backend exactly once"
    );
}

/// Code Mode surface: `gateway_search`'s tiered disclosure (L0 drops
/// disabled/killed tools; a profile-denied tool is invisible at every tier
/// because it never becomes a match at all) composes with authorization in
/// `code_mode_search`/`collect_code_mode_backend_matches`. This asserts the
/// disclosure difference is not cosmetic: a killed tool refuses
/// `gateway_execute` regardless of the tier that revealed it, a
/// profile-denied one refuses too, and the plain visible one actually runs.
#[allow(clippy::too_many_lines)] // one end-to-end trace; splitting it would hide the sequence
#[tokio::test]
async fn mik_7332_discovery_1_disclosure_tiers_agree_with_invocation() {
    let registry = Arc::new(BackendRegistry::new());
    let schema = json!({"type": "object", "properties": {}});
    // `alpha` must actually answer `tools/call` — its invocation is expected
    // to succeed, unlike `beta`/`gamma` below, which are refused before
    // dispatch ever reaches their (list-only) transport.
    let _ = registry.register(
        served_surface_backend(
            "alpha",
            vec![tool(
                "alpha_tool",
                "Alive backend tool. [keywords: widget]",
                schema.clone(),
            )],
            Arc::new(AtomicUsize::new(0)),
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "beta",
            vec![tool(
                "beta_tool",
                "Killed backend tool. [keywords: widget]",
                schema.clone(),
            )],
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "gamma",
            vec![tool(
                "gamma_tool",
                "Profile-denied tool. [keywords: widget]",
                schema,
            )],
        )
        .await,
    );

    let mut profiles: HashMap<String, RoutingProfileConfig> = HashMap::new();
    profiles.insert(
        "default".to_string(),
        RoutingProfileConfig {
            description: "Denies gamma_tool".to_string(),
            deny_tools: Some(vec!["gamma_tool".to_string()]),
            ..Default::default()
        },
    );
    let profile_registry = ProfileRegistry::from_config(&profiles, "default");

    let meta = MetaMcp::with_features(
        Arc::clone(&registry),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_profile_registry(profile_registry);
    meta.kill_switch().kill("beta");

    // --- L0: killed AND denied tools are both absent, for different reasons.
    let l0 = meta
        .code_mode_search_anon(&json!({ "query": "*_tool", "limit": 10 }), None)
        .await
        .unwrap();
    let l0_names: Vec<&str> = l0["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["tool"].as_str())
        .collect();
    assert!(
        l0_names.iter().any(|n| n.contains("alpha_tool")),
        "the alive, allowed tool must appear at L0: {l0_names:?}"
    );
    assert!(
        !l0_names.iter().any(|n| n.contains("beta_tool")),
        "a killed tool must be dropped at L0: {l0_names:?}"
    );
    assert!(
        !l0_names.iter().any(|n| n.contains("gamma_tool")),
        "a profile-denied tool must never appear, even at L0: {l0_names:?}"
    );

    // --- L1: the killed tool reappears (with its disabled status); the
    // profile-denied one still does not — proving the two absences are
    // different mechanisms, not the same filter under two names.
    let l1 = meta
        .code_mode_search_anon(
            &json!({ "query": "*_tool", "limit": 10, "detail": "l1" }),
            None,
        )
        .await
        .unwrap();
    let l1_matches = l1["matches"].as_array().unwrap();
    let beta_at_l1 = l1_matches
        .iter()
        .find(|m| m["tool"].as_str().is_some_and(|n| n.contains("beta_tool")));
    assert!(
        beta_at_l1.is_some(),
        "a killed (not denied) tool must be visible at L1: {l1_matches:?}"
    );
    assert_eq!(
        beta_at_l1.unwrap().get("status").and_then(Value::as_str),
        Some("disabled"),
        "and must carry the disabled status: {beta_at_l1:?}"
    );
    assert!(
        !l1_matches
            .iter()
            .any(|m| m["tool"].as_str().is_some_and(|n| n.contains("gamma_tool"))),
        "the profile-denied tool must still be absent at L1: {l1_matches:?}"
    );

    // --- Invocation: agrees with disclosure in both directions.
    let beta_call = meta
        .code_mode_execute(
            &json!({ "tool": "beta:beta_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        beta_call.is_err(),
        "a killed tool must refuse gateway_execute even though L1 disclosed it: {beta_call:?}"
    );

    let gamma_call = meta
        .code_mode_execute(
            &json!({ "tool": "gamma:gamma_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        gamma_call.is_err(),
        "a profile-denied tool must refuse gateway_execute: {gamma_call:?}"
    );

    let alpha_call = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:alpha_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        alpha_call.is_ok(),
        "the tool visible at L0 must actually run: {alpha_call:?}"
    );
}

/// Names disclosed by a `tools/list` response, in order.
fn listed_names(response: &JsonRpcResponse) -> Vec<String> {
    response
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .expect("tools/list must return a tools array")
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The same caller context as [`ctx`], holding admin.
fn admin_ctx(
    authorizer: &(dyn crate::gateway::authz::ToolAuthorizer + Sync),
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        is_admin: true,
        ..ctx(authorizer)
    }
}

/// Acceptance clause A (admin/nonadmin axis). Disclosure and dispatch answer
/// the admin question from one predicate, `CallerStanding::permits`
/// (`router::authorization`), so the served list and the invocable set agree on
/// both sides of the axis: a standard caller is neither shown nor served
/// `gateway_kill_server`, an admin is shown it and may run it.
///
/// The control is the second listing. Asserting only that the standard caller
/// is missing the tool would pass for a build that lists nothing at all, or
/// for a `permits` that answers `false` to every name; the admin listing of the
/// same `MetaMcp`, with the same allow-list, is what makes standing the only
/// thing that differs.
#[tokio::test]
async fn mik_7332_discovery_1_admin_axis_disclosure_versus_invocation() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&[
        "gateway_invoke".to_string(),
        "gateway_kill_server".to_string(),
    ]);

    let standard = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Standard),
    ));
    assert!(
        !standard.contains(&"gateway_kill_server".to_string()),
        "a standard caller must not be shown the admin-only meta-tool: {standard:?}"
    );
    assert!(
        standard.contains(&"gateway_invoke".to_string()),
        "the standing filter must remove the admin tool and nothing else: {standard:?}"
    );

    let admin = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        admin.contains(&"gateway_kill_server".to_string()),
        "the same allow-list must disclose the admin tool to an admin: {admin:?}"
    );

    // The invocation half of the same axis, unchanged by the filter: the
    // refusal a standard caller meets is still the admin gate's, worded as it
    // always was. Dispatch is the authority the listing is derived from, so
    // this is what the two assertions above are agreeing *with*.
    let nonadmin_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "gateway_kill_server",
        json!({"server": "alpha"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let err = nonadmin_call
        .error
        .expect("a nonadmin must be refused an admin meta-tool");
    assert_eq!(err.code, -32600, "{}", err.message);
    assert!(
        err.message.contains("requires admin access"),
        "the refusal must name the admin gate, not a routing failure: {}",
        err.message
    );

    let admin_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(4),
        "gateway_kill_server",
        json!({"server": "alpha"}),
        None,
        admin_ctx(&AllowAll),
    ))
    .await;
    assert!(
        !admin_call
            .error
            .as_ref()
            .is_some_and(|e| e.message.contains("requires admin access")),
        "the same call from an admin must pass the gate: {admin_call:?}"
    );
}

/// Acceptance clause B (configured/unconfigured features). `gateway_get_stats`
/// is gated at disclosure by `meta_mcp.expose_stats_tool` and at invocation by
/// the collector `Option` (`invoke.rs:3206`). "Unconfigured" is a deployment
/// that set neither, "configured" one that set both. This asserts both ends
/// move together for that operator: unconfigured contributes nothing to the
/// served list and refuses, configured appears and runs.
#[tokio::test]
async fn mik_7332_discovery_1_unconfigured_feature_neither_listed_nor_invocable() {
    let exposure = ["gateway_get_stats".to_string()];
    let registry = Arc::new(BackendRegistry::new());

    let unconfigured = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&exposure);
    let listed = listed_names(&unconfigured.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        !listed.contains(&"gateway_get_stats".to_string()),
        "an unconfigured feature must contribute nothing to the served list: {listed:?}"
    );
    let refused = Box::pin(unconfigured.handle_tools_call(
        RequestId::Number(2),
        "gateway_get_stats",
        json!({}),
        None,
        admin_ctx(&AllowAll), // admin-only since A3; the refusal is the feature's
    ))
    .await;
    let err = refused
        .error
        .expect("an unconfigured feature's tool must not execute");
    assert!(
        err.message.contains("Statistics not enabled"),
        "{}",
        err.message
    );

    let configured = MetaMcp::with_features(
        Arc::clone(&registry),
        None,
        Some(Arc::new(crate::stats::UsageStats::new())),
        None,
        Duration::from_secs(60),
    )
    .with_exposed_meta_tools(&exposure)
    .with_expose_stats_tool(true);
    let listed = listed_names(&configured.handle_tools_list_for_session(
        RequestId::Number(3),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        listed.contains(&"gateway_get_stats".to_string()),
        "configuring the feature must surface its tool: {listed:?}"
    );
    let ran = Box::pin(configured.handle_tools_call(
        RequestId::Number(4),
        "gateway_get_stats",
        json!({}),
        None,
        admin_ctx(&AllowAll),
    ))
    .await;
    assert!(
        ran.error.is_none(),
        "the surfaced tool must actually execute: {ran:?}"
    );
}
#[cfg(test)]
#[path = "search_disclosure_e2e_guide.rs"]
mod guide;
