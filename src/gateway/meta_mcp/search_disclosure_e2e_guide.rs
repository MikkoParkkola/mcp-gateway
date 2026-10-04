// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// Every `gateway_*` name mentioned in a guide's text.
fn guide_tool_names(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with("gateway_"))
        .map(str::to_string)
        .collect()
}

/// Read the gateway-owned routing guide as the given caller is served it.
async fn routing_guide_text(meta: &MetaMcp, standing: CallerStanding) -> String {
    let uri = json!({"uri": "gateway://guides/routing"});
    let response = meta
        .handle_resources_read(RequestId::Number(1), Some(&uri), standing, None, None)
        .await;
    response
        .result
        .and_then(|r| r.get("contents").and_then(Value::as_array).cloned())
        .and_then(|contents| contents.first().cloned())
        .and_then(|entry| {
            entry
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .expect("the routing guide resource must return text")
}

/// Acceptance clause C (routing guide agreement). The guide served at
/// `gateway://guides/routing` is projected through the same served set
/// `tools/list` answers from, so no caller is ever handed instructions for a
/// tool their own catalogue withholds — on either axis the surface narrows by.
///
/// Three surfaces, because "the guide names nothing" would satisfy a subset
/// assertion on its own. The admin default is the positive control: the guide
/// must still name the kill switch and every name in it must be listed. The
/// standard caller and the allow-listed operator are the two ways the surface
/// shrinks, and each is checked for subset *and* for the specific name that
/// had to disappear.
#[tokio::test]
async fn mik_7332_discovery_1_routing_guide_agrees_with_served_list() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry));

    // Positive control: the full surface keeps the guide whole.
    let named = guide_tool_names(&routing_guide_text(&meta, CallerStanding::Admin).await);
    assert!(
        named.contains("gateway_kill_server"),
        "an admin's routing guide must still document the kill switch: {named:?}"
    );
    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    for name in &named {
        assert!(
            listed.contains(name),
            "the routing guide names {name} but the served list withholds it: {listed:?}"
        );
    }

    // Standing axis: the same gateway, a caller without operator rights.
    let standard_named =
        guide_tool_names(&routing_guide_text(&meta, CallerStanding::Standard).await);
    assert!(
        !standard_named.contains("gateway_kill_server"),
        "a standard caller's guide must not document a tool they cannot run: {standard_named:?}"
    );
    assert!(
        !standard_named.is_empty(),
        "the guide must still route the tools this caller does have: {standard_named:?}"
    );
    let standard_listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(3),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Standard),
    ));
    for name in &standard_named {
        assert!(
            standard_listed.contains(name),
            "the guide names {name} to a caller whose list withholds it: {standard_listed:?}"
        );
    }

    // Exposure axis: an operator allow-list that hides most of the surface.
    let narrowed = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&[
        "gateway_invoke".to_string(),
        "gateway_search_tools".to_string(),
    ]);
    let narrowed_named =
        guide_tool_names(&routing_guide_text(&narrowed, CallerStanding::Admin).await);
    let narrowed_listed = listed_names(&narrowed.handle_tools_list_for_session(
        RequestId::Number(4),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    for name in &narrowed_named {
        assert!(
            narrowed_listed.contains(name),
            "the narrowed guide names {name}, which the allow-list withholds: {narrowed_listed:?}"
        );
    }
    let hidden = "gateway_list_profiles";
    assert!(
        !narrowed_named.contains(hidden),
        "the guide must drop the section naming {hidden}: {narrowed_named:?}"
    );
    // And the tool the guide no longer names is genuinely unreachable, so the
    // text was removed because the surface shrank, not merely edited.
    let refused = Box::pin(narrowed.handle_tools_call(
        RequestId::Number(5),
        hidden,
        json!({}),
        None,
        admin_ctx(&AllowAll),
    ))
    .await;
    let err = refused
        .error
        .expect("a tool outside the allow-list must refuse");
    assert_eq!(err.code, -32601, "{}", err.message);
}

/// A capability YAML naming one REST provider, with the given input schema.
fn capability_yaml(name: &str, input_type: &str) -> String {
    format!(
        "name: {name}\n\
         description: A surfaced capability used to prove per-tool degradation.\n\
         schema:\n  \
           input:\n    \
             type: {input_type}\n    \
             properties:\n      \
               q:\n        \
                 type: string\n\
         providers:\n  \
           primary:\n    \
             service: rest\n    \
             config:\n      \
               base_url: https://rest.invalid\n      \
               path: /{name}\n"
    )
}

/// Acceptance clause D (invalid schema withheld, healthy tools remain). A
/// capability whose `schema.input.type` is not `object` fails structural
/// validation with a CAP-003 error, and the loader skips that definition alone
/// (`capability/loader.rs:146`). This asserts the degradation is per-tool: the
/// broken tool is absent from the capability backend, absent from the served
/// `tools/list`, and refuses invocation, while its schema-valid sibling on the
/// same backend stays listed and routable. The sibling's execution stops at
/// routing — running it would issue the REST call its provider declares.
#[tokio::test]
async fn mik_7332_discovery_1_invalid_schema_tool_withheld_backend_survives() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("healthy.yaml"),
        capability_yaml("healthy_cap", "object"),
    )
    .expect("write healthy capability");
    std::fs::write(
        dir.path().join("broken.yaml"),
        capability_yaml("broken_cap", "string"),
    )
    .expect("write broken capability");

    let capabilities = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let loaded = capabilities
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("a backend with one invalid definition must still load");
    assert_eq!(
        loaded, 1,
        "only the schema-valid capability may load; the backend must not be dropped whole"
    );
    assert!(capabilities.has_capability("healthy_cap"));
    assert!(
        !capabilities.has_capability("broken_cap"),
        "the invalid-schema capability must be withheld"
    );

    // Control: the same definition, with only `schema.input.type` corrected,
    // loads. Without it this test would pass for any load failure at all.
    let control_dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        control_dir.path().join("broken.yaml"),
        capability_yaml("broken_cap", "object"),
    )
    .expect("write control capability");
    let control = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    assert_eq!(
        control
            .load_from_directory(control_dir.path().to_str().expect("utf-8 path"))
            .await
            .expect("the control definition must load"),
        1,
        "only the input schema may decide whether this definition loads"
    );

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "caps".to_string(),
                tool: "healthy_cap".to_string(),
            },
            SurfacedToolConfig {
                server: "caps".to_string(),
                tool: "broken_cap".to_string(),
            },
        ])
        .with_exposed_meta_tools(&["gateway_invoke".to_string()]);
    meta.set_capabilities(Arc::clone(&capabilities));

    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        listed.contains(&"healthy_cap".to_string()),
        "the healthy tool of the same backend must remain listed: {listed:?}"
    );
    assert!(
        !listed.contains(&"broken_cap".to_string()),
        "the invalid-schema tool must not be disclosed: {listed:?}"
    );

    assert!(
        capabilities
            .call_tool("broken_cap", json!({"q": "x"}))
            .await
            .is_err(),
        "the withheld tool must not be invocable either"
    );
}

/// Acceptance clause D, MCP-backend half. A capability is validated as it is
/// read off disk, so a malformed `schema.input` never reaches the surface. A
/// backend's tools arrive over the wire instead, and until this test the
/// gateway surfaced whatever a backend sent: a tool whose `inputSchema` is not
/// an object is a tool no client can build a call against, disclosed anyway.
///
/// Same verdict, same degradation shape as the capability path above: the one
/// bad tool is withheld from `tools/list` and refused by name, its healthy
/// sibling on the same backend stays listed and still routes, and the backend
/// itself is not dropped. The healthy control is what separates "the schema
/// decided this" from "the backend fell over".
#[tokio::test]
async fn mik_7332_discovery_1_invalid_schema_backend_tool_withheld_siblings_survive() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = served_surface_backend(
        "wire",
        vec![
            tool(
                "healthy_wire",
                "A backend tool whose input schema is a proper object.",
                json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            ),
            // `type: string` is the same CAP-003 error the capability loader
            // refuses a definition for.
            tool(
                "broken_wire",
                "A backend tool whose input schema is not an object.",
                json!({"type": "string", "properties": {"q": {"type": "string"}}}),
            ),
        ],
        Arc::clone(&calls),
    )
    .await;

    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(Arc::clone(&backend));
    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "wire".to_string(),
                tool: "healthy_wire".to_string(),
            },
            SurfacedToolConfig {
                server: "wire".to_string(),
                tool: "broken_wire".to_string(),
            },
        ])
        .with_exposed_meta_tools(&["gateway_invoke".to_string()]);

    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        listed.contains(&"healthy_wire".to_string()),
        "the healthy tool of the same backend must remain listed: {listed:?}"
    );
    assert!(
        !listed.contains(&"broken_wire".to_string()),
        "a structurally invalid input schema must not be disclosed: {listed:?}"
    );
    assert!(
        backend.has_cached_tools(),
        "one bad tool must not take the backend down with it"
    );

    // Unlisted and uninvocable are the same claim read two ways. The refusal
    // is worded like the unrecognised-tool fallback so it does not confirm the
    // existence of a tool the gateway declined to publish, and the backend
    // must never have been reached.
    let refused = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "broken_wire",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let err = refused
        .error
        .expect("a tool withheld from the catalogue must not execute");
    assert_eq!(err.code, -32601, "{}", err.message);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refusal must land before the backend is asked"
    );

    let ran = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "healthy_wire",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    assert!(
        ran.error.is_none(),
        "the sibling must still route through the same path: {ran:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the healthy sibling must reach the backend"
    );
}
