// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `required` per-user backend in search: discoverable for a caller with its
//! own slot, and for no one else (#2326). Split out for the file-size ceiling.
use super::*;

/// A `session_mode = per_user` MCP backend serving [`MCP_TOOLS`].
///
/// Identical to [`mcp_backend`] but for the propagation config, and it does not
/// assert the cache warmed: whether it warms is what the test asks.
async fn per_user_mcp_backend(name: &str) -> Arc<crate::backend::Backend> {
    let backend = cold_per_user_mcp_backend(name);
    let _ = backend.get_tools_shared().await;
    backend
}

/// [`per_user_mcp_backend`] with its shared tool cache never filled.
fn cold_per_user_mcp_backend(name: &str) -> Arc<crate::backend::Backend> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "aud".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let payload: Vec<Value> = MCP_TOOLS
        .iter()
        .map(|(n, d)| json!({ "name": n, "description": d, "inputSchema": { "type": "object" } }))
        .collect();
    backend.set_transport_for_test(Arc::new(ToolsListTestTransport {
        tools: json!(payload),
    }));
    backend
}

/// GIVEN a `session_mode = per_user`, `required` backend whose upstream
/// serves two tools
/// WHEN a caller with its own slot searches with a permissive profile
/// THEN both tools are discoverable, exactly as on the non-`per_user` control
/// [`permissive_profile_sees_the_mcp_backend_tools`]; an anonymous caller,
/// whose fetch would not carry an identity, finds neither (#2326).
#[tokio::test]
async fn per_user_backend_tools_are_discoverable() {
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(per_user_mcp_backend(MCP_BACKEND).await),
        "fixture backend failed to register"
    );
    let mut meta = MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(false)
    .with_profile_registry(registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    ));

    let anonymous = meta
        .search_tools_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();
    assert_eq!(
        tool_names(&anonymous),
        Vec::<String>::new(),
        "a `required` backend's tools reached a caller with no identity"
    );

    super::super::catalogue_per_caller_tests::install_minting(&mut meta);
    let alpha = super::super::catalogue_per_caller_tests::identity("alpha");
    meta.seed_caller_slot_for_test(MCP_BACKEND, &alpha).await;
    let response = meta
        .search_tools(
            &json!({ "query": QUERY }),
            None,
            &super::super::identified_caller(&alpha),
        )
        .await
        .unwrap();

    let mut names = tool_names(&response);
    names.sort();
    assert_eq!(
        names,
        vec!["weak_match".to_string(), QUERY.to_string()],
        "a per_user backend's tools must be discoverable, not blanked"
    );
}

/// #3042: an identified caller's search over an empty per-user slot fetches
/// with its own credential. It never starts the background fill of the
/// shared slot, whose `tools/list` would carry no identity at all.
#[tokio::test]
async fn a_bound_callers_search_does_not_fill_the_shared_slot() {
    let backend = cold_per_user_mcp_backend(MCP_BACKEND);
    let backends = Arc::new(BackendRegistry::new());
    assert!(backends.register(Arc::clone(&backend)));
    let mut meta = MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(false)
    .with_profile_registry(registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    ));
    super::super::catalogue_per_caller_tests::install_minting(&mut meta);
    let alpha = super::super::catalogue_per_caller_tests::identity("alpha");
    meta.seed_caller_slot_for_test(MCP_BACKEND, &alpha).await;

    meta.search_tools(
        &json!({ "query": QUERY }),
        None,
        &super::super::identified_caller(&alpha),
    )
    .await
    .unwrap();
    // A background fill, had one started, runs on this runtime: let it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !backend.cached_tools_known(),
        "a bound caller's search filled the shared slot without an identity"
    );
}
