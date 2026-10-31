// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Both gateway refusals are raised before anything is sent, at the reviewed
//! sites the pre-send scan holds, so both read as never sent. The composite
//! rows (a late refusal keeps its code and its run's key) are on the route:
//! `router/late_refusal_lease_tests.rs`.

#[test]
fn the_gateway_refusals_read_as_never_sent() {
    let denial = crate::Error::Forbidden {
        code: -32003,
        status: 403,
        message: "refused".into(),
    };
    assert!(denial.is_pre_dispatch(), "a denial reads as may have run");
    let refusal = crate::Error::gateway_refused(-32000, "switched off by the operator");
    assert!(
        refusal.is_pre_dispatch(),
        "a gateway refusal reads as may have run"
    );
}

/// A playbook named `name` with one step, `server`/`tool`, on `meta`.
fn one_step(meta: &crate::gateway::meta_mcp::MetaMcp, name: &str, server: &str, tool: &str) {
    let mut engine = crate::playbook::PlaybookEngine::new();
    let definition = serde_json::json!({
        "playbook": "1.0", "name": name, "description": "one step",
        "steps": [{"name": "only", "server": server, "tool": tool, "arguments": {}}],
    });
    engine.register(serde_json::from_value(definition).expect("the playbook parses"));
    meta.set_playbook_engine(engine);
}

/// The answer as JSON.
fn wire(response: &crate::protocol::JsonRpcResponse) -> serde_json::Value {
    serde_json::to_value(response).expect("response is JSON")
}

/// A step the routing profile refuses gets the neutral step refusal (A3):
/// -32003, and neither the step's server nor its tool is named.
#[tokio::test]
async fn a_step_the_profile_refuses_is_answered_neutrally() {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let (registry, calls) = crate::gateway::meta_mcp::authz_tests::counted_backend("alpha");
    let profiles = std::collections::HashMap::from([(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".into()]),
            ..RoutingProfileConfig::default()
        },
    )]);
    let meta = crate::gateway::meta_mcp::MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&profiles, "restricted"));
    one_step(&meta, "profiled", "alpha", "read");
    let answer = wire(
        &Box::pin(meta.handle_tools_call(
            crate::protocol::RequestId::Number(1),
            "gateway_run_playbook",
            serde_json::json!({"name": "profiled"}),
            None,
            crate::gateway::meta_mcp::authz_tests::ctx(&crate::gateway::authz::AllowAll),
        ))
        .await,
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "premise: not sent"
    );
    assert_eq!(
        answer["error"]["message"],
        crate::gateway::meta_mcp::STEP_NOT_PERMITTED,
        "{answer}"
    );
    assert_eq!(answer["error"]["code"], -32003, "{answer}");
}

/// A step on a personal capability the caller holds no grant for gets the
/// neutral step refusal too, and nothing reaches the capability.
#[tokio::test]
async fn a_step_the_identity_grant_refuses_is_answered_neutrally() {
    use crate::gateway::meta_mcp::grant_audit_fixture::{
        CAPS, Endpoint, PERSONAL, capability_backend, grants,
    };
    use crate::gateway::meta_mcp::grant_decision_audit_tests::{api_key, context};
    let endpoint = Endpoint::start(false).await;
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ))
    .with_identity_grants(grants(vec![]));
    meta.set_capabilities(capability_backend(endpoint.port, ("api_key", "alice")));
    one_step(&meta, "granted", CAPS, PERSONAL);
    let who = api_key("bob");
    let answer = wire(
        &Box::pin(meta.handle_tools_call(
            crate::protocol::RequestId::Number(1),
            "gateway_run_playbook",
            serde_json::json!({"name": "granted"}),
            None,
            context(&who),
        ))
        .await,
    );
    assert_eq!(endpoint.arrivals(), 0, "premise: not sent: {answer}");
    assert_eq!(
        answer["error"]["message"],
        crate::gateway::meta_mcp::STEP_NOT_PERMITTED,
        "{answer}"
    );
    assert_eq!(answer["error"]["code"], -32003, "{answer}");
}
