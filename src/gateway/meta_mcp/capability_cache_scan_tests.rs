// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability backend's own response cache sits behind this request's
//! egress scan, so a cache hit is judged again and its delivery is this
//! request's to state: the executor row of the stored-answer inventory
//! (`delivery_facts_tests::STORED_READS`) is vouched for that reason.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Map, Value, json};

use super::MetaMcp;
use super::grant_decision_audit_tests::{api_key, context};
use super::response_security::ResponseDeliveryContext;
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::delivery_facts::{record_fields, scope, snapshot};
use crate::gateway::egress_fixture::secret;
use crate::protocol::{ChainSource, RequestId};
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

const CAPS: &str = "cached_caps";
const TOOL: &str = "cached_read";

/// A REST endpoint answering a credential, and how often it was reached.
async fn leaking_endpoint() -> (u16, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/read",
        axum::routing::get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { axum::Json(json!({ "token": secret() })) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the endpoint");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (port, hits)
}

/// A public, cacheable capability reading the endpoint, under a Warn rule
/// that redacts the credential at egress.
fn gateway(port: u16) -> MetaMcp {
    let base_url = crate::test_fixture_host::fixture_url(port);
    let definition = crate::capability::parse_capability(&format!(
        "name: {TOOL}\n\
         description: Read one token\n\
         metadata:\n\
         \x20 exposure: public\n\
         \x20 read_only: true\n\
         cache:\n\
         \x20 ttl: 60\n\
         \x20 strategy: memory\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /read\n\
         \x20     method: GET\n"
    ))
    .expect("the capability parses");
    let client = crate::test_fixture_host::fixture_client(std::time::Duration::from_secs(5));
    let executor = Arc::new(CapabilityExecutor::new().with_test_http_client(client));
    let backend = Arc::new(CapabilityBackend::new(CAPS, executor));
    backend
        .register_capability(definition)
        .expect("the capability registers");
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(backend);
    let rules = vec![FirewallRule {
        tool_match: TOOL.to_string(),
        action: FirewallAction::Warn,
        reason: None,
        scan: Vec::new(),
        servers: None,
        keys: None,
        except: None,
    }];
    let config = FirewallConfig {
        enabled: true,
        scan_responses: true,
        scan_requests: false,
        credential_redaction: true,
        rules,
        ..FirewallConfig::default()
    };
    meta.set_firewall(Some(Arc::new(Firewall::from_config(config, None))));
    meta
}

/// One `gateway_invoke` of the capability, finalized for delivery inside a
/// fresh cell: the delivered answer and the facts its record would state.
async fn delivered(meta: &MetaMcp) -> (Value, Map<String, Value>) {
    scope(async {
        let who = api_key("alice");
        let arguments = json!({ "server": CAPS, "tool": TOOL, "arguments": {} });
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            "gateway_invoke",
            arguments,
            Some("cache-session"),
            context(&who),
        ))
        .await;
        let targets = [ResponsePolicyTarget {
            server: CAPS.to_string(),
            tool: TOOL.to_string(),
            origin: crate::security::response_policy::TargetOrigin::Routed,
        }];
        let response = meta.finalize_content(
            response,
            &ResponseDeliveryContext {
                method: "tools/call",
                targets: &targets,
                correlation: ResponseCorrelation {
                    session_id: "cache-session",
                    caller: "alice",
                    external_server: "gateway",
                    external_tool: "gateway_invoke",
                    subject: None,
                    trace_id: None,
                    key: crate::security::response_policy::KeyOf::NotKnown,
                },
                signing: None,
                chain_source: ChainSource::NotEligible,
                chain_nonce: None,
                generation: None,
            },
        );
        let mut fields = Map::new();
        record_fields(snapshot().as_ref(), false, &mut fields);
        (serde_json::to_value(&response).expect("serialises"), fields)
    })
    .await
}

/// The second call is the executor's cache hit, and this request's egress
/// scan still redacts the cached credential: `rewritten`, with its finding.
#[tokio::test]
async fn a_capability_cache_hit_is_scanned_by_this_request() {
    let (port, hits) = leaking_endpoint().await;
    let meta = gateway(port);
    for round in ["first call", "cache hit"] {
        let (answer, fields) = delivered(&meta).await;
        let text = answer.to_string();
        assert!(
            !text.contains(&secret()) && text.contains("[REDACTED"),
            "{round}: premise: redacted and delivered: {answer}"
        );
        assert_eq!(
            fields["response_effect"], "rewritten",
            "{round}: {fields:?}"
        );
        assert!(
            fields["response_findings"]
                .as_array()
                .is_some_and(|found| !found.is_empty()),
            "{round}: this request's finding: {fields:?}"
        );
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "premise: the second call was served by the executor's cache"
    );
}
