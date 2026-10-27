// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every destination or TLS refusal on a capability call path records
//! `refused` on that call's delivery: the caller receives the gateway's
//! refusal, not a backend's answer.

use std::future::Future;

use serde_json::{Value, json};

use super::super::rest::{ExecutionContext, ProtocolExecutor};
use crate::capability::{
    CapabilityDefinition, CapabilityExecutionContext, CapabilityExecutor, parse_capability,
};
use crate::gateway::delivery_facts;

/// The call's error and the `response_effect` its delivery records.
async fn recorded<T: std::fmt::Debug>(
    call: impl Future<Output = crate::Result<T>>,
) -> (String, Option<Value>) {
    let (outcome, facts) = delivery_facts::scope(async {
        let outcome = call.await;
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, false, &mut fields);
    let error = outcome.expect_err("the call is refused").to_string();
    (error, fields.get("response_effect").cloned())
}

/// A one-provider capability of `service` aimed at `target`.
fn definition(service: &str, target: &str, auth_required: bool) -> CapabilityDefinition {
    let config = if service == "rest" {
        format!("base_url: \"{target}\"\n      path: /v1/items\n      method: GET")
    } else {
        format!("endpoint: \"{target}\"\n      method: probe\n      body: \"{{ probe }}\"")
    };
    parse_capability(&format!(
        "
name: refused_{service}
description: probe
providers:
  primary:
    service: {service}
    config:
      {config}
auth:
  required: {auth_required}
  type: bearer
  key: env:MCP_GW_REFUSAL_PROBE
"
    ))
    .expect("parses")
}

/// Runs one call of `service` to `target`.
async fn call(service: &str, target: &str, auth_required: bool) -> (String, Option<Value>) {
    let executor = CapabilityExecutor::new();
    let cap = definition(service, target, auth_required);
    let context = CapabilityExecutionContext::default();
    match service {
        "rest" => {
            let provider = cap.providers.named.get("primary").expect("primary");
            recorded(executor.execute_provider_with_context(&cap, provider, &json!({}), &context))
                .await
        }
        _ => {
            let config = cap.providers.named["primary"].protocol_config();
            let ctx = ExecutionContext {
                capability: &cap,
                timeout_secs: 10,
                context,
            };
            if service == "graphql" {
                let graphql = super::GraphqlExecutor {
                    executor: &executor,
                };
                recorded(graphql.execute(&config, json!({}), &ctx)).await
            } else {
                let jsonrpc = super::super::jsonrpc::JsonRpcExecutor {
                    executor: &executor,
                };
                recorded(jsonrpc.execute(&config, json!({}), &ctx)).await
            }
        }
    }
}

/// A private destination, refused before anything is sent.
#[tokio::test]
async fn a_private_destination_records_refused_for_each_protocol() {
    for (service, target) in [
        ("rest", "http://10.0.0.5"),
        ("graphql", "http://10.0.0.5/rpc"),
        ("jsonrpc", "http://10.0.0.5/rpc"),
    ] {
        let (error, effect) = call(service, target, false).await;
        assert!(error.contains("SSRF blocked"), "{service}: {error}");
        assert_eq!(effect, Some("refused".into()), "{service}");
    }
}

/// A credential bound for cleartext off this machine, refused before the
/// secret is read.
#[tokio::test]
async fn a_cleartext_credential_records_refused_for_each_protocol() {
    for (service, target) in [
        ("rest", "http://93.184.215.14"),
        ("graphql", "http://93.184.215.14/rpc"),
        ("jsonrpc", "http://93.184.215.14/rpc"),
    ] {
        let (error, effect) = call(service, target, true).await;
        assert!(error.contains("cleartext"), "{service}: {error}");
        assert_eq!(effect, Some("refused".into()), "{service}");
    }
}

/// The token endpoint's checks before the refresh flight: cleartext, then
/// a private destination.
#[tokio::test]
async fn a_refused_token_endpoint_records_refused() {
    for (endpoint, says) in [
        ("http://off-machine.invalid/token", "cleartext"),
        ("https://10.0.0.5/token", "SSRF blocked"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let storage =
            std::sync::Arc::new(crate::oauth::TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let (error, effect) = recorded(CapabilityExecutor::new().refresh_provider_token(
            "refused",
            endpoint,
            &storage,
            &CapabilityExecutionContext::default(),
        ))
        .await;
        assert!(error.contains(says), "{endpoint}: {error}");
        assert_eq!(effect, Some("refused".into()), "{endpoint}");
    }
}
