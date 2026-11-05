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
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
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
    if service == "rest" {
        let provider = cap.providers.named.get("primary").expect("primary");
        return Box::pin(recorded(executor.execute_provider_with_context(
            &cap,
            provider,
            &json!({}),
            &context,
        )))
        .await;
    }
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
        Box::pin(recorded(graphql.execute(&config, json!({}), &ctx))).await
    } else {
        let jsonrpc = super::super::jsonrpc::JsonRpcExecutor {
            executor: &executor,
        };
        Box::pin(recorded(jsonrpc.execute(&config, json!({}), &ctx))).await
    }
}

/// Notes a case whose error does not say `says` or whose delivery does not
/// record `refused`. Each test asserts once over every case, so one run shows
/// every site that fails, not only the first.
fn check(fails: &mut Vec<String>, case: &str, error: &str, says: &str, effect: Option<&Value>) {
    if !error.contains(says) {
        fails.push(format!("{case}: error does not say {says:?}: {error}"));
    }
    if effect != Some(&Value::from("refused")) {
        fails.push(format!("{case}: response_effect {effect:?}, not refused"));
    }
}

/// A private destination, refused before anything is sent.
#[tokio::test]
async fn a_private_destination_records_refused_for_each_protocol() {
    let mut fails = Vec::new();
    for (service, target) in [
        ("rest", "http://10.0.0.5"),
        ("graphql", "http://10.0.0.5/rpc"),
        ("jsonrpc", "http://10.0.0.5/rpc"),
    ] {
        let (error, effect) = Box::pin(call(service, target, false)).await;
        check(&mut fails, service, &error, "SSRF blocked", effect.as_ref());
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// A malformed URL (no host, not absolute, unparsable) is a configuration
/// error, not a refusal: it is answered as before and records nothing
/// refused.
#[tokio::test]
async fn a_hostless_url_records_no_refusal() {
    let mut fails = Vec::new();
    for (target, says) in [
        ("file:///tmp/rpc", "has no host"),
        ("rpc-path-only", "not absolute"),
        ("http://[::1/rpc", "Invalid URL"),
    ] {
        for service in ["rest", "graphql", "jsonrpc"] {
            let (error, effect) = Box::pin(call(service, target, false)).await;
            if !error.contains(says) {
                fails.push(format!(
                    "{service} {target}: error does not say {says:?}: {error}"
                ));
            }
            if effect == Some(Value::from("refused")) {
                fails.push(format!(
                    "{service} {target}: a configuration error recorded refused"
                ));
            }
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// A host naming loopback, refused by its own check before any lookup.
#[tokio::test]
async fn a_loopback_name_records_refused_for_each_protocol() {
    let mut fails = Vec::new();
    for (service, target) in [
        ("rest", "http://localhost"),
        ("graphql", "http://localhost/rpc"),
        ("jsonrpc", "http://localhost/rpc"),
    ] {
        let (error, effect) = Box::pin(call(service, target, false)).await;
        check(&mut fails, service, &error, "SSRF blocked", effect.as_ref());
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// A credential bound for cleartext off this machine, refused before the
/// secret is read.
#[tokio::test]
async fn a_cleartext_credential_records_refused_for_each_protocol() {
    let mut fails = Vec::new();
    for (service, target) in [
        ("rest", "http://93.184.215.14"),
        ("graphql", "http://93.184.215.14/rpc"),
        ("jsonrpc", "http://93.184.215.14/rpc"),
    ] {
        let (error, effect) = Box::pin(call(service, target, true)).await;
        check(&mut fails, service, &error, "cleartext", effect.as_ref());
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// The token endpoint's checks before the refresh flight: cleartext, then
/// a private destination.
#[tokio::test]
async fn a_refused_token_endpoint_records_refused() {
    let mut fails = Vec::new();
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
        check(&mut fails, endpoint, &error, says, effect.as_ref());
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// A composite's step: the plan's record is unvouched before any step runs,
/// so a step refused here leaves it without a refusal of its own.
#[tokio::test]
async fn a_refused_step_of_a_composite_records_no_refusal() {
    let executor = CapabilityExecutor::new();
    let cap = definition("rest", "http://10.0.0.5", false);
    let provider = cap.providers.named.get("primary").expect("primary");
    let context = CapabilityExecutionContext::default();
    let (outcome, facts) = delivery_facts::scope(async {
        delivery_facts::unvouched();
        let outcome =
            Box::pin(executor.execute_provider_with_context(&cap, provider, &json!({}), &context))
                .await;
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let error = outcome.expect_err("the step is refused").to_string();
    assert!(error.contains("SSRF blocked"), "{error}");
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    assert_eq!(fields.get("response_effect"), None, "{fields:?}");
}

/// A process capability of `service` whose parameter names a network
/// destination: refused before anything is spawned.
fn egress_capability(service: &str) -> CapabilityDefinition {
    let config = if service == "cli" {
        "command: 'true'".to_owned()
    } else {
        "command: 'true'\n      transport: stdio\n      tool_selector:\n        param: operation\n        \
         tools:\n          op: { tool: echo }"
            .to_owned()
    };
    parse_capability(&format!(
        "
name: egress_{service}
description: probe
schema:
  input:
    type: object
    properties:
      url:
        type: string
        format: uri
        egress: true
providers:
  primary:
    service: {service}
    config:
      {config}
"
    ))
    .expect("parses")
}

/// A network-destination parameter, refused for CLI and MCP alike.
#[tokio::test]
async fn an_egress_parameter_records_refused_for_each_process_service() {
    use crate::capability::definition::ProcessConfig;
    let mut fails = Vec::new();
    for service in ["cli", "mcp"] {
        let cap = egress_capability(service);
        let executor = CapabilityExecutor::new();
        let context = CapabilityExecutionContext::default();
        let (error, effect) = match cap.providers.process.get("primary") {
            Some(ProcessConfig::Cli(config)) => {
                Box::pin(recorded(executor.execute_cli(
                    &cap,
                    config,
                    &json!({}),
                    &context,
                )))
                .await
            }
            Some(ProcessConfig::Mcp(config)) => {
                Box::pin(recorded(executor.execute_mcp(
                    &cap,
                    config,
                    &json!({}),
                    &context,
                )))
                .await
            }
            None => panic!("{service}: no process provider"),
        };
        check(
            &mut fails,
            service,
            &error,
            "network destination",
            effect.as_ref(),
        );
    }
    assert!(fails.is_empty(), "{fails:#?}");
}
