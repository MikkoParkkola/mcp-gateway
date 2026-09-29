// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2231 over stdio: the five catalogue methods stdio serves resolve an
//! account-bound backend for the operator who spawned the process, and
//! change nothing for any other backend.

use serde_json::{Value, json};

use super::super::STDIO;
use super::super::stdio_catalogue::{METHODS, dispatch};
use crate::config::AuthConfig;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway, OPERATOR_TOKEN,
};
use crate::gateway::server::account_bindings::ServeMode;
use crate::protocol::RequestId;

const URI: &str = "mail://inbox";

fn params(method: &str) -> Option<Value> {
    match method {
        "prompts/get" => Some(json!({"name": format!("{BACKEND}/summary")})),
        "resources/read" => Some(json!({"uri": URI})),
        _ => None,
    }
}

fn stdio_gateway(binding: &Binding) -> (DirectAccountGateway, MetaMcp) {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), binding);
    let meta = gateway.take_meta();
    (gateway, meta)
}

/// Every stdio catalogue method reaches the managed backend on the operator's
/// slot with the operator's grant. Fails if stdio forwards with no caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_catalogue_serves_the_operator_the_account_backend() {
    let (gateway, meta) = stdio_gateway(&Binding::Connected);
    for method in METHODS {
        if method == "resources/read" {
            // The owner lookup lists first; answer it with the resource.
            gateway.answer_next(json!({"resources": [{"uri": URI, "name": "inbox"}]}));
        }
        let _ = dispatch(&meta, method, RequestId::Number(1), params(method).as_ref()).await;
    }
    let slot = DirectAccountGateway::operator_binding();
    let requests = gateway.requests();
    for method in [
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/read",
        "resources/templates/list",
    ] {
        let sent: Vec<_> = requests.iter().filter(|(m, _, _)| m == method).collect();
        assert!(
            !sent.is_empty()
                && sent.iter().all(|(_, auth, key)| {
                    key.as_deref() == Some(slot.as_str())
                        && auth.as_deref().is_some_and(|a| a.contains(OPERATOR_TOKEN))
                }),
            "stdio {method} must reach the backend as the operator: {requests:?}"
        );
    }
}

/// PIN: on a backend the sole-operator assertion does not cover (a `required`
/// signed-assertion backend), stdio answers every method exactly as the
/// handlers answer a caller with no client, and nothing reaches the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_catalogue_output_is_unchanged_for_a_non_account_backend() {
    let (gateway, meta) = stdio_gateway(&Binding::Propagation);
    for method in METHODS {
        let p = params(method);
        let id = || RequestId::Number(1);
        let via_stdio = dispatch(&meta, method, id(), p.as_ref()).await;
        let no_client = match method {
            "prompts/list" => meta.handle_prompts_list(id(), p.as_ref(), None, None).await,
            "prompts/get" => meta.handle_prompts_get(id(), p.as_ref(), None, None).await,
            "resources/list" => {
                meta.handle_resources_list(id(), p.as_ref(), None, None)
                    .await
            }
            "resources/read" => {
                meta.handle_resources_read(id(), p.as_ref(), STDIO, None, None)
                    .await
            }
            "resources/templates/list" => {
                meta.handle_resources_templates_list(id(), p.as_ref(), None, None)
                    .await
            }
            other => panic!("unpinned stdio method {other}"),
        };
        assert_eq!(
            serde_json::to_value(&via_stdio).expect("serializes"),
            serde_json::to_value(&no_client).expect("serializes"),
            "stdio {method} changed for a non-account backend"
        );
    }
    assert_eq!(
        gateway.requests(),
        Vec::new(),
        "nothing may reach the backend"
    );
}
