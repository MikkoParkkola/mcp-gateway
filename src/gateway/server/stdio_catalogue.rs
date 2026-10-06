// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resource and prompt methods stdio serves.
//!
//! Forwarded with no API-key scope and no end-user identity: the process was
//! spawned by its one client, which holds whatever the operator holds. That
//! client is [`stdio_client`], so a managed-account backend resolves for the
//! sole operator here as it does on `gateway_invoke` (#2231). Any other
//! backend whose identity propagation is `required` is refused, exactly as on
//! an HTTP request that carries no verified identity.

use serde_json::Value;

use super::{STDIO, STDIO_CREDENTIAL_PRINCIPAL};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::relay;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Every method [`dispatch`] answers.
pub(super) const METHODS: [&str; 5] = [
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

/// The one client a stdio gateway serves, as the catalogue handlers see it.
///
/// EQUIVALENT TO NO CLIENT FOR EVERY READER BUT ONE. On this path the handlers
/// read `client` only through `authorize_backend`, which admits every backend
/// for `None` and for `["*"]` alike (and names `client.name` only on a refusal
/// neither reaches). The one intended reader is `principal`: it classifies the
/// caller as the local transport, which the managed vault's sole-operator
/// predicate accepts. Never exposed beyond the crate, never built from input.
fn stdio_client() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "stdio".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        // MIK-6704.IDENT.1a: the stdio transport constant; spawning the process is the credential.
        principal: STDIO_CREDENTIAL_PRINCIPAL.to_string(),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::LocalTransport,
    }
}

/// The local operator as a catalogue relay caller: one relay principal, the
/// one `tools/call` keys.
fn operator() -> relay::CatalogueCaller {
    relay::CatalogueCaller {
        key: crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL.to_owned(),
        keyed: true,
        name: "stdio".to_owned(),
        // The id the stdio dispatcher keys this connection by (MIK-7942).
        session: super::STDIO_SESSION_ID.to_owned(),
    }
}

pub(super) async fn dispatch(
    meta: &MetaMcp,
    method: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    relay::as_caller(
        operator(),
        Box::pin(dispatch_catalogue(meta, method, id, params)),
    )
    .await
}

async fn dispatch_catalogue(
    meta: &MetaMcp,
    method: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let client = stdio_client();
    let client = Some(&client);
    match method {
        "prompts/list" => meta.handle_prompts_list(id, params, client, None).await,
        "prompts/get" => meta.handle_prompts_get(id, params, client, None).await,
        "resources/list" => meta.handle_resources_list(id, params, client, None).await,
        "resources/read" => {
            meta.handle_resources_read(id, params, STDIO, client, None)
                .await
        }
        "resources/templates/list" => {
            meta.handle_resources_templates_list(id, params, client, None)
                .await
        }
        other => JsonRpcResponse::error(
            Some(id),
            -32601,
            format!("stdio: '{other}' is not a catalogue method"),
        ),
    }
}

#[cfg(test)]
#[path = "stdio_catalogue_tests.rs"]
mod tests;
