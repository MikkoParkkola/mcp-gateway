// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Forwarding one resource or prompt request to its backend for one caller.
//!
//! Shared by `resources/read`, `resources/subscribe`, `resources/unsubscribe`
//! and `prompts/get`. The resource methods get scope, isolation and the
//! caller's credential from the owner lookup
//! ([`MetaMcp::find_resource_owner`]), which reads catalogues on the same
//! terms `resources/list` does; `prompts/get` names its backend, so it asks
//! the same questions here. Either way the credential is resolved once and
//! the request is forwarded under it. Own file because `resources.rs` sits
//! near the 800-line ceiling.

use serde_json::Value;

use super::MetaMcp;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::authorize_backend;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

/// The caller's credential for one backend: minted headers and the cache
/// binding that selects its pool slot. Empty for an identity-free caller.
pub(super) type ForwardCredential = (Vec<(String, String)>, Option<String>);

impl MetaMcp {
    /// The refusal `tools/call` gives when `backend` is outside `client`'s
    /// scope (`-32003`, answered 403), if it is.
    pub(super) fn scope_refusal(
        id: &RequestId,
        backend: &str,
        method: &str,
        client: Option<&AuthenticatedClient>,
    ) -> Option<JsonRpcResponse> {
        let e = authorize_backend(client, backend).err()?;
        crate::gateway::authz::audit_refusal(
            crate::gateway::authz::Transport::Http,
            client.map(|c| c.name.as_str()),
            backend,
            method,
            &e.message,
        );
        let refusal = crate::Error::Forbidden {
            code: e.code,
            status: e.status.as_u16(),
            message: e.message,
        };
        Some(super::error_response_preserving_status(
            id.clone(),
            &refusal,
        ))
    }

    /// The caller's credential for `prompts/get`, or the refusal.
    ///
    /// Resolved by the resolver `gateway_invoke` uses, so a `required`
    /// backend is refused, never reached over the shared session, when the
    /// caller carries no verified identity or the mint fails. Only a
    /// propagating backend is resolved: the resolver also refuses an
    /// account-bound backend with no strategy, which is `gateway_invoke`'s
    /// rule, and here that backend stays on the INV-2 terms below.
    ///
    /// INV-2 (ADR-008) is then judged on the bit the catalogue fill uses,
    /// whether this request's slot carries the caller's identity, so a
    /// backend `prompts/list` showed this caller is one it can fetch from.
    pub(super) async fn prompt_credential(
        &self,
        id: &RequestId,
        backend: &crate::backend::Backend,
        verified_identity: Option<&VerifiedIdentity>,
    ) -> Result<ForwardCredential, Box<JsonRpcResponse>> {
        let isolation = |binding: Option<&str>| {
            let carries_identity = backend.fetch_carries_caller_identity(binding);
            self.enforce_oauth_isolation_for(backend, &backend.name, carries_identity)
                .map_err(|e| {
                    Box::new(JsonRpcResponse::error(
                        Some(id.clone()),
                        e.to_rpc_code(),
                        e.to_string(),
                    ))
                })
        };
        // An identity-free caller's verdict needs no mint, so it is judged
        // first: a request refused anyway writes no identity audit record.
        if verified_identity.is_none() {
            isolation(None)?;
        }
        let credential = if backend.identity_propagation_config().is_some() {
            self.resolve_propagation_credential(&backend.name, verified_identity)
                .await
                .map_err(|e| {
                    Box::new(JsonRpcResponse::error(
                        Some(id.clone()),
                        e.to_rpc_code(),
                        e.to_string(),
                    ))
                })?
        } else {
            (Vec::new(), None)
        };
        isolation(credential.1.as_deref())?;
        Ok(credential)
    }

    /// Send `method` to `backend` under `credential`, already resolved for
    /// this request. `empty` answers a backend success that carried no result.
    pub(super) async fn forward_for_caller(
        id: RequestId,
        backend: &crate::backend::Backend,
        method: &str,
        params: Value,
        credential: ForwardCredential,
        empty: Value,
    ) -> JsonRpcResponse {
        let (headers, binding) = credential;
        match backend
            .request_with_headers(method, Some(params), &headers, binding.as_deref())
            .await
        {
            Ok(resp) => match resp.error {
                Some(error) => JsonRpcResponse::error(Some(id), error.code, error.message),
                None => JsonRpcResponse::success(id, resp.result.unwrap_or(empty)),
            },
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }
}
