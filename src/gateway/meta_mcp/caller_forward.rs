// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Forwarding one resource or prompt request to its backend for one caller.
//!
//! Shared by `resources/read`, `resources/subscribe`, `resources/unsubscribe`
//! and `prompts/get`, so the scope check, the isolation guard and the
//! credential resolution happen in one order on every route. Own file because
//! `resources.rs` sits near the 800-line ceiling.

use serde_json::Value;

use super::MetaMcp;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::authorize_backend;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

impl MetaMcp {
    /// Why `client` may not have `method` forwarded to `backend`, if it may not.
    ///
    /// Backend scope first, with the refusal `tools/call` gives (`-32003`,
    /// answered 403), then INV-2 (ADR-008). The isolation guard is still asked
    /// with `false` although [`Self::forward_for_caller`] may resolve a per-user
    /// credential, so this route admits nothing on a multi-user gateway that it
    /// refused before. Both come before [`Self::forward_for_caller`] resolves a
    /// credential, so a refused `prompts/get` mints nothing.
    pub(super) fn refusal_for(
        &self,
        id: &RequestId,
        backend: &crate::backend::Backend,
        method: &str,
        client: Option<&AuthenticatedClient>,
    ) -> Option<JsonRpcResponse> {
        if let Err(e) = authorize_backend(client, &backend.name) {
            crate::gateway::authz::audit_refusal(
                crate::gateway::authz::Transport::Http,
                client.map(|c| c.name.as_str()),
                &backend.name,
                method,
                &e.message,
            );
            let refusal = crate::Error::Forbidden {
                code: e.code,
                status: e.status.as_u16(),
                message: e.message,
            };
            return Some(super::error_response_preserving_status(
                id.clone(),
                &refusal,
            ));
        }
        self.enforce_oauth_isolation_for(backend, &backend.name, false)
            .err()
            .map(|e| JsonRpcResponse::error(Some(id.clone()), e.to_rpc_code(), e.to_string()))
    }

    /// Send `method` to `backend` under the caller's own identity credential.
    ///
    /// Resolved by the resolver `gateway_invoke` uses, so a backend whose
    /// identity propagation is `required` is refused, never reached over the
    /// shared session, when the caller carries no verified identity or the
    /// mint fails. A caller with no identity and a backend without `required`
    /// propagation get the shared session, as before. `empty` answers a
    /// backend success that carried no result.
    pub(super) async fn forward_for_caller(
        &self,
        id: RequestId,
        backend: &crate::backend::Backend,
        method: &str,
        params: Value,
        verified_identity: Option<&VerifiedIdentity>,
        empty: Value,
    ) -> JsonRpcResponse {
        // Only a propagating backend is resolved. `resolve_propagation_credential`
        // also refuses an account-bound backend with no strategy, which is
        // `gateway_invoke`'s rule and not this route's: here that backend stays
        // on the INV-2 terms `refusal_for` already applied.
        let (headers, binding) = if backend.identity_propagation_config().is_some() {
            match self
                .resolve_propagation_credential(&backend.name, verified_identity)
                .await
            {
                Ok(credential) => credential,
                Err(e) => return JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
            }
        } else {
            (Vec::new(), None)
        };
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
