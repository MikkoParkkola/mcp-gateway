// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's answer to a dispatched failure, shared by both of
//! `dispatch_in_scope`'s callers: the sanitized `tools/call` arm and the
//! passthrough/other-method arm (A11 amendment, Direct).
//!
//! A11-c: a 401 on a managed credential forces at most one refresh first. A
//! provider that killed the grant turns the failure into the route's account
//! refusal (`direct_refusal`, 403/-32003); any other outcome keeps the
//! failure's JSON-RPC error and adds `{error_code, retry}` so the caller knows
//! whether a retry presents a newer token.

use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::Json;
use axum::http::StatusCode;
use serde_json::Value;
use tracing::error;

use super::super::AppState;
use super::super::helpers::build_http_response;
use super::{record_client_failure, settle_direct_failure};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::egress::EgressOutcome;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::ManagedLease;
use crate::personal_accounts::refusal::{marked, refusal_text, upstream_rejection};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::http_diagnostics::is_upstream_unauthorized;

/// The request a dispatched failure answers.
#[derive(Clone)]
pub(super) struct DirectFailure<'a> {
    pub(super) state: &'a AppState,
    pub(super) name: &'a str,
    pub(super) id: RequestId,
    pub(super) client: Option<&'a AuthenticatedClient>,
    pub(super) identity: Option<&'a VerifiedIdentity>,
    /// The managed lease the dispatched headers were released under, if any.
    pub(super) managed: Option<&'a ManagedLease>,
}

impl DirectFailure<'_> {
    /// Answer `error`, settling the idempotency reservation as a dispatched
    /// failure (ADR-012 consequence 1) whichever answer it gets.
    pub(super) async fn answer(
        self,
        reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
        error: crate::Error,
        call: &crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall<'_>,
    ) -> (StatusCode, Json<Value>) {
        let error = match self.managed {
            Some(managed) if is_upstream_unauthorized(&error) => {
                managed.after_upstream_401(error).await
            }
            _ => error,
        };
        // A full slot table says nothing about this caller (#2300).
        if !matches!(error, crate::Error::IdentitySlotsExhausted { .. }) {
            record_client_failure(self.state, self.client);
        }
        // The code only: the error's text can be the backend's, unscreened.
        error!(backend = %self.name, code = error.to_rpc_code(), "Backend request failed");
        let (code, text) = (error.to_rpc_code(), refusal_text(&error));
        let response = match upstream_rejection(&error) {
            Some(rejection) => JsonRpcResponse::error_with_data(
                Some(self.id.clone()),
                code,
                text,
                rejection.data(),
            ),
            None => JsonRpcResponse::error(Some(self.id.clone()), code, text),
        };
        // MIK-8139: a failed dispatch's text can be the backend's own (a
        // non-2xx JSON-RPC refusal), so it gets a result's screening; the
        // screened answer is what the reservation settles with.
        let mut response = response;
        // An error frame: its method selects nothing, the target is `call`.
        let screen = super::super::direct_guards::scan_direct_egress(
            self.state,
            (call, call.tool),
            self.client,
            &mut response,
        );
        // A reconnect refusal settles the key with `response`, not the refusal
        // body returned below. That entry is never replayed: a fenced account
        // is refused at mint, before the idempotency guard, and the guard's
        // principal is the managed binding, which changes with a reconnect or
        // a rotation (`support.rs` `caller_cache_principal`, A11 review).
        settle_direct_failure(reservation, &error, &response);
        // The account refusal re-reads the failure's text, so it answers only
        // a failure the screen left as it was.
        if screen == EgressOutcome::Refused {
            return build_http_response(&Egressed::of(response), StatusCode::OK);
        }
        if screen == EgressOutcome::Delivered && marked(&error).is_some() {
            let text = refusal_text(&error);
            return self
                .state
                .meta_mcp
                .direct_refusal(Some(self.id), text, Some(error), self.identity)
                .await;
        }
        build_http_response(&Egressed::of(response), StatusCode::INTERNAL_SERVER_ERROR)
    }
}
