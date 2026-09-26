// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2's undeclared-key check on the direct route (MIK-7570.SCHEMA.1), with
//! F13's fetch of the caller's own catalogue when its slot is cold.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tracing::error;

use super::super::AppState;
use super::super::helpers::{build_http_error_response, build_http_response};
use super::{BackendAuthContext, BackendRejection, record_client_failure};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The caller's slot binding and the headers it propagates upstream; a cold
/// slot is listed with exactly these, so the list is fetched as the caller.
pub(super) type CallerSlot<'a> = (Option<&'a str>, &'a [(String, String)]);

/// The rejection for a `tools/call` R2 refuses, or `None` to proceed.
///
/// A refusal is a tool result, not a 403, so a model can correct the call;
/// the early return drops the idempotency reservation unsettled. When the
/// slot's failsafe refuses the cold-slot list, or under `closed` the list
/// fails on transport (F13, A3), the call is accounted and answered exactly
/// as a failed dispatch is in `backend_handler`: the client failure is
/// recorded, the error logged, and the error returned as JSON-RPC with
/// status 500. No `tools/call` left the gateway, so the dropped reservation
/// releases, as `settle_direct_failure` does for a pre-dispatch failure.
pub(super) async fn key_refusal(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    backend: &crate::backend::Backend,
    (identity_key, headers): CallerSlot<'_>,
    params: &Value,
    id: &RequestId,
) -> Option<BackendRejection> {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let checked = backend.undeclared_key_refusal(identity_key, headers, tool, arguments);
    match Box::pin(checked).await {
        Ok(None) => None,
        Ok(Some(text)) => {
            let result = json!({ "content": [{ "type": "text", "text": text }], "isError": true });
            let response = JsonRpcResponse::success(id.clone(), result);
            Some(build_http_response(&response, StatusCode::OK))
        }
        Err(e) => {
            record_client_failure(state, auth.client);
            error!(backend = %backend.name, error = %e, "Backend request failed");
            Some(build_http_error_response(
                Some(id.clone()),
                e.to_rpc_code(),
                e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}
