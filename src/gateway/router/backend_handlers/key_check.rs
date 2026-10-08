// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2's undeclared-key check on the direct route (MIK-7570.SCHEMA.1), with
//! F13's fetch of the caller's own catalogue when its slot is cold.

use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::helpers::build_http_response;
use super::BackendRejection;
use super::direct_failure::DirectFailure;
use crate::protocol::{JsonRpcResponse, RequestId};

/// The caller's slot binding and the headers it propagates upstream; a cold
/// slot is listed with exactly these, so the list is fetched as the caller.
pub(super) type CallerSlot<'a> = (Option<&'a str>, &'a [(String, String)]);

/// The rejection for a `tools/call` R2 refuses, or `None` to proceed.
///
/// A refusal is a tool result, not a 403, so a model can correct the call;
/// the early return drops the idempotency reservation unsettled. When the
/// slot's failsafe refuses the cold-slot list, or under `closed` the list
/// fails on transport (F13, A3), the call is answered by the same
/// [`DirectFailure`] a failed dispatch is: client failure recorded, error
/// logged, a 401 on a managed credential refreshed once (A11-c). It gets no
/// reservation: no `tools/call` left the gateway, so the dropped reservation
/// releases.
pub(super) async fn key_refusal(
    backend: &crate::backend::Backend,
    ((identity_key, headers), failed): (CallerSlot<'_>, &DirectFailure<'_>),
    params: &Value,
    id: &RequestId,
) -> Option<BackendRejection> {
    let tool = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let call = crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall {
        server: &backend.name,
        tool,
        session_id: None,
        api_key_name: None,
        trace_id: tool,
        caller_key: None,
    };
    let checked = backend.undeclared_key_refusal(identity_key, headers, tool, arguments);
    match checked.await {
        Ok(None) => None,
        Ok(Some(text)) => {
            let result = json!({ "content": [{ "type": "text", "text": text }], "isError": true });
            let mut response = JsonRpcResponse::success(id.clone(), result);
            // The text names the listing's keys: screened like any answer.
            let screen = (&call, "tools/call");
            super::super::direct_guards::scan_direct_egress(
                failed.state,
                screen,
                failed.client,
                &mut response,
            );
            Some(build_http_response(&Egressed::of(response), StatusCode::OK))
        }
        Err(e) => Some(failed.clone().answer(None, e, &call).await),
    }
}
