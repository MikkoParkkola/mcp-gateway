// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2 (MIK-7570.AUDIT.2): one invocation record per direct-route `tools/call`,
//! written by the outer handler around whatever the inner one answered.

use axum::{Json, http::StatusCode};
use serde_json::Value;

use crate::gateway::auth::AuthenticatedClient;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
};
use crate::security::transparency_log::{CorrelationKey, CorrelationSource};

use super::super::AppState;
use super::super::helpers::build_http_error_response;

type Answer = (StatusCode, Json<Value>);

/// The slot the inner handler fills once the body is JSON with
/// `"method": "tools/call"`, before the envelope is validated (D2-a), so a
/// malformed call is still recorded.
pub(super) struct DirectCall {
    tool: Option<String>,
    request_hash: String,
    otel_trace_id: Option<String>,
    who: AuditWho,
}

impl DirectCall {
    /// `Some` only for a `tools/call`: D1 audits invocations, nothing else.
    pub(super) fn of(
        request: &Value,
        client: Option<&AuthenticatedClient>,
        grant_subject: Option<&GrantSubject>,
    ) -> Option<Self> {
        if request.get("method").and_then(Value::as_str) != Some("tools/call") {
            return None;
        }
        // As the caller sent them, before sanitisation (D2-e).
        let params = request.get("params").unwrap_or(&Value::Null);
        let otel_trace_id = params
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        Some(Self {
            tool: params
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
            request_hash: sha256_of(params),
            otel_trace_id,
            who: AuditWho::from_request(client, grant_subject),
        })
    }
}

fn sha256_of(value: &Value) -> String {
    format!("sha256:{}", crate::hashing::canonical_json_sha256(value))
}

/// The only classifier for a direct-route answer (D2-c). A 200 is read from
/// its body; any other status goes through the shared status table, never
/// through the JSON-RPC code, because `-32600` is both a refusal and a
/// malformed envelope on this route.
pub(super) fn direct_outcome(status: StatusCode, body: &Value) -> AuditOutcome {
    let code = body
        .pointer("/error/code")
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok());
    if status != StatusCode::OK {
        return AuditOutcome::from_http_status(status, code);
    }
    match code {
        Some(code) => AuditOutcome::Error(code),
        None if body.pointer("/result/isError") == Some(&Value::Bool(true)) => {
            AuditOutcome::ToolError
        }
        None => AuditOutcome::Ok,
    }
}

/// Write the record for `call` and hand `answer` on, or withhold it when the
/// write fails under [`AuditFailurePolicy::FailClosed`] (D1-f, D2-g).
pub(super) async fn record(
    state: &AppState,
    server: &str,
    call: DirectCall,
    answer: Answer,
) -> Answer {
    let Some(log) = state.transparency_log.as_ref() else {
        return answer;
    };
    let (status, Json(body)) = &answer;
    let outcome = direct_outcome(*status, body);
    // D1-d.1: a failed call has no response hash.
    let response_hash = body.get("result").is_some().then(|| sha256_of(body));
    // D2-f: the caller's W3C trace id, else a trace id; no session rung.
    let trace_id = crate::gateway::trace::current().unwrap_or_else(crate::gateway::trace::generate);
    let envelope = AuditEnvelope {
        trace_id: Some(trace_id.clone()),
        otel_trace_id: call.otel_trace_id.clone(),
        outcome,
        who: call.who,
    };
    let (srv, tool, request_hash, otel) = (
        server.to_string(),
        call.tool,
        call.request_hash,
        call.otel_trace_id,
    );
    // F20: on the blocking pool under the append bound, so a stalled disk
    // answers 503 instead of pinning a runtime worker.
    let written = (move |log: &crate::security::TransparencyLogger| {
            let key = match otel.as_deref() {
                Some(otel) => CorrelationKey {
                    id: otel,
                    source: CorrelationSource::OtelTraceId,
                },
                None => CorrelationKey {
                    id: &trace_id,
                    source: CorrelationSource::TraceId,
                },
            };
            let target = InvocationTarget {
                route: InvocationRoute::Direct,
                server: &srv,
                tool: tool.as_deref(),
            };
            log.log_invocation_correlated(
                key,
                &envelope,
                target,
                &request_hash,
                response_hash.as_deref(),
            )
        })(&**log);
    match written {
        Ok(()) => answer,
        Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
            tracing::error!(server, %error, "direct-route audit write failed; result withheld");
            let id = body
                .get("id")
                .and_then(|id| serde_json::from_value::<RequestId>(id.clone()).ok());
            let error = crate::Error::AuditUnavailable;
            build_http_error_response(
                id,
                error.to_rpc_code(),
                error.to_string(),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        }
        Err(error) => {
            tracing::warn!(server, %error, "Transparency log write failed (non-fatal)");
            answer
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// D2-T4. One `(status, body)` per D2-c row; codes come from the body.
    #[test]
    fn direct_outcome_table_covers_every_row() {
        let err = |code: i32| json!({"error": {"code": code, "message": "m"}});
        let rows = [
            (200, json!({"result": {"content": []}}), AuditOutcome::Ok),
            (
                200,
                json!({"result": {"isError": true}}),
                AuditOutcome::ToolError,
            ),
            (200, err(-32005), AuditOutcome::Error(-32005)),
            (200, err(-32600), AuditOutcome::Error(-32600)),
            (401, err(-32600), AuditOutcome::Denied(-32600)),
            (403, err(-32600), AuditOutcome::Denied(-32600)),
            (403, err(-32003), AuditOutcome::Denied(-32003)),
            (400, err(-32600), AuditOutcome::Invalid(-32600)),
            (400, err(-32700), AuditOutcome::Invalid(-32700)),
            (404, err(-32001), AuditOutcome::Invalid(-32001)),
            (409, err(409), AuditOutcome::Error(409)),
            (500, err(-32603), AuditOutcome::Error(-32603)),
            (503, err(-32005), AuditOutcome::Error(-32005)),
        ];
        for (status, body, expected) in rows {
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(direct_outcome(status, &body), expected, "{status} {body}");
        }
    }
}
