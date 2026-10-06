// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2 (MIK-7570.AUDIT.2): one invocation record per direct-route `tools/call`,
//! written by the outer handler around whatever the inner one answered.

use std::sync::Arc;

use axum::{Json, http::StatusCode};
use serde_json::Value;

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::audit::DispatchNotes;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationRoute, InvocationTarget,
};
use crate::security::transparency_log::CorrelationKey;

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
    /// MIK-7116.MIN.1: the tool's `arguments` as sent, for request tenants.
    arguments: Value,
    /// The id of the incoming request: a refusal answers `id: null`, and the
    /// `FailClosed` 503 must still echo what the caller sent.
    request_id: Option<RequestId>,
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
            // The firewall's own fallback (`handle_backend_call`): a call with
            // no `arguments` member is scanned over `params`, so attribute it
            // the same way (#2523).
            arguments: params.get("arguments").unwrap_or(params).clone(),
            request_id: request
                .get("id")
                .and_then(|id| serde_json::from_value(id.clone()).ok()),
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

/// What the inner handler learns that the read verdict needs (MIK-7116.MIN.2):
/// the caller, formed only when the verdict is on, and the request params.
/// Also the caller's name and the tool the delivery record names (MIK-7669),
/// empty when the request was refused before its body was read.
#[derive(Default)]
pub(super) struct DirectReads {
    key: Option<String>,
    params: Option<Value>,
    caller: Option<String>,
    /// The caller's verified grant subject, for the delivery record (MIK-7938).
    subject: Option<GrantSubject>,
    tool: String,
}

impl DirectReads {
    /// The resolved caller's name and verified subject, kept as soon as they
    /// are known, so even an answer refused before the body is read names its
    /// caller.
    pub(super) fn name_caller(
        &mut self,
        client: Option<&AuthenticatedClient>,
        subject: Option<&GrantSubject>,
    ) {
        self.caller = client.map(|client| client.name.clone());
        self.subject = subject.cloned();
    }

    /// Capture the caller (`key` forms it) and the request params, only when
    /// the verdict is on, so the default config copies nothing. The tool is
    /// always kept: every answer is recorded.
    pub(super) fn capture(
        &mut self,
        state: &AppState,
        request: &Value,
        key: impl FnOnce() -> String,
    ) {
        // As on the meta route: the tool a `tools/call` names, else the method.
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.tool = if method == "tools/call" {
            request
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        } else {
            method.to_string()
        };
        if crate::gateway::outbound::judges(super::super::helpers::read_guard(state).as_deref()) {
            self.key = Some(key()).filter(|key| !key.is_empty());
            self.params = request.get("params").cloned();
        }
    }
}

/// D2: one write per tools/call, with the notes of its dispatch scope. Then
/// every answer, whatever the method, is judged for the caller (H9) and
/// written through the outbound sink.
/// [`audited_call_judged`] inside one relay-receipt collector, which spans the
/// dispatch, the audit write and the judge (COLLUDE.1). With relay detection
/// off there is nothing to collect.
pub(super) async fn audited_call(
    state: Arc<AppState>,
    name: String,
    request: axum::http::Request<axum::body::Body>,
) -> crate::gateway::outbound::OutboundReply {
    let judged = audited_call_judged(Arc::clone(&state), name, request);
    #[cfg(feature = "firewall")]
    if state.firewall.as_ref().is_some_and(|fw| fw.relay_active()) {
        return crate::gateway::meta_mcp::invoke::relay::collecting(Box::pin(judged)).await;
    }
    Box::pin(judged).await
}

async fn audited_call_judged(
    state: Arc<AppState>,
    name: String,
    request: axum::http::Request<axum::body::Body>,
) -> crate::gateway::outbound::OutboundReply {
    let mut call = None;
    let mut reads = DirectReads::default();
    let guard = super::super::helpers::read_guard(&state);
    let inner = Box::pin(crate::gateway::outbound::read_scoped(
        guard.clone(),
        super::backend_handler_inner(
            Arc::clone(&state),
            name.clone(),
            request,
            &mut call,
            &mut reads,
        ),
    ));
    let ((answer, hidden), notes) =
        crate::gateway::meta_mcp::invoke::audit::with_dispatch_scope(inner).await;
    let (status, Json(body)) = match call {
        Some(call) => record(&state, &name, call, answer, notes).await,
        None => answer,
    };
    if status == StatusCode::ACCEPTED {
        // An accepted notification: the gateway's own placeholder, sent
        // with no body (MIK-7759), carries nothing to judge.
        return crate::gateway::outbound::gateway_reply(super::super::helpers::bodiless_accepted(
            (status, Json(body)),
        ));
    }
    let mut frame = crate::gateway::outbound::answer_value(
        guard.as_deref(),
        reads.key.as_deref(),
        body,
        reads.params.as_ref(),
        hidden.as_ref(),
    );
    // MIK-7669: the delivery record the meta route writes (`judged_answer`),
    // after the judge and with the answer's `tenant_read` fields in it. The
    // direct route keeps no session, so the session fingerprint is empty.
    let mut status = status;
    let correlation = crate::security::response_policy::ResponseCorrelation {
        session_id: "",
        caller: reads.caller.as_deref().unwrap_or("anonymous"),
        external_server: &name,
        external_tool: &reads.tool,
        subject: reads.subject.as_ref(),
    };
    // No log, nothing to record: the answer is not copied to be hashed.
    let document = state
        .transparency_log
        .as_ref()
        .and_then(|_| frame.answer_document());
    let recorded = match document {
        Some(document) => {
            let read = frame.take_record_fields();
            // The HTTP status decides as for the invocation record: a 403 or
            // 429 refusal carries the body `{}` and no error code (L1254).
            let body = document.as_ref().unwrap_or(&Value::Null);
            let outcome = direct_outcome(status, body);
            crate::gateway::meta_mcp::response_security::record_answer_delivery(
                state.transparency_log.as_ref(),
                document,
                outcome,
                &correlation,
                read,
            )
            .await
        }
        None => true,
    };
    if !recorded {
        let refusal =
            crate::gateway::meta_mcp::MetaMcp::audit_unavailable_refusal(frame.answer_id());
        frame = frame.replaced_by(refusal);
        status = StatusCode::SERVICE_UNAVAILABLE;
    }
    // COLLUDE.1 x MIN.2: receipts record only an answer that was delivered, so
    // they follow the judge, the audit write and the delivery record (which
    // carries the read verdict), as each can still replace the answer.
    let delivers = frame.delivers_result();
    let response = crate::gateway::outbound::to_http(frame, status, "");
    let (reply, written) =
        crate::gateway::outbound::judged_reply_checked(response, state.transparency_log.as_ref())
            .await;
    #[cfg(feature = "firewall")]
    super::relay::commit_direct_receipts(&state, delivers && written);
    #[cfg(not(feature = "firewall"))]
    let _ = (delivers, written);
    reply
}

/// Write the record for `call` and hand `answer` on, or withhold it when the
/// write fails under [`AuditFailurePolicy::FailClosed`] (D1-f, D2-g).
pub(super) async fn record(
    state: &AppState,
    server: &str,
    call: DirectCall,
    answer: Answer,
    notes: DispatchNotes,
) -> Answer {
    let (status, Json(body)) = &answer;
    let outcome = direct_outcome(*status, body);
    // D4: counted before the log check, so auth off still counts.
    let firewall = body
        .get("error")
        .is_some_and(crate::gateway::meta_mcp::invoke::dispatch_guards::is_firewall_refusal);
    if let Some(reason) = crate::security::security_metrics::direct_denial(outcome, body, firewall)
    {
        use crate::security::security_metrics::{DenialRoute, denied};
        denied(DenialRoute::Direct, reason);
    }
    let Some(log) = state.transparency_log.as_ref() else {
        return answer;
    };
    // D1-d.1: a failed call has no response hash.
    let response_hash = body.get("result").is_some().then(|| sha256_of(body));
    // MIK-7116.MIN.1: what the gates saw, or the delivered value on a replay.
    let tenants = state.meta_mcp.request_tenants(&call.arguments);
    let attribution = notes.attribution(&state.meta_mcp, tenants, body.get("result"));
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
    let written = log
        .append_bounded(move |log| {
            let key = CorrelationKey::ladder(otel.as_deref(), None, &trace_id);
            let target = InvocationTarget {
                route: InvocationRoute::Direct,
                server: &srv,
                tool: tool.as_deref(),
            };
            log.log_invocation_attributed(
                key,
                &envelope,
                target,
                &request_hash,
                response_hash.as_deref(),
                attribution,
            )
        })
        .await;
    match written {
        Ok(()) => answer,
        Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
            tracing::error!(server, %error, "direct-route audit write failed; result withheld");
            let error = crate::Error::AuditUnavailable;
            build_http_error_response(
                call.request_id,
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
