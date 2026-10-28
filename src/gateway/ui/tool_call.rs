// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U12: try a tool from the web UI, `POST /ui/api/tools/call`.
//!
//! The route assembles no pipeline of its own: it builds the `/mcp`
//! `tools/call` of `gateway_invoke` the request stands for and runs the MCP
//! handler in process, with this request's headers and extensions, so every
//! gate, record and scan is the MCP path's own. A [`UiCall`] in scope carries
//! the one thing the MCP path does not know (what the admin confirmed) and
//! brings back what only the dispatch knows (whether the tool was sent).
//!
//! The answer's status is the web shell's contract: 4xx means the tool did
//! not run, 200 that it ran (its own `isError` included), 5xx that it may
//! have run. The status is read from the dispatch's record, never from a
//! JSON-RPC code, and every error message is a fixed string.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::admin_audit::{AuditDetail, record_admin_action};
use super::errors::admin_auth_required;
use super::{AppState, AuthenticatedClient, is_admin};
use crate::gateway::ui_call::{Confirm, Outcome, UiCall};
use crate::key_server::oidc::VerifiedIdentity;

/// The largest request body read: a tool's arguments typed into a form.
const MAX_BODY: usize = 1 << 20;

/// How long the route waits for the tool before answering 504. Under the
/// shell's own 30 s, so the shell hears "may still be running" from us.
const DEADLINE: Duration = Duration::from_secs(25);

#[cfg(test)]
thread_local! {
    /// A shorter deadline for the deadline row.
    pub(crate) static DEADLINE_FOR_TEST: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

fn deadline() -> Duration {
    #[cfg(test)]
    if let Some(short) = DEADLINE_FOR_TEST.with(std::cell::Cell::get) {
        return short;
    }
    DEADLINE
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallRequest {
    server: String,
    tool: String,
    arguments: Map<String, Value>,
    #[serde(default)]
    confirm_write: bool,
}

/// Where the call ended, as the shell and the record name it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Disposition {
    Ran,
    NotRun,
    MayHaveRun,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ran => "ran",
            Self::NotRun => "not_run",
            Self::MayHaveRun => "may_have_run",
        }
    }
}

/// The handler.
pub(super) async fn call(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    let (parts, body) = request.into_parts();
    // `DefaultBodyLimit` binds extractors only, so this read is capped here.
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the body could not be read",
            Disposition::NotRun,
        );
    };
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&bytes) else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the body is not a JSON object",
            Disposition::NotRun,
        );
    };
    let Ok(ask) = serde_json::from_value::<CallRequest>(Value::Object(object)) else {
        return refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid",
            "expected server, tool, arguments (an object) and confirm_write only",
            Disposition::NotRun,
        );
    };
    let via = via_label(&state, client.as_ref(), &parts.extensions);
    let mut detail = Map::new();
    detail.insert("via".into(), via.into());
    detail.insert("server".into(), ask.server.clone().into());
    detail.insert("tool".into(), ask.tool.clone().into());
    detail.insert("confirm_write".into(), ask.confirm_write.into());

    // Under required signing every call carries the caller's nonce; the
    // route mints none on its behalf. Refused here: unsigned, dispatch would
    // answer with the code a missing tool also uses.
    if state.meta_mcp.requires_call_nonce() {
        return finish(
            refusal(
                StatusCode::FORBIDDEN,
                "signing_required",
                "this gateway requires signed calls; use a signing client",
                Disposition::NotRun,
            ),
            detail,
            Disposition::NotRun,
            None,
        );
    }
    // One of the few UI calls that may run at once, and the drain tracker's
    // permit, so shutdown waits for a call that runs on past its answer.
    let pool = Arc::clone(state.meta_mcp.ui_call_permits()).try_acquire_owned();
    let drain = Arc::clone(&state.inflight).try_acquire_owned();
    let (Ok(pool), Ok(drain)) = (pool, drain) else {
        return finish(
            refusal(
                StatusCode::FORBIDDEN,
                "busy",
                "too many tool calls are running from the web UI; nothing was run",
                Disposition::NotRun,
            ),
            detail,
            Disposition::NotRun,
            None,
        );
    };
    let permit = (pool, drain);
    let principal = client
        .as_ref()
        .map(|c| c.principal.storage_form().to_owned())
        .unwrap_or_default();
    let confirm = if ask.confirm_write {
        Confirm::Confirmed
    } else {
        Confirm::DeclaredReadOnlyOnly
    };
    let ui_call = UiCall::new(&ask.server, &ask.tool, &principal, confirm);
    let internal = internal_request(&parts, &ask);
    let started = Instant::now();
    let (answered, answer) = tokio::sync::oneshot::channel();
    let follow_up = FollowUp {
        client: client.clone(),
        identity: parts.extensions.get::<VerifiedIdentity>().cloned(),
        detail: detail.clone(),
    };
    let abort = spawn_call(&state, &ui_call, internal, permit, answered, follow_up);
    let Ok(answer) = tokio::time::timeout(deadline(), answer).await else {
        if !ui_call.outcome().dispatched {
            // Nothing was sent: nothing runs on past this answer.
            abort.abort();
        }
        // Read after the abort: a send that began in between is marked
        // before it starts, so it reads here as may-have-run.
        let outcome = ui_call.outcome();
        let disposition = if outcome.dispatched {
            Disposition::MayHaveRun
        } else {
            Disposition::NotRun
        };
        return finish(
            refusal(
                StatusCode::GATEWAY_TIMEOUT,
                "deadline",
                "no answer in time; the tool may still be running",
                disposition,
            ),
            detail,
            disposition,
            outcome.trace,
        );
    };
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = ui_call.outcome();
    // A closed channel: the task ended without an answer (it panicked).
    let answer = answer.ok().flatten();
    let (status, disposition) = classify(&outcome, answer.as_ref());
    let response = if status == StatusCode::OK {
        let result = answer
            .as_ref()
            .and_then(|a| a.get("result"))
            .map(tool_result)
            .unwrap_or(Value::Null);
        let is_error = result.get("isError").and_then(Value::as_bool) == Some(true);
        let mut body = json!({
            "result": result,
            "is_error": is_error,
            "latency_ms": latency_ms,
            "disposition": disposition.as_str(),
        });
        if let Some(trace) = &outcome.trace {
            body["receipt"] = trace.as_ref().into();
        }
        (status, axum::Json(body)).into_response()
    } else {
        let (code, message) = wording(status);
        refusal(status, code, message, disposition)
    };
    finish(response, detail, disposition, outcome.trace)
}

/// Who and what the completion record names, captured before the spawn.
struct FollowUp {
    client: Option<AuthenticatedClient>,
    identity: Option<VerifiedIdentity>,
    detail: Map<String, Value>,
}

/// Run the MCP handler for `internal` with `ui_call` in scope, on its own
/// task: a call already sent finishes after a deadline answer, holding
/// `permit` (the drain tracker's) until it does. The answer goes back on
/// `answered`; when nobody is there to take it (the deadline passed or the
/// request was dropped) the task writes the record of how the call ended.
fn spawn_call(
    state: &Arc<AppState>,
    ui_call: &Arc<UiCall>,
    internal: Request,
    permit: (
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    ),
    answered: tokio::sync::oneshot::Sender<Option<Value>>,
    follow_up: FollowUp,
) -> tokio::task::AbortHandle {
    let state = Arc::clone(state);
    let ui_call = Arc::clone(ui_call);
    let task = tokio::spawn(async move {
        let _permit = permit;
        let reply = ui_call
            .scope(crate::gateway::router::meta_mcp_handler(
                State(Arc::clone(&state)),
                internal,
            ))
            .await
            .into_response();
        let answer = read_answer(reply).await;
        if let Err(answer) = answered.send(answer) {
            let outcome = ui_call.outcome();
            let mut fields = follow_up.detail;
            fields.insert("completion".into(), true.into());
            fields.insert(
                "disposition".into(),
                classify(&outcome, answer.as_ref()).1.as_str().into(),
            );
            if let Some(trace) = outcome.trace {
                fields.insert("invocation_trace".into(), trace.as_ref().into());
            }
            let _ = record_admin_action(
                &state,
                "admin_ui",
                follow_up.client.as_ref(),
                follow_up.identity.as_ref(),
                fields,
            );
        }
    });
    task.abort_handle()
}

/// The status and disposition of a call, from what the dispatch recorded.
/// A JSON-RPC code is read only once the record says nothing was sent, to
/// tell a no-such-tool or an audit outage from a refusal: every one of those
/// is "did not run" whatever the code means.
fn classify(outcome: &Outcome, answer: Option<&Value>) -> (StatusCode, Disposition) {
    let code = answer
        .and_then(|a| a.get("error"))
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64);
    let audit_down = code == Some(i64::from(AUDIT_UNAVAILABLE));
    if outcome.confirm_refused {
        // Refused before its backend or capability ran.
        return (StatusCode::CONFLICT, Disposition::NotRun);
    }
    if outcome.dispatched {
        let ran = !outcome.failed_after_send && answer.is_some_and(|a| a.get("result").is_some());
        return match (ran, audit_down) {
            (true, _) => (StatusCode::OK, Disposition::Ran),
            (false, true) => (StatusCode::SERVICE_UNAVAILABLE, Disposition::MayHaveRun),
            (false, false) => (StatusCode::INTERNAL_SERVER_ERROR, Disposition::MayHaveRun),
        };
    }
    match (answer, code) {
        // Unreadable: the record says unsent, but the shell is told only
        // what is certain.
        (None, _) => (StatusCode::INTERNAL_SERVER_ERROR, Disposition::MayHaveRun),
        (Some(_), Some(NO_SUCH_TOOL)) => (StatusCode::NOT_FOUND, Disposition::NotRun),
        (Some(_), _) if audit_down => (StatusCode::SERVICE_UNAVAILABLE, Disposition::NotRun),
        // A gate's refusal, or a sealed refusal answered as an `isError`
        // result before the send.
        (Some(_), _) => (StatusCode::FORBIDDEN, Disposition::NotRun),
    }
}

/// `BackendNotFound` and `ToolNotFound` (`Error::to_rpc_code`).
const NO_SUCH_TOOL: i64 = -32001;
/// `Error::AuditUnavailable`.
const AUDIT_UNAVAILABLE: i32 = -32005;

/// The fixed code and message for a status: no dispatch or backend text is
/// ever copied into a UI answer.
fn wording(status: StatusCode) -> (&'static str, &'static str) {
    match status {
        StatusCode::CONFLICT => (
            "confirm_write_required",
            "this tool is not declared read-only; send confirm_write to run it",
        ),
        StatusCode::NOT_FOUND => ("no_such_tool", "no such server or tool"),
        StatusCode::FORBIDDEN => ("refused", "the gateway refused this call; nothing was run"),
        StatusCode::SERVICE_UNAVAILABLE => (
            "audit_unavailable",
            "the audit log could not record this call",
        ),
        _ => ("failed", "the call failed; the tool may have run"),
    }
}

fn refusal(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    disposition: Disposition,
) -> Response {
    let mut body = crate::gateway::http_error::structured_error_body(code, message);
    body["disposition"] = disposition.as_str().into();
    (status, axum::Json(body)).into_response()
}

/// The `/mcp` request this call stands for: a stateless `tools/call` of
/// `gateway_invoke`, carrying this request's headers (dispatch re-reads the
/// identity ones) and extensions (what the auth layers already decided).
fn internal_request(parts: &axum::http::request::Parts, ask: &CallRequest) -> Request {
    let revision = crate::protocol::meta::FIRST_STATELESS_VERSION;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": ask.server, "tool": ask.tool, "arguments": ask.arguments},
            "_meta": {"io.modelcontextprotocol/protocolVersion": revision},
        },
    });
    let mut request = Request::new(Body::from(body.to_string()));
    *request.method_mut() = axum::http::Method::POST;
    *request.uri_mut() = axum::http::Uri::from_static(crate::gateway::routes::MCP);
    let headers = request.headers_mut();
    *headers = parts.headers.clone();
    headers.remove(header::CONTENT_LENGTH);
    headers.remove("mcp-session-id");
    let json_type = HeaderValue::from_static("application/json");
    headers.insert(header::CONTENT_TYPE, json_type.clone());
    headers.insert(header::ACCEPT, json_type);
    headers.insert("mcp-protocol-version", HeaderValue::from_static(revision));
    headers.insert("mcp-method", HeaderValue::from_static("tools/call"));
    headers.insert("mcp-name", HeaderValue::from_static("gateway_invoke"));
    *request.extensions_mut() = parts.extensions.clone();
    request.extensions_mut().remove::<MatchedPath>();
    request
}

/// The MCP answer's JSON-RPC body. Reading it commits its delivery record.
async fn read_answer(reply: Response) -> Option<Value> {
    let bytes = axum::body::to_bytes(reply.into_body(), usize::MAX)
        .await
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The tool's own result inside a `gateway_invoke` answer, without the
/// members the gateway adds.
fn tool_result(outer: &Value) -> Value {
    let mut result = crate::protocol::tool_result_payload(outer).unwrap_or_else(|| outer.clone());
    if let Some(object) = result.as_object_mut() {
        object.remove("trace_id");
        object.remove("_context_integrity");
    }
    result
}

/// `ui:` and the caller's label as the call counters write it.
fn via_label(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    extensions: &axum::http::Extensions,
) -> String {
    let subject = extensions.get::<VerifiedIdentity>().and_then(|id| {
        crate::identity_grants::GrantSubject::checked(id.issuer.clone(), id.subject.clone(), None)
    });
    let who = crate::security::audit::AuditWho::from_request(
        client,
        subject.as_ref(),
        state.auth_config.record_key(),
    );
    let kind = who
        .credential_kind
        .unwrap_or(crate::security::audit::CredentialKind::None);
    format!("ui:{}", crate::counters::caller_label(kind, &who.account))
}

/// Put the call's fields on its `admin_action` record and return the answer.
fn finish(
    mut response: Response,
    mut detail: Map<String, Value>,
    disposition: Disposition,
    trace: Option<Arc<str>>,
) -> Response {
    detail.insert("disposition".into(), disposition.as_str().into());
    if let Some(trace) = trace {
        detail.insert("invocation_trace".into(), trace.as_ref().into());
    }
    response.extensions_mut().insert(AuditDetail(detail));
    response
}
