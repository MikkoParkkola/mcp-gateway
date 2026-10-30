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

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, MatchedPath, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::admin_audit::{AuditDetail, record_admin_action_as};
use super::errors::admin_auth_required;
use super::{AppState, AuthenticatedClient, is_admin};
use crate::gateway::ui_call::{Confirm, Outcome, UiCall};
use crate::key_server::oidc::VerifiedIdentity;

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
        let mut detail = Map::new();
        detail.insert(
            "via".into(),
            via_label(&state, client.as_ref(), request.extensions()).into(),
        );
        let refused = admin_auth_required().into_response();
        return finish(refused, detail, Disposition::NotRun, None);
    }
    let (parts, body) = request.into_parts();
    // A JSON body only: a cross-site form post cannot send this type without
    // a preflight, so a session cookie alone cannot start a call.
    let json = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        });
    // Every exit from here on names the caller on its admin_action record.
    let mut detail = Map::new();
    detail.insert(
        "via".into(),
        via_label(&state, client.as_ref(), &parts.extensions).into(),
    );
    if !json {
        let refused = refusal(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the body must be application/json",
            Disposition::NotRun,
        );
        return finish(refused, detail, Disposition::NotRun, None);
    }
    let ask = match parse(&parts, body).await {
        Ok(ask) => ask,
        Err(refused) => return finish(*refused, detail, Disposition::NotRun, None),
    };
    detail.insert("server".into(), ask.server.clone().into());
    detail.insert("tool".into(), ask.tool.clone().into());
    detail.insert("confirm_write".into(), ask.confirm_write.into());

    let permit = match admit(&state) {
        Ok(permit) => permit,
        Err(refused) => return finish(*refused, detail, Disposition::NotRun, None),
    };
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
    spawn_call(&state, &ui_call, internal, permit, answered, follow_up);
    let Ok(answer) = tokio::time::timeout(deadline(), answer).await else {
        return past_deadline(&ui_call, detail);
    };
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = ui_call.outcome();
    // A closed channel: the task ended without an answer (it panicked).
    let answer = answer.ok().flatten();
    let (status, disposition) = classify(&outcome, answer.as_ref());
    let response = if status == StatusCode::OK {
        ran(answer.as_ref(), latency_ms, outcome.trace.as_deref())
    } else {
        let (code, message) = wording(status);
        refusal(status, code, message, disposition)
    };
    finish(response, detail, disposition, outcome.trace)
}

/// The request body, read through the `Bytes` extractor so the gateway's one
/// configured body limit applies (`DefaultBodyLimit` binds extractors only).
async fn parse(parts: &Parts, body: Body) -> Result<CallRequest, Box<Response>> {
    let request = Request::from_parts(parts.clone(), body);
    let bytes = match Bytes::from_request(request, &()).await {
        Ok(bytes) => bytes,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return Err(Box::new(refusal(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "the body is over the gateway's size limit",
                Disposition::NotRun,
            )));
        }
        Err(_) => {
            return Err(Box::new(refusal(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "the body could not be read",
                Disposition::NotRun,
            )));
        }
    };
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(Box::new(refusal(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the body is not a JSON object",
            Disposition::NotRun,
        )));
    };
    serde_json::from_value::<CallRequest>(Value::Object(object)).map_err(|_| {
        Box::new(refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid",
            "expected server, tool, arguments (an object) and confirm_write only",
            Disposition::NotRun,
        ))
    })
}

/// The refusals before anything is built, and the permits a call runs on.
fn admit(
    state: &AppState,
) -> Result<
    (
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    ),
    Box<Response>,
> {
    // Under required signing every call carries the caller's nonce; the
    // route mints none on its behalf. Refused here: unsigned, dispatch would
    // answer with the code a missing tool also uses.
    if state.meta_mcp.requires_call_nonce() {
        return Err(Box::new(refusal(
            StatusCode::FORBIDDEN,
            "signing_required",
            "this gateway requires signed calls; use a signing client",
            Disposition::NotRun,
        )));
    }
    // One of the few UI calls that may run at once, and the drain tracker's
    // permit, so shutdown waits for a call that runs on past its answer.
    let pool = Arc::clone(state.meta_mcp.ui_call_permits()).try_acquire_owned();
    let drain = Arc::clone(&state.inflight).try_acquire_owned();
    match (pool, drain) {
        (Ok(pool), Ok(drain)) => Ok((pool, drain)),
        _ => Err(Box::new(refusal(
            StatusCode::FORBIDDEN,
            "busy",
            "too many tool calls are running from the web UI; nothing was run",
            Disposition::NotRun,
        ))),
    }
}

/// The 504. The deadline and the send race through one atomic claim: when
/// the deadline wins nothing is ever sent (not run); when the send won first
/// it runs on (may have run). Either way the task is left to finish: a call
/// the deadline claimed reaches its send claim, which refuses it, so its
/// delivery record says refused.
fn past_deadline(ui_call: &UiCall, detail: Map<String, Value>) -> Response {
    let (disposition, message) = if ui_call.cancel() {
        (Disposition::NotRun, "no answer in time; nothing was run")
    } else {
        (
            Disposition::MayHaveRun,
            "no answer in time; the tool may still be running",
        )
    };
    finish(
        refusal(
            StatusCode::GATEWAY_TIMEOUT,
            "deadline",
            message,
            disposition,
        ),
        detail,
        disposition,
        ui_call.outcome().trace,
    )
}

/// The 200 body of a call that ran.
fn ran(answer: Option<&Value>, latency_ms: u64, trace: Option<&str>) -> Response {
    let result = answer
        .and_then(|a| a.get("result"))
        .map_or(Value::Null, tool_result);
    let is_error = result.get("isError").and_then(Value::as_bool) == Some(true);
    let mut body = json!({
        "result": result,
        "is_error": is_error,
        "latency_ms": latency_ms,
        "disposition": Disposition::Ran.as_str(),
    });
    if let Some(trace) = trace {
        body["receipt"] = trace.into();
    }
    (StatusCode::OK, axum::Json(body)).into_response()
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
) {
    let state = Arc::clone(state);
    let ui_call = Arc::clone(ui_call);
    // Detached: the route's deadline never stops it (see `past_deadline`).
    drop(tokio::spawn(async move {
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
            // Named as the layer names the route's own record.
            fields.insert("route".into(), crate::gateway::routes::UI_TOOLS_CALL.into());
            fields.insert("method".into(), "POST".into());
            fields.insert("completion".into(), true.into());
            let (status, disposition) = classify(&outcome, answer.as_ref());
            fields.insert("disposition".into(), disposition.as_str().into());
            fields.insert("http_status".into(), status.as_u16().into());
            if let Some(trace) = outcome.trace {
                fields.insert("invocation_trace".into(), trace.as_ref().into());
            }
            // Its outcome is how the call ended, not "ok".
            let _ = record_admin_action_as(
                &state,
                "admin_ui",
                (follow_up.client.as_ref(), follow_up.identity.as_ref()),
                fields,
                status,
            );
        }
    }));
}

/// The status and disposition of a call, from what the dispatch recorded.
/// A JSON-RPC code is read only once the record says nothing was sent, to
/// tell an audit outage from a refusal: both are "did not run" whatever the
/// code means. A missing server or tool is answered as a refusal, as /mcp
/// answers it (no 404: the route names no more than /mcp does).
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
        (Some(_), _) if audit_down => (StatusCode::SERVICE_UNAVAILABLE, Disposition::NotRun),
        // A gate's refusal, or a sealed refusal answered as an `isError`
        // result before the send.
        (Some(_), _) => (StatusCode::FORBIDDEN, Disposition::NotRun),
    }
}

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
            // A stateless call declares what its client can answer: the web UI
            // answers no backend question, so it declares nothing.
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": revision,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
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
    // The gateway built this answer itself: the `/mcp` route sends the same
    // bytes to an MCP client.
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
        state.live_config.generation().auth().record_key(),
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
