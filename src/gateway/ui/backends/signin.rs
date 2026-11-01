// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting and confirming a person's sign-in to an OAuth backend.
//!
//! Implements:
//!   POST `/ui/api/backends/:name/signin`          — start a sign-in
//!   POST `/ui/api/backends/:name/signin/confirm`  — confirm or cancel it
//!
//! Guards, in order: admin, a JSON body, a valid dashboard session (so a
//! caller without one learns nothing about which backends exist), the backend
//! (404, then 409 `not_oauth`), and the gateway-host gate. The flow itself is
//! `signin_flow.rs`.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::signin_flow::{Decided, Decision, Holder, Started, decide, start};
use crate::backend::Backend;
use crate::gateway::auth::{AuthenticatedClient, Now, SessionCheck, SessionLimits, Touch};
use crate::gateway::record_principal::sign_in_owner;
use crate::gateway::router::AppState;
use crate::gateway::ui::errors::{flat_error, structured_error};
use crate::gateway::ui::guard::Guard;

/// What A12 tells a person whose dashboard is not on the gateway host.
const GATEWAY_HOST_REASON: &str = "open the dashboard at localhost or 127.0.0.1 on the gateway host to sign in (through a tunnel, forward the callback port too)";

/// Whether `authority` (the request's URI authority, else its `Host`) names
/// the gateway host itself: a loopback name or address, with any port. No name
/// is resolved.
fn is_gateway_host_authority(authority: &str) -> bool {
    authority
        .parse::<axum::http::uri::Authority>()
        .is_ok_and(|parsed| crate::gateway::is_loopback_host(parsed.host()))
}

/// The authority a request is addressed to: HTTP/2 carries it on the URI,
/// HTTP/1.1 in `Host`.
fn request_authority(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority().map(ToString::to_string).or_else(|| {
        headers
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .map(str::to_owned)
    })
}

/// A JSON body only: a cross-site form post cannot send this type without a
/// preflight, so a session cookie alone cannot start anything.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// The refusal for a caller that is not on the gateway host; `None` to go on.
fn refuse_host(uri: &Uri, headers: &HeaderMap) -> Option<Response> {
    let on_host = request_authority(uri, headers).is_some_and(|a| is_gateway_host_authority(&a));
    (!on_host).then(|| {
        structured_error(
            StatusCode::CONFLICT,
            "gateway_host_required",
            GATEWAY_HOST_REASON,
        )
        .into_response()
    })
}

/// The refusal for a body that is not JSON; `None` to go on.
fn refuse_body(headers: &HeaderMap) -> Option<Response> {
    (!is_json(headers)).then(|| {
        flat_error(StatusCode::BAD_REQUEST, "the body must be application/json").into_response()
    })
}

/// The backend `name`, or the answer for its absence (404) or, when
/// `need_oauth`, for its having no `oauth` block (409).
fn find_backend(
    state: &AppState,
    name: &str,
    need_oauth: bool,
) -> Result<Arc<Backend>, Box<Response>> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let found = state.backends.get(name);
    let Some(backend) = found else {
        return Err(Box::new(
            flat_error(StatusCode::NOT_FOUND, format!("Backend '{name}' not found"))
                .into_response(),
        ));
    };
    if need_oauth && !backend.has_oauth() {
        return Err(Box::new(
            structured_error(
                StatusCode::CONFLICT,
                "not_oauth",
                "this backend does not sign in with OAuth",
            )
            .into_response(),
        ));
    }
    Ok(backend)
}

/// The owner tag of the caller's valid dashboard session. A caller with no
/// handle, or a handle that is not valid, gets 403: no owner is ever derived
/// from nothing.
/// Judged against the request's pinned key table, so a session minted by a
/// key a reload has since removed or demoted is no session here (as in the
/// auth middleware).
fn session_owner(
    state: &AppState,
    keys: &crate::gateway::auth::ResolvedAuthConfig,
    headers: &HeaderMap,
) -> Result<String, Box<Response>> {
    let refused = || {
        Box::new(
            structured_error(
                StatusCode::FORBIDDEN,
                "dashboard_session_required",
                "sign in from a dashboard session",
            )
            .into_response(),
        )
    };
    let handle = crate::gateway::auth::session_cookie_value(headers).ok_or_else(refused)?;
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let check = state.dashboard_bootstrap.check_session_with(
        &handle,
        Now::read(),
        &limits,
        Touch::No,
        keys,
    );
    if !matches!(check, SessionCheck::Valid) {
        return Err(refused());
    }
    Ok(sign_in_owner(&state.record_key(), &handle))
}

/// Put the backend and the outcome on the request's `admin_action` record:
/// names only, never a link, state, verifier, code or token.
fn audited(mut response: Response, name: &str, outcome: &str) -> Response {
    let mut detail = serde_json::Map::new();
    detail.insert("backend".into(), name.into());
    detail.insert("sign_in_outcome".into(), outcome.into());
    response
        .extensions_mut()
        .insert(crate::gateway::ui::admin_audit::AuditDetail(detail));
    response
}

/// `body` with `key` set to `at` as RFC 3339, left out when the clock reads
/// before the epoch.
pub(in crate::gateway::ui) fn with_time(
    mut body: Value,
    key: &str,
    at: std::time::SystemTime,
) -> Value {
    if let (Some(time), Some(map)) = (
        crate::config_reload::refusals::rfc3339(at),
        body.as_object_mut(),
    ) {
        map.insert(key.to_owned(), json!(time));
    }
    body
}

/// `POST /ui/api/backends/:name/signin` — start a sign-in.
pub(super) async fn start_sign_in(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if let Some(refused) = refuse_body(&headers) {
        return refused;
    }
    if serde_json::from_slice::<Value>(&body).is_err() {
        return flat_error(StatusCode::BAD_REQUEST, "the body must be JSON").into_response();
    }
    let owner = match session_owner(&state, generation.auth(), &headers) {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let backend = match find_backend(&state, &name, true) {
        Ok(backend) => backend,
        Err(refused) => return *refused,
    };
    if let Some(refused) = refuse_host(&uri, &headers) {
        return audited(refused, &name, "refused");
    }
    let (response, outcome) = match start(&state, &backend, owner, client).await {
        Ok(Started::Link {
            url,
            attempt_id,
            expires_at,
        }) => (
            (
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-store")],
                Json(with_time(
                    json!({ "authorization_url": url, "attempt_id": attempt_id }),
                    "expires_at",
                    expires_at,
                )),
            )
                .into_response(),
            "started",
        ),
        Ok(Started::InProgress {
            holder,
            expires_at,
            retry_after_secs,
        }) => (in_progress(holder, expires_at, retry_after_secs), "refused"),
        Ok(Started::Cancelled) => (
            structured_error(
                StatusCode::CONFLICT,
                "sign_in_cancelled",
                "the backend was restarted; start the sign-in again",
            )
            .into_response(),
            "refused",
        ),
        Err(_) => (
            structured_error(
                StatusCode::BAD_GATEWAY,
                "sign_in_unavailable",
                "the sign-in could not be started",
            )
            .into_response(),
            "refused",
        ),
    };
    audited(response, &name, outcome)
}

fn in_progress(
    holder: Holder,
    expires_at: std::time::SystemTime,
    retry_after_secs: u64,
) -> Response {
    (
        StatusCode::CONFLICT,
        Json(with_time(
            json!({
                "error": "sign_in_in_progress",
                "message": "a sign-in for this backend is already in progress",
                "owner": holder.word(),
                "retry_after_secs": retry_after_secs,
            }),
            "expires_at",
            expires_at,
        )),
    )
        .into_response()
}

/// The body of a confirm.
#[derive(serde::Deserialize)]
struct ConfirmBody {
    decision: Decision,
    attempt_id: String,
}

/// `POST /ui/api/backends/:name/signin/confirm` — confirm or cancel it.
pub(super) async fn confirm_sign_in(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if let Some(refused) = refuse_body(&headers) {
        return refused;
    }
    let Ok(ask) = serde_json::from_slice::<ConfirmBody>(&body) else {
        return flat_error(
            StatusCode::BAD_REQUEST,
            "expected a decision and an attempt_id",
        )
        .into_response();
    };
    let owner = match session_owner(&state, generation.auth(), &headers) {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };
    let backend = match find_backend(&state, &name, false) {
        Ok(backend) => backend,
        Err(refused) => return *refused,
    };
    if let Some(refused) = refuse_host(&uri, &headers) {
        return audited(refused, &name, "refused");
    }
    let decided = decide(&state, &backend, &owner, &ask.attempt_id, ask.decision).await;
    let (response, outcome) = match decided {
        Decided::Done => {
            let word = if ask.decision == Decision::Confirm {
                "confirmed"
            } else {
                "cancelled"
            };
            (
                (
                    StatusCode::OK,
                    Json(json!({ "backend": name, "outcome": word })),
                )
                    .into_response(),
                word,
            )
        }
        Decided::NoSignIn => (
            structured_error(
                StatusCode::NOT_FOUND,
                "no_sign_in",
                "no sign-in in progress for you",
            )
            .into_response(),
            "refused",
        ),
        Decided::NotReady { retry_after_secs } => (
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "sign_in_not_ready",
                    "message": "the sign-in has not come back from the provider yet",
                    "retry_after_secs": retry_after_secs,
                })),
            )
                .into_response(),
            "refused",
        ),
        Decided::SaveFailed => (
            structured_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign_in_save_failed",
                "the sign-in could not be saved; start it again",
            )
            .into_response(),
            "failed",
        ),
    };
    audited(response, &name, outcome)
}

#[cfg(test)]
#[path = "signin_gate_tests.rs"]
mod gate_tests;

#[cfg(test)]
#[path = "signin_admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "signin_fixture.rs"]
mod fixture;
#[cfg(test)]
#[path = "signin_outcome_tests.rs"]
mod outcome_tests;
#[cfg(test)]
#[path = "signin_owner_tests.rs"]
mod owner_tests;
#[cfg(test)]
#[path = "signin_read_tests.rs"]
mod read_tests;
#[cfg(test)]
#[path = "signin_secrecy_tests.rs"]
mod secrecy_tests;
#[cfg(test)]
#[path = "signin_settle_tests.rs"]
mod settle_tests;
#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "signin_timing_tests.rs"]
mod timing_tests;
#[cfg(test)]
#[path = "signin_window_tests.rs"]
mod window_tests;
