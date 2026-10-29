// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/stream`: the UI's live event feed (ADR-020).

mod conn;
mod guard;
#[allow(
    dead_code,
    reason = "the log-kind merge loop is wired to the Activity source when that lands"
)]
mod id;
#[allow(
    dead_code,
    reason = "the log-kind merge loop is wired to the Activity source when that lands"
)]
mod merge;
#[cfg(test)]
mod probe;
mod sent;
mod watcher;

#[cfg(test)]
mod guard_tests;
#[cfg(test)]
mod id_tests;
#[cfg(test)]
mod merge_tests;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use tokio::sync::mpsc;

use self::guard::Refusal;
pub(crate) use self::guard::StreamHub;
#[cfg(test)]
pub(crate) use self::guard::{MAX_PER_CREDENTIAL, MAX_UI_STREAMS};
use self::id::StreamId;
use super::errors::{auth_required, flat_error};
use super::{auth_facts, is_admin};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::auth::live::{HeldCredential, current_caller, held_credential};
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The stream route.
pub(super) fn stream_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_STREAM, get(stream))
}

/// The kinds this caller gets, in `hello` order: `status` for everyone the
/// status route answers (counts only below admin), `reload` for admins, as
/// the config endpoint's rule has it. Activity, config rows and the queue are
/// not advertised until their sources exist.
pub(super) fn kinds_for(client: &AuthenticatedClient) -> Vec<&'static str> {
    let mut kinds = vec!["status"];
    if is_admin(Some(client)) {
        kinds.push("reload");
    }
    kinds
}

#[derive(Debug, Deserialize)]
pub(super) struct StreamQuery {
    last_event_id: Option<String>,
}

/// Whether the reconnect carries an id from this process. The header wins over
/// the query form; anything unparseable or from another boot is a fresh
/// connect. Snapshot kinds resend their latest state either way.
fn resumed(headers: &HeaderMap, query: &StreamQuery, boot: u64) -> bool {
    let text = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .or(query.last_event_id.as_deref());
    text.and_then(|t| StreamId::parse(t).ok())
        .is_some_and(|id| id.boot == Some(boot))
}

fn too_many(refusal: Refusal) -> Response {
    let why = match refusal {
        Refusal::Global => "Too many live streams are open; retry shortly",
        Refusal::Credential => "This credential already holds the most live streams allowed",
    };
    let mut reply = flat_error(StatusCode::SERVICE_UNAVAILABLE, why).into_response();
    reply
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    reply
}

/// `GET /ui/api/stream`: server-sent events for the shell. The same response
/// serves an `EventSource` (cookie) and a streamed `fetch` (bearer).
async fn stream(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Response {
    let auth = crate::gateway::router::build_auth_state(&state);
    let held = held_credential(&headers);
    // Judged against the live config now, as every later re-check is.
    let Some(caller) = current_caller(&auth, held.as_ref()).await else {
        return auth_required(StatusCode::UNAUTHORIZED).into_response();
    };
    let client = client.map(|Extension(c)| c).unwrap_or(caller.client);
    let hub = state.dashboard_bootstrap.stream_hub();
    let who = held
        .as_ref()
        .map_or_else(|| "anonymous".to_owned(), HeldCredential::deciding_digest);
    let guard = match hub.admit(&who, || watcher::spawn(&state)) {
        Ok(guard) => guard,
        Err(refusal) => return too_many(refusal),
    };
    let (tx, rx) = mpsc::channel(1);
    let conn = conn::Conn {
        facts: auth_facts(&state, Some(&client)),
        kinds: kinds_for(&client),
        admin: is_admin(Some(&client)),
        state: Arc::clone(&state),
        auth,
        held,
        tx,
        guard,
    };
    let boot = hub.boot();
    let resumed = resumed(&headers, &query, boot);
    tokio::spawn(conn::run(conn, boot, resumed));
    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}
