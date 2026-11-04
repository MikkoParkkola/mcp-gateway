// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/stream`: the UI's live event feed (ADR-020).

mod activity_source;
mod conn;
mod feed;
mod guard;
mod id;
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
#[cfg(test)]
mod merge_two_log_tests;

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
/// One log's broadcast capacity, for the rows that must burst past it.
#[cfg(test)]
pub(crate) const BROADCAST: usize = feed::BROADCAST;
use self::id::StreamId;
use super::activity::access::Access;
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
/// the config endpoint's rule has it; `activity` for any caller Activity
/// admits, and `config` only for full access, never a backend-scoped key
/// (config rows are gateway-wide). A kind whose log this gateway does not
/// write is not advertised. The queue is not advertised until its source
/// exists.
pub(super) fn kinds_for(
    client: &AuthenticatedClient,
    access: Option<&Access>,
    state: &AppState,
) -> Vec<&'static str> {
    let mut kinds = vec!["status"];
    if is_admin(Some(client)) {
        kinds.push("reload");
    }
    if access.is_some() && state.transparency_log.is_some() {
        kinds.push("activity");
    }
    if matches!(access, Some(Access::All)) && state.governance_log.is_some() {
        kinds.push("config");
    }
    kinds
}

#[derive(Debug, Deserialize)]
pub(super) struct StreamQuery {
    last_event_id: Option<String>,
}

/// The log positions a reconnect carries, when its id is from this process.
/// The header wins over the query form; anything unparseable or from another
/// boot is a fresh connect, which starts each log at its head. Snapshot kinds
/// resend their latest state either way.
fn resumed(headers: &HeaderMap, query: &StreamQuery, boot: u64) -> Option<id::LogCursor> {
    let text = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .or(query.last_event_id.as_deref());
    text.and_then(|t| StreamId::parse(t).ok())
        .filter(|id| id.boot == Some(boot))
        .map(|id| id.cursor)
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
    let access = conn::activity_access(&client, caller.identity.as_ref(), &caller.generation);
    let conn = conn::Conn {
        facts: auth_facts(&state, Some(&client)),
        kinds: kinds_for(&client, access.as_ref(), &state),
        access,
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
