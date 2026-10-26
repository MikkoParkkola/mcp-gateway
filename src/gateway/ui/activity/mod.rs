// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity page's reads and exports over the transparency logs: the
//! invocation log and the governance log, newest first, as rows built from a
//! per-kind allowlist.

mod access;
mod csv;
mod cursor;
mod reader;
mod rows;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use self::access::{Access, Refused};
use self::reader::{Limits, read_page};
use self::rows::{FeedOutcome, Filter, kind_of, owned_by, row};
use super::AppState;
use super::errors::{auth_required, flat_error};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::routes;
use crate::key_server::oidc::VerifiedIdentity;

/// Rows per page unless the caller asks for fewer or more.
const DEFAULT_LIMIT: usize = 50;
/// The most rows one page returns.
const MAX_LIMIT: usize = 200;
/// The most bytes one page examines; a sparse filter past it gets
/// `scan_exhausted` and a token to keep looking.
const PAGE_SCAN_BYTES: u64 = 8 << 20;

/// The outcomes the list can filter on today.
const SUPPORTED_OUTCOMES: [&str; 3] = ["ok", "failed", "blocked"];

pub(super) fn activity_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_ACTIVITY, get(list))
}

/// The list's query, as sent. Parsed by [`parse`].
#[derive(Debug, Default, Deserialize)]
pub(super) struct ListQuery {
    outcome: Option<String>,
    server: Option<String>,
    caller: Option<String>,
    rule: Option<String>,
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    limit: Option<String>,
}

/// The logs a page reads, and the secret that checks their signatures.
pub(super) struct Logs {
    pub(super) invocation: PathBuf,
    pub(super) governance: Option<PathBuf>,
    pub(super) secret: Option<Vec<u8>>,
}

fn logs(state: &AppState) -> Option<Logs> {
    let invocation = state.transparency_log.as_ref()?.path();
    let governance = state
        .control_plane_store
        .as_ref()
        .and(state.control_plane_base.as_ref())
        .map(|base| {
            base.path
                .join(crate::control_plane::role_mapping::GOVERNANCE_LOG_FILE)
        });
    let secret = state
        .live_config
        .get()
        .security
        .transparency_log
        .shared_secret
        .clone();
    Some(Logs {
        invocation,
        governance,
        secret: (!secret.is_empty()).then(|| secret.into_bytes()),
    })
}

fn bad_request(body: Value) -> Response {
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

fn refused(r: Refused) -> Response {
    match r {
        Refused::Unauthenticated => auth_required(StatusCode::UNAUTHORIZED).into_response(),
        Refused::Forbidden => flat_error(
            StatusCode::FORBIDDEN,
            "Activity needs an admin credential or an OIDC identity mapped to a role",
        )
        .into_response(),
    }
}

async fn list(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Query(query): Query<ListQuery>,
) -> Response {
    let access = match access::resolve(
        client.as_ref().map(|Extension(c)| c),
        identity.as_ref().map(|Extension(i)| i),
        &state.live_config.get().control_plane.role_mapping,
    ) {
        Ok(access) => access,
        Err(r) => return refused(r),
    };
    let Some(logs) = logs(&state) else {
        return flat_error(StatusCode::NOT_FOUND, "no transparency log is configured")
            .into_response();
    };
    tokio::task::spawn_blocking(move || list_page(&logs, &access, &query))
        .await
        .unwrap_or_else(|_| {
            flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the activity read failed",
            )
            .into_response()
        })
}

/// A parsed query: the filter, the page size, and where to resume.
struct Parsed {
    filter: Filter,
    limit: usize,
    cursor: Option<reader::Cursor>,
    /// A token was sent but is not this process's: read from the newest row.
    token_reset: bool,
}

fn time(
    field: &str,
    value: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::FixedOffset>>, Response> {
    value
        .map(|t| {
            chrono::DateTime::parse_from_rfc3339(t).map_err(|_| {
                bad_request(json!({"error": format!("`{field}` must be an RFC 3339 time")}))
            })
        })
        .transpose()
}

fn parse(q: &ListQuery) -> Result<Parsed, Response> {
    let outcome = match q.outcome.as_deref() {
        None => None,
        Some("ok") => Some(FeedOutcome::Ok),
        Some("failed") => Some(FeedOutcome::Failed),
        Some("blocked") => Some(FeedOutcome::Blocked),
        Some("cleaned") => {
            return Err(bad_request(json!({
                "error": "answer changes are not recorded by this gateway version",
                "supported": SUPPORTED_OUTCOMES,
            })));
        }
        Some(_) => {
            return Err(bad_request(json!({
                "error": "outcome not supported",
                "supported": SUPPORTED_OUTCOMES,
            })));
        }
    };
    if q.rule.is_some() {
        return Err(bad_request(
            json!({"error": "rules are not recorded by this gateway version"}),
        ));
    }
    let limit = match q.limit.as_deref() {
        None => DEFAULT_LIMIT,
        Some(l) => match l.parse::<usize>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
            _ => {
                return Err(bad_request(
                    json!({"error": format!("`limit` must be 1 to {MAX_LIMIT}")}),
                ));
            }
        },
    };
    let cursor = q.cursor.as_deref().map(cursor::decode);
    Ok(Parsed {
        filter: Filter {
            outcome,
            server: q.server.clone(),
            caller: q.caller.clone(),
            q: q.q.clone(),
            from: time("from", q.from.as_deref())?,
            to: time("to", q.to.as_deref())?,
        },
        limit,
        token_reset: matches!(cursor, Some(None)),
        cursor: cursor.flatten(),
    })
}

/// One page of the list. Blocking: it reads the log files.
pub(super) fn list_page(logs: &Logs, access: &Access, query: &ListQuery) -> Response {
    let parsed = match parse(query) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let limits = Limits {
        matches: parsed.limit,
        bytes: PAGE_SCAN_BYTES,
    };
    let keep = |line: &reader::Line| {
        kind_of(line).is_some_and(|kind| {
            parsed.filter.matches(line, kind)
                && match access {
                    Access::All => true,
                    Access::Own { issuer, subject } => owned_by(line, kind, issuer, subject),
                }
        })
    };
    let page = match read_page(
        &logs.invocation,
        logs.governance.as_deref(),
        parsed.cursor.clone(),
        limits,
        keep,
    ) {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%error, "activity read failed");
            return flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the activity log could not be read",
            )
            .into_response();
        }
    };
    let rows: Vec<Value> = page
        .lines
        .iter()
        .filter_map(|line| row(line, logs.secret.as_deref()))
        .collect();
    Json(json!({
        "rows": rows,
        "next_cursor": page.next.as_ref().map(cursor::encode),
        "scan_exhausted": page.scan_exhausted,
        "cursor_reset": page.cursor_reset || parsed.token_reset,
        "unreadable_lines": page.unreadable.len(),
        "order": "recorded",
    }))
    .into_response()
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod list_tests;
