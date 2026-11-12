// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity page's reads and exports over the transparency logs: the
//! invocation log and the governance log, newest first, as rows built from a
//! per-kind allowlist.

// Widened within the UI so the status report decides Activity access with
// the resolver the routes use, not a copy of its role rules.
pub(in crate::gateway::ui) mod access;
mod answer;
mod csv;
mod cursor;
mod export;
pub(in crate::gateway::ui) mod forward;
mod joiner;
mod key_lookup;
mod reader;
mod receipt;
mod receipt_scan;
/// The decision set's startup read of one record kind.
pub(super) mod replay;
mod rows;
mod seek;
mod strict_scan;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use self::access::{Access, Refused};
use self::answer::{Effect, Joined, SCOPE_LABEL, SUPPORTED_EFFECTS};
use self::joiner::Joiner;
use self::reader::{Limits, Look, read_page_joined};
use self::rows::{FeedOutcome, Filter, Kind, NOT_A_CALL, kind_of, row};
use super::AppState;
use super::errors::{auth_required, flat_error};
use super::guard::Guard;
use crate::config_reload::Generation;
use crate::gateway::routes;

/// Rows per page unless the caller asks for fewer or more.
const DEFAULT_LIMIT: usize = 50;
/// The most rows one page returns.
const MAX_LIMIT: usize = 200;
/// The most bytes one page examines; a sparse filter past it gets
/// `scan_exhausted` and a token to keep looking.
const PAGE_SCAN_BYTES: u64 = 8 << 20;

/// The outcomes the list can filter on today.
const SUPPORTED_OUTCOMES: [&str; 4] = ["ok", "failed", "blocked", "cleaned"];

pub(super) fn activity_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_ACTIVITY, get(list))
        .route(routes::UI_ACTIVITY_EXPORT, get(export_route))
        .route(routes::UI_ACTIVITY_RECEIPT, get(receipt_route))
        .route(routes::UI_KEY_SERVER_LOOKUP_EMAIL, post(key_lookup::lookup))
}

/// The list's query, as sent. Parsed by [`parse`].
#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    outcome: Option<String>,
    effect: Option<String>,
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
struct Logs {
    invocation: PathBuf,
    governance: Option<PathBuf>,
    secret: Option<Vec<u8>>,
}

impl Logs {
    /// The anchors and secret one request checks rows with.
    fn check(&self) -> rows::Check<'_> {
        rows::Check::new(
            self.secret.as_deref(),
            &self.invocation,
            self.governance.as_deref(),
        )
    }
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
    Some(Logs {
        invocation,
        governance,
        secret: verification_secret(&state.live_config),
    })
}

/// The key rows' HMACs are checked with: the one the logger runs with. A
/// reload changes the configured key, not the running logger's, so a key
/// loaded but not yet running would read every row as invalid.
fn verification_secret(live: &crate::config_reload::LiveConfig) -> Option<Vec<u8>> {
    let secret = &live.running().security.transparency_log.shared_secret;
    (!secret.is_empty()).then(|| secret.clone().into_bytes())
}

/// An early answer from a parsing or admission step. Boxed: a `Response`
/// is large, and the happy path should not carry its size.
type Early = Box<Response>;

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

/// The caller's access and the logs to read, or the refusal. The role is the
/// one the request's pinned generation maps (ADR-023).
fn admit(
    state: &AppState,
    generation: &Generation,
    guard: &Guard,
) -> Result<(Access, Logs), Early> {
    let mapping = &generation.config().control_plane.role_mapping;
    let access = guard.admit_activity(|client, identity| {
        access::resolve(client, identity, mapping).map_err(|r| Box::new(refused(r)))
    })?;
    let logs = logs(state).ok_or_else(|| {
        Box::new(
            flat_error(StatusCode::NOT_FOUND, "no transparency log is configured").into_response(),
        )
    })?;
    Ok((access, logs))
}

/// Run a blocking read off the async runtime, holding one of `reads`' slots
/// (the state's [`ProcessFacts::activity_reads`]); a read beyond the limit waits
/// its turn. The slot moves into the blocking closure, so it is held until the
/// read itself finishes, even when the caller stops waiting.
///
/// [`ProcessFacts::activity_reads`]: crate::gateway::router::ProcessFacts::activity_reads
async fn blocking(
    reads: &Arc<tokio::sync::Semaphore>,
    read: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    let Ok(permit) = Arc::clone(reads).acquire_owned().await else {
        return flat_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the activity read failed",
        )
        .into_response();
    };
    tokio::task::spawn_blocking(move || {
        let _held = permit;
        read()
    })
    .await
    .unwrap_or_else(|_| {
        flat_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the activity read failed",
        )
        .into_response()
    })
}

/// What one live-stream read is given: the list's page byte budget, and the
/// key the rows' HMACs are checked with, resolved as the list resolves it.
pub(in crate::gateway::ui) struct StreamRead {
    pub(in crate::gateway::ui) bytes: u64,
    pub(in crate::gateway::ui) secret: Option<Vec<u8>>,
}

/// Run one live-stream read under the same gate as the list, the receipt and
/// the export. The permit moves into the blocking closure, so it is held
/// until the read itself finishes, even when the caller stops waiting.
pub(in crate::gateway::ui) async fn stream_read<T: Send + 'static>(
    state: &AppState,
    read: impl FnOnce(StreamRead) -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    let given = StreamRead {
        bytes: PAGE_SCAN_BYTES,
        secret: verification_secret(&state.live_config),
    };
    let permit = Arc::clone(state.process.activity_reads())
        .acquire_owned()
        .await
        .map_err(|_| std::io::Error::other("the activity read gate is closed"))?;
    tokio::task::spawn_blocking(move || {
        let _held = permit;
        read(given)
    })
    .await
    .map_err(|_| std::io::Error::other("the activity read did not finish"))?
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Query(query): Query<ListQuery>,
) -> Response {
    match admit(&state, &generation, &guard) {
        Ok((access, logs)) => {
            blocking(state.process.activity_reads(), move || {
                list_page(&logs, &access, &query)
            })
            .await
        }
        Err(r) => *r,
    }
}

fn not_kept() -> Response {
    flat_error(StatusCode::NOT_FOUND, "no such entry in the kept log").into_response()
}

async fn receipt_route(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Path(id): Path<String>,
) -> Response {
    let (access, logs) = match admit(&state, &generation, &guard) {
        Ok(admitted) => admitted,
        Err(r) => return *r,
    };
    let Some(id) = receipt::parse_id(&id) else {
        return not_kept();
    };
    let log = match id.log {
        reader::Which::Invocation => logs.invocation.clone(),
        reader::Which::Governance => match logs.governance.clone() {
            Some(path) => path,
            None => return not_kept(),
        },
    };
    blocking(
        state.process.activity_reads(),
        move || match receipt::receipt(&log, &id, &access, &logs.check()) {
            Ok(Some(body)) => Json(body).into_response(),
            Ok(None) => not_kept(),
            Err(error) => {
                tracing::warn!(%error, "activity receipt read failed");
                flat_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the activity log could not be read",
                )
                .into_response()
            }
        },
    )
    .await
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
) -> Result<Option<chrono::DateTime<chrono::FixedOffset>>, Early> {
    value
        .map(|t| {
            chrono::DateTime::parse_from_rfc3339(t).map_err(|_| {
                Box::new(bad_request(
                    json!({"error": format!("`{field}` must be an RFC 3339 time")}),
                ))
            })
        })
        .transpose()
}

fn parse(q: &ListQuery) -> Result<Parsed, Early> {
    let outcome = match q.outcome.as_deref() {
        // `cleaned` filters on the joined effect, not on a call's outcome.
        None | Some("cleaned") => None,
        Some("ok") => Some(FeedOutcome::Ok),
        Some("failed") => Some(FeedOutcome::Failed),
        Some("blocked") => Some(FeedOutcome::Blocked),
        Some(_) => {
            return Err(Box::new(bad_request(json!({
                "error": "outcome not supported",
                "supported": SUPPORTED_OUTCOMES,
            }))));
        }
    };
    let effect = match q.effect.as_deref().map(Effect::parse) {
        None => None,
        Some(Some(e)) => Some(e),
        Some(None) => {
            return Err(Box::new(bad_request(json!({
                "error": "effect not supported",
                "supported": SUPPORTED_EFFECTS,
            }))));
        }
    };
    let limit = match q.limit.as_deref() {
        None => DEFAULT_LIMIT,
        Some(l) => match l.parse::<usize>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
            _ => {
                return Err(Box::new(bad_request(
                    json!({"error": format!("`limit` must be 1 to {MAX_LIMIT}")}),
                )));
            }
        },
    };
    let cursor = q.cursor.as_deref().map(cursor::decode);
    Ok(Parsed {
        filter: Filter {
            outcome,
            cleaned: q.outcome.as_deref() == Some("cleaned"),
            effect,
            server: q.server.clone(),
            caller: q.caller.clone(),
            q: q.q.clone(),
            rule: q.rule.clone(),
            from: time("from", q.from.as_deref())?,
            to: time("to", q.to.as_deref())?,
        },
        limit,
        token_reset: matches!(cursor, Some(None)),
        cursor: cursor.flatten(),
    })
}

/// One page of the list. Blocking: it reads the log files.
fn list_page(logs: &Logs, access: &Access, query: &ListQuery) -> Response {
    let parsed = match parse(query) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let limits = Limits {
        matches: parsed.limit,
        bytes: PAGE_SCAN_BYTES,
    };
    let check = logs.check();
    let joiner = std::cell::RefCell::new(Joiner::new(&check));
    let mut answers: Vec<Joined> = Vec::new();
    let mut fold = |line: &reader::Line| {
        joiner.borrow_mut().observe(line);
    };
    let keep = |line: &reader::Line, seen| {
        let mut j = joiner.borrow_mut();
        if j.observe(line) {
            return false;
        }
        let Some(kind) = kind_of(line) else {
            return false;
        };
        // Only a call has an answer to join; a refusal has none.
        let this = if kind == Kind::Call {
            j.join(line, seen)
        } else {
            NOT_A_CALL
        };
        if !access.admits(line, kind) {
            return false;
        }
        if kind == Kind::Call {
            j.count(&this);
        }
        let hit = parsed.filter.matches(line, kind, &this);
        if hit {
            answers.push(this);
        }
        hit
    };
    let look = if parsed.cursor.is_some() {
        Look::Fold(&mut fold)
    } else {
        Look::Carried(reader::Seen {
            above: 0,
            head_covered: true,
        })
    };
    let page = match read_page_joined(
        &logs.invocation,
        logs.governance.as_deref(),
        parsed.cursor.as_ref(),
        limits,
        look,
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
    debug_assert_eq!(answers.len(), page.lines.len());
    let rows: Vec<Value> = page
        .lines
        .iter()
        .zip(&answers)
        .filter_map(|(line, j)| row(line, &check, j))
        .collect();
    let counts = joiner.into_inner();
    Json(json!({
        "rows": rows,
        // Log-wide, even when every row here is valid.
        "signing_anchor": {
            "invocation": check.report(reader::Which::Invocation),
            "governance": check.report(reader::Which::Governance),
        },
        "next_cursor": page.next.as_ref().map(cursor::encode),
        "scan_exhausted": page.scan_exhausted,
        "cursor_reset": page.cursor_reset || parsed.token_reset,
        "unreadable_lines": page.unreadable.len(),
        "order": "recorded",
        "join_incomplete": counts.join_incomplete,
        "answer_integrity_failed": counts.answer_integrity_failed,
        "answer_integrity_scope": SCOPE_LABEL,
    }))
    .into_response()
}

/// The export's query: the list's filters and the format.
#[derive(Debug, Default, Deserialize)]
struct ExportQuery {
    #[serde(flatten)]
    list: ListQuery,
    format: Option<String>,
}

/// The filters an export ran under, as sent, for its manifest.
fn filters_sent(q: &ListQuery) -> Value {
    json!({
        "outcome": q.outcome, "effect": q.effect, "server": q.server, "caller": q.caller,
        "q": q.q, "rule": q.rule, "from": q.from, "to": q.to,
    })
}

async fn export_route(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Query(query): Query<ExportQuery>,
) -> Response {
    let (access, logs) = match admit(&state, &generation, &guard) {
        Ok(admitted) => admitted,
        Err(r) => return *r,
    };
    let signer = state.meta_mcp.public_provenance_signer();
    blocking(state.process.activity_reads(), move || {
        export_response(&logs, &access, &query, signer.as_deref())
    })
    .await
}

/// One export. NDJSON is signed with the provenance key and refused without
/// one; the gateway never makes a key nobody publishes. CSV is unsigned.
fn export_response(
    logs: &Logs,
    access: &Access,
    query: &ExportQuery,
    signer: Option<&crate::trust::provenance_public::ProvenancePublicSigner>,
) -> Response {
    use axum::http::header;
    let parsed = match parse(&query.list) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let csv = match query.format.as_deref() {
        None | Some("ndjson") => false,
        Some("csv") => true,
        Some(_) => return bad_request(json!({"error": "`format` is ndjson or csv"})),
    };
    let signer = match (csv, signer) {
        (false, None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!(
                        "{} is not set: the NDJSON export is signed and this gateway has no signing key",
                        crate::trust::provenance_public::PROVENANCE_SEED_ENV
                    ),
                    "csv": "CSV is unsigned: evidence to read, not to verify",
                })),
            )
                .into_response();
        }
        (_, signer) => signer,
    };
    let size = if csv {
        export::csv_size
    } else {
        export::ndjson_size
    };
    // The cap covers the whole download: room is kept for the framing.
    let framing = if csv {
        export::csv_framing()
    } else {
        export::MANIFEST_RESERVE
    };
    let caps = export::Caps {
        bytes: export::CAPS.bytes - framing,
        ..export::CAPS
    };
    let collected = match export::collect(
        &logs.invocation,
        logs.governance.as_deref(),
        &parsed.filter,
        access,
        &logs.check(),
        caps,
        size,
    ) {
        Ok(c) => c,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            return flat_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the log rotated past this export while it ran; start it again",
            )
            .into_response();
        }
        Err(error) => {
            tracing::warn!(%error, "activity export read failed");
            return flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the activity log could not be read",
            )
            .into_response();
        }
    };
    match signer {
        Some(signer) if !csv => (
            [
                (header::CONTENT_TYPE, "application/x-ndjson"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"activity.ndjson\"",
                ),
            ],
            export::ndjson(&collected, filters_sent(&query.list), signer),
        )
            .into_response(),
        _ => (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"activity.csv\"",
                ),
            ],
            export::csv(&collected),
        )
            .into_response(),
    }
}

#[cfg(test)]
#[path = "answer_alloc_tests.rs"]
mod answer_alloc_tests;
#[cfg(test)]
#[path = "answer_budget_tests.rs"]
mod answer_budget_tests;
#[cfg(test)]
#[path = "answer_export2_tests.rs"]
mod answer_export2_tests;
#[cfg(test)]
#[path = "answer_export3_tests.rs"]
mod answer_export3_tests;
#[cfg(test)]
#[path = "answer_export_tests.rs"]
mod answer_export_tests;
#[cfg(test)]
#[path = "answer_far_tests.rs"]
mod answer_far_tests;
#[cfg(test)]
#[path = "answer_fixture_tests.rs"]
mod answer_fixture;
#[cfg(test)]
#[path = "answer_integrity2_tests.rs"]
mod answer_integrity2_tests;
#[cfg(test)]
#[path = "answer_integrity_tests.rs"]
mod answer_integrity_tests;
#[cfg(test)]
#[path = "answer_joiner_tests.rs"]
mod answer_joiner_tests;
#[cfg(test)]
#[path = "answer_list_tests.rs"]
mod answer_list_tests;
#[cfg(test)]
#[path = "answer_page_tests.rs"]
mod answer_page_tests;
#[cfg(test)]
#[path = "answer_profile_tests.rs"]
mod answer_profile_tests;
#[cfg(test)]
#[path = "answer_progress_tests.rs"]
mod answer_progress_tests;
#[cfg(test)]
#[path = "answer_receipt2_tests.rs"]
mod answer_receipt2_tests;
#[cfg(test)]
#[path = "answer_receipt3_tests.rs"]
mod answer_receipt3_tests;
#[cfg(test)]
#[path = "answer_receipt_tests.rs"]
mod answer_receipt_tests;
#[cfg(test)]
#[path = "answer_segment_tests.rs"]
mod answer_segment_tests;
#[cfg(test)]
#[path = "answer_stream_tests.rs"]
mod answer_stream_tests;
#[cfg(test)]
#[path = "decision_export_tests.rs"]
mod decision_export_tests;
#[cfg(test)]
#[path = "decision_fixtures_tests.rs"]
mod decision_fixtures;
#[cfg(test)]
#[path = "decision_receipt_tests.rs"]
mod decision_receipt_tests;
#[cfg(test)]
#[path = "list_tests.rs"]
mod list_tests;
#[cfg(test)]
#[path = "refusal_tests.rs"]
mod refusal_tests;
#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;
#[cfg(test)]
#[path = "security_tests.rs"]
mod security_tests;
#[cfg(test)]
#[path = "sigstate_tests.rs"]
mod sigstate_tests;

#[cfg(test)]
#[path = "key_lookup_route_tests.rs"]
mod key_lookup_route_tests;
