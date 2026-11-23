// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config history routes: the kept versions and reload events (GET),
//! and an admin's restore of one kept version's gateway.yaml (POST) through
//! the shared audited writer.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, State, rejection::JsonRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::errors::{
    WriteRoute, flat_error, incomplete, no_config_file, refused_write, structured_error,
};
use super::guard::Guard;
use crate::config_persistence::keyedit::Template;
use crate::config_reload::history::{Event, Lookup, Snapshot, Source};
use crate::config_reload::{
    Expected, IntentKind, ReloadOutcome, Replace, ReplaceOutcome, ReplaceReload, Replaced,
    StatusChange,
};
use crate::gateway::auth::SessionMintedBy;
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// How a refused restore is logged and answered (the shared writer answers).
const RESTORE_WRITE: WriteRoute = WriteRoute {
    log: "config restore route",
    change: "the restore",
};

/// Both routes, merged into the UI's API router.
pub(super) fn config_history_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_CONFIG_HISTORY, get(history))
        .route(routes::UI_CONFIG_RESTORE, post(restore))
}

/// The kept versions and the events, newest first, with the served version
/// marked: a projection built field by field, so no stored byte, diff or
/// field added later can reach the answer.
async fn history(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Some(hook) = state.live_config.history_hook() else {
        return no_config_file().into_response();
    };
    let store = Arc::clone(&hook.store);
    match tokio::task::spawn_blocking(move || store.contents()).await {
        Ok(Ok((versions, events))) => {
            // Sampled after the read, as a restore's baseline is.
            let served = state.live_config.served_revision();
            Json(projection(&versions, &events, served.as_deref())).into_response()
        }
        Ok(Err(_)) => unreadable(UNREADABLE_STORE),
        Err(_) => unreadable(UNREADABLE_TASK),
    }
}

/// The log line's cause when the store's file cannot be read or parsed.
const UNREADABLE_STORE: &str = "the history file could not be read or parsed";
/// The log line's cause when the blocking read did not finish.
const UNREADABLE_TASK: &str = "the history read did not finish";

/// One fixed answer for a history that cannot be read or parsed: no path,
/// no parser text. The log line names which of the two failed, nothing more.
fn unreadable(cause: &'static str) -> Response {
    tracing::warn!(cause, "config history route: the history could not be read");
    structured_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "history_unreadable",
        "the config history could not be read; nothing was changed",
    )
    .into_response()
}

fn projection(versions: &[Snapshot], events: &[Event], served: Option<&str>) -> Value {
    // Only the newest copy of the served revision is marked: the copy the
    // store pins and a restore of that revision writes.
    let marked = served.and_then(|served| versions.iter().rposition(|v| v.revision == served));
    let listed: Vec<Value> = versions
        .iter()
        .enumerate()
        .rev()
        .map(|(index, version)| {
            let files: Vec<Value> = version
                .files
                .iter()
                .map(|file| json!({ "path": file.path, "present": file.bytes.is_some() }))
                .collect();
            json!({
                "revision": version.revision,
                "at": version.at,
                "source": source(&version.source),
                "pending_restart": version.pending_restart,
                "files": files,
                "running": Some(index) == marked,
            })
        })
        .collect();
    let happened: Vec<Value> = events.iter().rev().map(event).collect();
    json!({ "running": served, "versions": listed, "events": happened })
}

fn source(source: &Source) -> Value {
    match source {
        Source::Start => json!({ "kind": "start" }),
        Source::File => json!({ "kind": "file" }),
        Source::Ui { who } => json!({ "kind": "ui", "who": who }),
    }
}

/// One event, its optional parts only when present; never its diff.
fn event(event: &Event) -> Value {
    let mut out = Map::new();
    out.insert("at".into(), json!(event.at));
    out.insert("source".into(), source(&event.source));
    out.insert("outcome".into(), json!(event.outcome));
    if let Some(revision) = &event.revision {
        out.insert("revision".into(), json!(revision));
    }
    if event.unchanged {
        out.insert("unchanged".into(), json!(true));
    }
    if let Some(still) = &event.still_running {
        out.insert(
            "still_running".into(),
            json!({ "revision": still.revision, "since": still.since }),
        );
    }
    if let Some(line) = event.location {
        out.insert("location".into(), json!(line));
    }
    Value::Object(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreBody {
    version: String,
}

/// Write one kept version's gateway.yaml back through the shared audited
/// writer as a Restore, keeping the replaced file beside it. Each step
/// answers before the next runs.
async fn restore(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Extension(arrival): Extension<Arc<crate::config_reload::Generation>>,
    session: Option<Extension<SessionMintedBy>>,
    body: Result<Json<RestoreBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // A restore rewrites the whole file, auth included: a caller barred from
    // auth edits is barred here, before anything is read or locked.
    let quota = guard
        .client
        .as_ref()
        .and_then(|client| client.quota_principal.as_ref());
    let minted = session.as_ref().map(|Extension(SessionMintedBy(key))| key);
    // The table the request was authenticated against, never a later one: a
    // reload that drops the key mid-request must not lift the ban.
    if super::settings::caller_is_cli_key(arrival.auth(), quota, minted) {
        return super::guard::Refused::Forbidden.into_response();
    }
    let version = match body {
        Ok(Json(RestoreBody { version })) if !version.is_empty() => version,
        _ => return flat_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_body").into_response(),
    };
    let (Some(context), Some(hook)) = (
        state.meta_mcp.reload_context(),
        state.live_config.history_hook(),
    ) else {
        return no_config_file().into_response();
    };
    let (store, live, wanted) = (
        Arc::clone(&hook.store),
        Arc::clone(&state.live_config),
        version.clone(),
    );
    let read = tokio::task::spawn_blocking(move || {
        store.lookup_against(&wanted, || live.served_revision())
    })
    .await;
    let (found, baseline) = match read {
        Ok(Ok(read)) => read,
        Ok(Err(_)) => return unreadable(UNREADABLE_STORE),
        Err(_) => return unreadable(UNREADABLE_TASK),
    };
    let kept = match found {
        Lookup::Kept(kept) => kept,
        Lookup::NoLongerKept => {
            return refusal(
                StatusCode::GONE,
                "no_longer_kept",
                "that config version is no longer kept, so it cannot be restored",
            );
        }
        Lookup::Unknown => {
            return refusal(
                StatusCode::NOT_FOUND,
                "unknown_version",
                "no kept or recorded config version has that id",
            );
        }
    };
    let Some(bytes) = kept
        .files
        .iter()
        .find(|file| file.path == hook.config_path)
        .and_then(|file| file.bytes.clone())
    else {
        return refusal(
            StatusCode::CONFLICT,
            "not_restorable",
            "that config version holds no gateway.yaml to restore",
        );
    };
    let unwritten = not_restored(&kept, baseline.as_ref(), &hook.config_path);
    let replace = Replace {
        expected: Expected::Any,
        compute: Box::new(move |_current: &[u8]| -> Result<Template, String> {
            Ok(Template::plain(bytes))
        }),
        replaced: Replaced::KeepBeside,
        secrets: None,
        // A restore never holds bytes for a restart: one that would bring
        // in a first key, or keep a waiting one, is refused by the writer.
        status_change: StatusChange::Refuse,
    };
    let who =
        super::admin_audit::caller_who(&state, guard.client.as_ref(), guard.identity.as_ref());
    match super::write_audited(&state, context, replace, IntentKind::Restore, &who).await {
        Ok(outcome) => match &outcome.reload {
            ReplaceReload::Applied(reload) => restored(&version, &outcome, reload, unwritten),
            // A restore passes `Refuse`; the writer never holds it.
            ReplaceReload::HeldForRestart { .. } => incomplete(RESTORE_WRITE, "held_for_restart"),
        },
        Err(error) => refused_write(RESTORE_WRITE, &error),
    }
}

fn refusal(status: StatusCode, code: &'static str, text: &'static str) -> Response {
    structured_error(status, code, text).into_response()
}

/// The success answer. `changed` is false when the bytes were already the
/// file's: then no revision, no kept copy and no grants entry.
fn restored(
    version: &str,
    outcome: &ReplaceOutcome,
    reload: &ReloadOutcome,
    mut unwritten: Vec<Value>,
) -> Response {
    let changed = outcome.revision.is_some();
    if changed {
        // A restore never writes the grants file and a version holds no
        // grants bytes: live grants stay as they are.
        unwritten.push(json!({ "kind": "grants" }));
    }
    let mut answer = json!({
        "version": version,
        "changed": changed,
        "reload": reload,
        "restart_required": reload.pending_restart_fields,
        "not_restored": unwritten,
    });
    if let Some(revision) = &outcome.revision {
        answer["revision"] = json!(revision.as_str());
    }
    let kept_name = outcome
        .kept_beside
        .as_deref()
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str);
    if let Some(name) = kept_name {
        answer["kept_beside"] = json!(name);
    }
    Json(answer).into_response()
}

/// The env files a version holds beside gateway.yaml: each path with its
/// bytes (`None` when that version had no such file).
fn env_files<'a>(version: &'a Snapshot, config: &str) -> Vec<(&'a str, Option<&'a [u8]>)> {
    version
        .files
        .iter()
        .filter(|file| file.path != config)
        .map(|file| (file.path.as_str(), file.bytes.as_deref()))
        .collect()
}

/// Each env file that differs between the restored version and `baseline`
/// (the served version's kept copy), over both versions' paths: the
/// restored version's first, then those only the served one has. With no
/// baseline kept, every env file of the restored version.
fn not_restored(kept: &Snapshot, baseline: Option<&Snapshot>, config: &str) -> Vec<Value> {
    let listed = |path: &str| json!({ "path": path, "kind": "env_file" });
    let restored = env_files(kept, config);
    let Some(baseline) = baseline else {
        return restored.iter().map(|(path, _)| listed(path)).collect();
    };
    let served = env_files(baseline, config);
    let mut paths: Vec<&str> = restored.iter().map(|(path, _)| *path).collect();
    for (path, _) in &served {
        if !paths.contains(path) {
            paths.push(*path);
        }
    }
    // A path absent from a version reads as no entry, apart from one it
    // lists with no bytes.
    let on_restored: BTreeMap<&str, Option<&[u8]>> = restored.iter().copied().collect();
    let on_served: BTreeMap<&str, Option<&[u8]>> = served.iter().copied().collect();
    paths
        .into_iter()
        .filter(|path| on_restored.get(path) != on_served.get(path))
        .map(listed)
        .collect()
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_cli_tests.rs"]
mod cli_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_first_key_tests.rs"]
mod first_key_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_restore_scope_tests.rs"]
mod restore_scope_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_restore_tests.rs"]
mod restore_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_support_tests.rs"]
mod support_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_history_tests.rs"]
mod tests;
