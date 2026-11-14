// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unused secret entries for Gateway › Settings: list them, delete one at a time.
//! The delete holds the reload lock, the config sidecar and the vault lock, in that
//! order, and re-checks every naming source under them.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{Path, Query, State, rejection::QueryRejection};
use axum::http::{HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::admin_audit::AuditDetail;
use super::errors::{no_reload_read, no_reload_write, structured_error};
use crate::config_reload::{ConfigWriteError, RELOAD_LOCK_WAIT, ReloadContext};
use crate::gateway::{router::AppState, ui::guard::Guard};
use crate::secret_store::{
    DeleteRefused, Deleted, FilesStore, Listing, NamingSources, SecretStore, Vault, delete_unused,
    is_generated_name, listing,
};

/// Fixed sentences. None repeats a path, a name, or a loader error.
const CONFIG_UNREAD: &str = "the config could not be read";
const UNREADABLE: &str = "the unused entries could not be read";
const VAULT_FAILED: &str = "the vault could not be opened";
const LOCK_FAILED: &str = "the config lock could not be taken";
const DELETE_FAILED: &str = "the delete did not finish";
const NO_KEYCHAIN: &str = "no keychain on this platform";
/// Why a keychain delete is refused where the system keychain can finish a
/// timed-out delete after this route has released its locks.
const KEYCHAIN_GUARDED: &str = "keychain entries cannot be deleted from Settings on this platform yet: \
     the system keychain can finish a timed-out delete later, after a config may name the entry again";

type Opened = Arc<dyn SecretStore + Send + Sync>;

/// `?store=keychain|files` on a delete.
#[derive(Deserialize)]
pub(super) struct StoreQuery {
    pub(super) store: String,
}

/// `BadName` 400, `NotListed` 404, `StoreMismatch`/`Named`/`Pending`/`Busy` 409 (refused,
/// nothing attempted), `TimedOut`/`Failed` 503 (the outcome is not confirmed).
pub(super) fn refusal_status(refused: &DeleteRefused) -> StatusCode {
    match refused {
        DeleteRefused::BadName => StatusCode::BAD_REQUEST,
        DeleteRefused::NotListed => StatusCode::NOT_FOUND,
        DeleteRefused::StoreMismatch
        | DeleteRefused::Named
        | DeleteRefused::Pending
        | DeleteRefused::Busy
        | DeleteRefused::KeychainUnavailable => StatusCode::CONFLICT,
        DeleteRefused::TimedOut | DeleteRefused::Failed(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The one place naming sources are gathered for `target`.
///
/// Config path, the running gateway's env files, values parsed from those files
/// by a fresh load, every process-environment value, and both capability-directory
/// lists with duplicates removed. A failed load is [`CONFIG_UNREAD`], with no detail.
fn naming_sources(ctx: &ReloadContext, target: &std::path::Path) -> Result<NamingSources, String> {
    let loaded = crate::config::Config::load_with_overlay(Some(target), ctx.env_paths())
        .map_err(|_| CONFIG_UNREAD.to_owned())?;
    let mut capability_dirs = Vec::new();
    extend_dirs(
        &mut capability_dirs,
        &ctx.live_config.get().capabilities.directories,
    );
    extend_dirs(
        &mut capability_dirs,
        &loaded.config.capabilities.directories,
    );
    Ok(NamingSources {
        config: target.to_path_buf(),
        // The files store the vault and the delete use: beside the unresolved config
        // path, which a symlinked config can put in another directory than `target`.
        entries_dir: FilesStore::new(config_dir(&ctx.config_path))
            .entries_dir()
            .to_path_buf(),
        env_files: ctx.env_paths().as_paths().to_vec(),
        env_values: loaded
            .overlay
            .assigned_values()
            .map(str::to_owned)
            .collect(),
        process_env: std::env::vars_os().map(|(_, value)| value).collect(),
        capability_dirs,
    })
}

/// Append `listed` as paths, skipping a path already present.
fn extend_dirs(dirs: &mut Vec<PathBuf>, listed: &[String]) {
    for dir in listed {
        let path = PathBuf::from(dir);
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    }
}

/// Parent of the running config path: where a save keeps the vault and the files store.
fn config_dir(path: &std::path::Path) -> &std::path::Path {
    path.parent().unwrap_or(std::path::Path::new("."))
}

/// 503 `unreadable` with a fixed sentence.
fn unreadable(message: &str) -> Response {
    structured_error(StatusCode::SERVICE_UNAVAILABLE, "unreadable", message).into_response()
}

/// `GET /ui/api/settings/secrets/unused`. Names, stores, and write times. No value, no audit.
pub(super) async fn list_unused(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Some(ctx) = state.meta_mcp.reload_context() else {
        return no_reload_read().into_response();
    };
    match tokio::task::spawn_blocking(move || read_unused(&ctx)).await {
        Ok(Ok(listed)) => Json(list_body(&listed)).into_response(),
        Ok(Err(sentence)) => unreadable(sentence),
        Err(_) => unreadable(UNREADABLE),
    }
}

/// Build sources for `ctx.config_path`, open the vault and the stores, and list.
/// A sources or vault failure is a fixed sentence.
fn read_unused(ctx: &ReloadContext) -> Result<Listing, &'static str> {
    let sources = naming_sources(ctx, &ctx.config_path).map_err(|_| CONFIG_UNREAD)?;
    let dir = config_dir(&ctx.config_path);
    let vault = Vault::for_config_dir(dir).map_err(|_| VAULT_FAILED)?;
    let files = FilesStore::new(dir);
    let keychain = crate::config::keychain::os_secret_store();
    let mut stores: Vec<&dyn SecretStore> = vec![&files];
    if let Some(store) = &keychain {
        let store: &dyn SecretStore = store.as_ref();
        stores.push(store);
    }
    Ok(listing(&vault, &stores, &sources))
}

/// `entries` of name, store kind, and RFC 3339 `written_at` (`null` at 0 ms).
/// `errors` of store kind and why. No secret value.
fn list_body(listed: &Listing) -> Value {
    json!({
        "entries": listed.entries.iter().map(|entry| json!({
            "name": entry.name,
            "store": entry.store.as_str(),
            "written_at": written_at(entry.created_at_ms),
        })).collect::<Vec<_>>(),
        "errors": listed.errors.iter().map(|(kind, why)| json!({
            "store": kind.as_str(),
            "why": why,
        })).collect::<Vec<_>>(),
    })
}

/// RFC 3339 from `created_at_ms`, or `None` (JSON null) when the index stored 0.
fn written_at(created_at_ms: u64) -> Option<String> {
    if created_at_ms == 0 {
        return None;
    }
    let millis = i64::try_from(created_at_ms).ok()?;
    chrono::DateTime::from_timestamp_millis(millis).map(|at| at.to_rfc3339())
}

/// `DELETE /ui/api/settings/secrets/unused/{name}?store=...`.
///
/// Query and name are refused before anything else is touched. From the reload
/// lock on, that lock and the config sidecar stay held until this returns, and
/// every answer records the entry, the store, and the result. Never a value.
pub(super) async fn delete_unused_entry(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Path(name): Path<String>,
    query: Result<Query<StoreQuery>, QueryRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Query(StoreQuery { store })) = query else {
        return refusal_response(&DeleteRefused::BadName);
    };
    if store != "files" && store != "keychain" {
        return refusal_response(&DeleteRefused::BadName);
    }
    if !is_generated_name(&name) {
        return refusal_response(&DeleteRefused::BadName);
    }
    if cfg!(any(target_os = "macos", windows)) && store == "keychain" {
        // The first of two copies: delete_unused refuses it again for any other caller.
        return refusal_response(&DeleteRefused::KeychainUnavailable);
    }
    let Some(ctx) = state.meta_mcp.reload_context() else {
        return no_reload_write().into_response();
    };
    let held = match ctx.hold_config(RELOAD_LOCK_WAIT).await {
        Ok(held) => held,
        Err(ConfigWriteError::Busy) => return audited(&name, &store, &DeleteRefused::Busy),
        Err(ConfigWriteError::Failed(_)) => {
            return audited(
                &name,
                &store,
                &DeleteRefused::Failed(LOCK_FAILED.to_owned()),
            );
        }
    };
    if crate::config_persistence::journal::unsettled(&held.locked.target) {
        return audited(&name, &store, &DeleteRefused::Pending);
    }
    let opened: Opened = if store == "files" {
        Arc::new(FilesStore::new(config_dir(&ctx.config_path)))
    } else {
        let Some(os) = crate::config::keychain::os_secret_store() else {
            // No OS keychain is configured here: a conflict with the request, not an outage.
            return with_audit(
                structured_error(StatusCode::CONFLICT, "no_keychain", NO_KEYCHAIN).into_response(),
                &name,
                &store,
                "no_keychain",
            );
        };
        os
    };
    // The config load, the vault and the store calls all block: they run off the
    // async workers while this task keeps both locks held.
    let target = held.locked.target.clone();
    let worker = Arc::clone(&ctx);
    let entry = name.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let sources = naming_sources(&worker, &target).map_err(DeleteRefused::Failed)?;
        let vault = Vault::for_config_dir(config_dir(&worker.config_path))
            .map_err(|_| DeleteRefused::Failed(VAULT_FAILED.to_owned()))?;
        delete_unused(
            &vault,
            opened.as_ref(),
            &entry,
            &sources,
            Instant::now() + RELOAD_LOCK_WAIT,
        )
    })
    .await;
    let Ok(outcome) = joined else {
        return audited(
            &name,
            &store,
            &DeleteRefused::Failed(DELETE_FAILED.to_owned()),
        );
    };
    match outcome {
        Ok(Deleted::Removed) => deleted(&name, &store, false),
        Ok(Deleted::AlreadyGone) => deleted(&name, &store, true),
        Err(refused) => audited(&name, &store, &refused),
    }
}

/// 200 `{"deleted","already_gone"}`, audited as `removed` or `already_gone`.
fn deleted(name: &str, store: &str, already_gone: bool) -> Response {
    let response = Json(json!({"deleted": name, "already_gone": already_gone})).into_response();
    let result = if already_gone {
        "already_gone"
    } else {
        "removed"
    };
    with_audit(response, name, store, result)
}

/// Refusal JSON, `{"error","message"}`, with no audit detail.
fn refusal_response(refused: &DeleteRefused) -> Response {
    let (code, message) = refusal_parts(refused);
    let mut response = structured_error(refusal_status(refused), code, message).into_response();
    // Busy attempted nothing and is worth retrying soon, as the save route's busy says.
    if matches!(refused, DeleteRefused::Busy) {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

/// [`refusal_response`] plus the audit detail. Used only after the reload lock is taken.
fn audited(name: &str, store: &str, refused: &DeleteRefused) -> Response {
    let (code, _) = refusal_parts(refused);
    with_audit(refusal_response(refused), name, store, code)
}

/// `secret_entry`, `store`, and `result` on the response. Never a value.
fn with_audit(mut response: Response, name: &str, store: &str, result: &str) -> Response {
    let mut detail = serde_json::Map::new();
    detail.insert("secret_entry".into(), json!(name));
    detail.insert("store".into(), json!(store));
    detail.insert("result".into(), json!(result));
    response.extensions_mut().insert(AuditDetail(detail));
    response
}

/// The refusal's code word and its fixed sentence (`Failed` keeps the store's text).
fn refusal_parts(refused: &DeleteRefused) -> (&'static str, &str) {
    match refused {
        DeleteRefused::BadName => (
            "bad_name",
            "the name or the store is not one this route deletes",
        ),
        DeleteRefused::NotListed => ("not_listed", "that entry is not listed"),
        DeleteRefused::StoreMismatch => ("store_mismatch", "that entry is in the other store"),
        DeleteRefused::Named => ("named", "a source still names that entry"),
        DeleteRefused::Pending => ("pending", "a config write is still unsettled"),
        DeleteRefused::Busy => ("busy", "a lock this delete needs is held"),
        DeleteRefused::KeychainUnavailable => ("keychain_delete_unavailable", KEYCHAIN_GUARDED),
        DeleteRefused::TimedOut => ("timed_out", "the secret store did not answer in time"),
        DeleteRefused::Failed(text) => ("failed", text),
    }
}
