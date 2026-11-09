// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/keys`: `{revision, keys}` for the web UI's Access page.
//!
//! Admin only. With a readable gateway.yaml the keys are the file's, in file
//! order, under the revision of the very bytes they were read from; `live` and
//! `last_used` are joined by name from the request's pinned key table. With no
//! file, or one that cannot be loaded, the keys are the pinned table's and the
//! answer says so in `file`. Every entry is built field by field from an
//! explicit list, never by serialising a key, so no secret, digest, previous
//! digest, principal or limit key can reach it. `last_used` is the key's last
//! accepted match in this process, null before its first since start.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

use super::config_file::{Gateway, read_gateway};
use super::guard::Guard;
use crate::config::ApiKeyConfig;
use crate::gateway::auth::{ResolvedApiKey, ResolvedAuthConfig};
use crate::gateway::router::AppState;

/// Under test, a request may carry a count of the handler's key-table reads,
/// so a row can prove a refusal read nothing.
#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct TableReads(pub(super) Arc<std::sync::atomic::AtomicUsize>);

/// Under test, a request may carry a hook that runs right after the file read
/// returns, so a row can rewrite the file between the read and the answer.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct AfterRead(pub(super) Arc<dyn Fn() + Send + Sync>);

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `last_used` and `live` for the live key of the same name, if there is one.
/// A key past its expiry is not live, whatever the file says.
fn joined(auth: &ResolvedAuthConfig, live: Option<&ResolvedApiKey>) -> (Option<String>, bool) {
    let last_used = live
        .and_then(|key| auth.key_last_used(key))
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .map(rfc3339);
    // Effective liveness: a CLI key whose approver is gone is listed, not live.
    let is_live = live.is_some_and(|key| {
        !crate::config::api_key_expired_now(key.expires_at)
            && auth.binding_live(key, crate::clock::utc_now().ok())
    });
    (last_used, is_live)
}

/// One file entry, joined with the live key of its name.
fn file_entry(auth: &ResolvedAuthConfig, live: &[ResolvedApiKey], key: &ApiKeyConfig) -> Value {
    let (last_used, is_live) = joined(auth, live.iter().find(|l| l.name == key.name));
    json!({
        "name": key.name,
        "backends": key.backends,
        "allowed_tools": key.allowed_tools,
        "denied_tools": key.denied_tools,
        "admin": key.admin,
        "expires_at": key.expires_at.map(rfc3339),
        "previous_expires_at": key.previous_expires_at.map(rfc3339),
        "rate_limit": key.rate_limit,
        "last_used": last_used,
        "live": is_live,
        "cli_host": key.cli_host,
    })
}

/// One live key, for an answer with no usable file behind it.
fn live_entry(auth: &ResolvedAuthConfig, key: &ResolvedApiKey) -> Value {
    let (last_used, is_live) = joined(auth, Some(key));
    json!({
        "name": key.name,
        "backends": key.backends,
        "allowed_tools": key.allowed_tools,
        "denied_tools": key.denied_tools,
        "admin": key.admin,
        "expires_at": key.expires_at.map(rfc3339),
        "previous_expires_at": key.previous.as_ref().map(|p| rfc3339(p.expires_at)),
        "rate_limit": key.rate_limit,
        "last_used": last_used,
        "live": is_live,
        "cli_host": key.cli_host,
    })
}

/// The answer for no file (`absent`) or a file that failed to load
/// (`unloadable`): the pinned table's keys and no revision.
fn from_live(auth: &ResolvedAuthConfig, file: &str) -> Value {
    let keys: Vec<Value> = auth
        .api_keys()
        .iter()
        .map(|key| live_entry(auth, key))
        .collect();
    json!({"revision": null, "file": file, "keys": keys})
}

pub(super) async fn keys(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    #[cfg(test)] reads: Option<Extension<TableReads>>,
    #[cfg(test)] after_read: Option<Extension<AfterRead>>,
) -> impl IntoResponse {
    // Before anything reads the table or the file.
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    #[cfg(test)]
    if let Some(Extension(reads)) = &reads {
        reads.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    // One read: the revision and the keys come from the same bytes.
    let path = state.config_path.clone();
    let read = tokio::task::spawn_blocking(move || read_gateway("keys", path.as_deref())).await;
    #[cfg(test)]
    if let Some(Extension(hook)) = &after_read {
        (hook.0)();
    }
    let auth = generation.auth();
    let answer = match read {
        Ok(Ok(Gateway::File { revision, config })) => {
            let live = auth.api_keys();
            let keys: Vec<Value> = config
                .auth
                .api_keys
                .iter()
                .map(|key| file_entry(auth, &live, key))
                .collect();
            json!({"revision": revision.as_str(), "keys": keys})
        }
        Ok(Ok(Gateway::None)) => from_live(auth, "absent"),
        Ok(Err(_)) | Err(_) => from_live(auth, "unloadable"),
    };
    Json(answer).into_response()
}

#[cfg(test)]
#[path = "keys_binding_tests.rs"]
mod binding_tests;
