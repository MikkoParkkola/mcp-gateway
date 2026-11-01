// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/keys`: the configured API keys, as the request's pinned key
//! table holds them, for the web UI's Access page.
//!
//! Admin only. The answer is built field by field from an explicit list, never
//! by serialising the resolved key, so no secret, digest, previous digest,
//! principal or limit key can reach it. `last_used` is the key's last
//! accepted match in this process, null before its first since start.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::response::IntoResponse;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

use super::guard::Guard;

/// Under test, a request may carry a count of the handler's key-table reads,
/// so a row can prove a refusal read nothing.
#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct TableReads(pub(super) Arc<std::sync::atomic::AtomicUsize>);

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(super) async fn keys(
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    #[cfg(test)] reads: Option<Extension<TableReads>>,
) -> impl IntoResponse {
    // Before anything reads the table.
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    #[cfg(test)]
    if let Some(Extension(reads)) = &reads {
        reads.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let auth = generation.auth();
    let keys: Vec<Value> = auth
        .api_keys()
        .iter()
        .map(|key| {
            let last_used = auth
                .key_last_used(key)
                .and_then(|secs| DateTime::from_timestamp(secs, 0))
                .map(rfc3339);
            json!({
                "name": key.name,
                "backends": key.backends,
                "allowed_tools": key.allowed_tools,
                "denied_tools": key.denied_tools,
                "admin": key.admin,
                "expires_at": key.expires_at.map(rfc3339),
                "rate_limit": key.rate_limit,
                "last_used": last_used,
            })
        })
        .collect();
    Json(Value::Array(keys)).into_response()
}
