// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /ui/api/keys/{name}`: admit and revision-check remote revocation.
//! This first chunk refuses an absent unbound target; other selections await
//! the audited writer and receipt implementation and cannot report success.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;

use super::config_file::{Gateway, read_gateway};
use super::errors::{flat_error, stale, structured_error};
use super::guard::Guard;
use crate::config_reload::Generation;
use crate::gateway::router::AppState;

/// Strict request fields; revision is required even when If-Match is supplied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokeBody {
    revision: String,
    #[serde(default, deserialize_with = "supplied_tag")]
    expected_key_tag: Option<String>,
}

/// A supplied binding must be a string; null cannot hide duplicate fields.
fn supplied_tag<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

/// Check admin before file/table reads and revision before target selection.
/// Axum decodes the entire path segment; it is never split or reinterpreted.
pub(super) async fn revoke_key(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    Path(name): Path<String>,
    guard: Guard,
    body: Result<Json<RevokeBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Json(body)) = body else {
        return structured_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
            "the body must be {\"revision\"} and the optional expected_key_tag, and nothing else",
        )
        .into_response();
    };
    let path = state.config_path.clone();
    let read = tokio::task::spawn_blocking(move || read_gateway("keys", path.as_deref())).await;
    let (revision, config) = match read {
        Ok(Ok(Gateway::File { revision, config })) => (revision, config),
        Ok(Ok(Gateway::None)) => {
            return flat_error(StatusCode::CONFLICT, "no_config_file").into_response();
        }
        _ => return super::errors::config_refusal().into_response(),
    };
    if revision.as_str() != body.revision {
        return stale(&revision).into_response();
    }
    if body.expected_key_tag.is_none()
        && !config.auth.api_keys.iter().any(|key| key.name == name)
        && !generation
            .auth()
            .api_keys()
            .iter()
            .any(|key| key.name == name)
    {
        return flat_error(StatusCode::CONFLICT, "target_binding_required").into_response();
    }
    flat_error(StatusCode::NOT_IMPLEMENTED, "not_implemented").into_response()
}
