// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`: create an API key in gateway.yaml.
//!
//! The caller names the key, its scope and the gateway.yaml revision it saw.
//! The route checks, in order: admin, a config file, reload and a loadable
//! file, a free name, a current revision, then the values themselves. Every
//! refusal is fixed text that names a field at most, never the body or a
//! value. The secret is generated here and nowhere else (see `write`).

#[cfg(test)]
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use super::config_file::{Gateway, read_gateway};
use super::errors::{flat_error, structured_error};
use super::guard::Guard;
use crate::config::{ApiKeyConfig, AuthConfig, Config, EnvOverlay};
use crate::config_reload::FileRevision;
use crate::gateway::router::AppState;

/// Under test, a request may carry the secret the route hands out, so a row
/// knows it and its digest.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct KnownSecret(pub(super) String);

/// Under test, a request may carry a hook that runs after the route's checks
/// and just before it asks the writer for the config lock.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct BeforeLock(pub(super) Arc<dyn Fn() + Send + Sync>);

/// The create body: strict, so a key outside the list is refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBody {
    name: String,
    backends: Vec<String>,
    allowed_tools: Option<Vec<String>>,
    denied_tools: Option<Vec<String>>,
    admin: Option<bool>,
    rate_limit: Option<u32>,
    expires_at: Option<DateTime<Utc>>,
    revision: String,
}

fn fixed(status: StatusCode, message: &'static str) -> Response {
    flat_error(status, message).into_response()
}

fn coded(status: StatusCode, error: &'static str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// The one refusal every unreadable body gets.
fn invalid_body() -> Response {
    structured_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_body",
        "the body must be {\"name\", \"backends\", \"revision\"} and the optional \
         allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else",
    )
    .into_response()
}

/// A value the loader or the clock refuses: the field is named, the value never.
fn invalid_field(field: &'static str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "invalid_field",
            "field": field,
            "message": "the value is not accepted",
        })),
    )
        .into_response()
}

fn stale(current: &FileRevision) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({"error": "stale", "current": current.as_str()})),
    )
        .into_response()
}

/// Whether the loader accepts a config holding only `key`.
fn loader_accepts(key: ApiKeyConfig) -> bool {
    let config = Config {
        auth: AuthConfig {
            api_keys: vec![key],
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    config.validate_with_env(&EnvOverlay::none()).is_ok()
}

/// The first body field the loader would refuse, judged one field at a time
/// over an entry that is otherwise valid, so no loader text is parsed.
fn refused_field(body: &CreateBody) -> Option<&'static str> {
    let base = ApiKeyConfig {
        name: "valid".into(),
        key_sha256: Some(crate::config::api_key_digest_spec(b"validation")),
        backends: vec!["*".into()],
        ..ApiKeyConfig::default()
    };
    let probes: [(&'static str, ApiKeyConfig); 4] = [
        (
            "name",
            ApiKeyConfig {
                name: body.name.clone(),
                ..base.clone()
            },
        ),
        (
            "backends",
            ApiKeyConfig {
                backends: body.backends.clone(),
                ..base.clone()
            },
        ),
        (
            "allowed_tools",
            ApiKeyConfig {
                allowed_tools: body.allowed_tools.clone(),
                ..base.clone()
            },
        ),
        (
            "denied_tools",
            ApiKeyConfig {
                denied_tools: body.denied_tools.clone(),
                ..base
            },
        ),
    ];
    probes
        .into_iter()
        .find(|(_, key)| !loader_accepts(key.clone()))
        .map(|(field, _)| field)
}

/// A requested expiry at or before now would never authenticate.
fn expired_by(expires_at: Option<DateTime<Utc>>) -> Result<(), Box<Response>> {
    let Some(at) = expires_at else { return Ok(()) };
    match crate::clock::utc_now() {
        Ok(now) if at > now => Ok(()),
        Ok(_) => Err(Box::new(invalid_field("expires_at"))),
        Err(_) => Err(Box::new(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the clock cannot be read",
        ))),
    }
}

/// What the preconditions found: the file as read, for the write.
struct Checked {
    revision: FileRevision,
    auth: AuthConfig,
}

/// The preconditions, in order: a config file, reload and a loadable file, a
/// free name, a current revision.
async fn preconditions(state: &AppState, body: &CreateBody) -> Result<Checked, Box<Response>> {
    let path = state.config_path.clone();
    let read = tokio::task::spawn_blocking(move || read_gateway("keys", path.as_deref())).await;
    if matches!(read, Ok(Ok(Gateway::None))) {
        return Err(Box::new(coded(StatusCode::CONFLICT, "no_config_file")));
    }
    let (Ok(Ok(Gateway::File { revision, config })), Some(_)) =
        (read, state.meta_mcp.reload_context())
    else {
        return Err(Box::new(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload is off or gateway.yaml could not be loaded",
        )));
    };
    if config.auth.api_keys.iter().any(|k| k.name == body.name) {
        return Err(Box::new(coded(StatusCode::CONFLICT, "name_taken")));
    }
    if revision.as_str() != body.revision {
        return Err(Box::new(stale(&revision)));
    }
    Ok(Checked {
        revision,
        auth: config.auth,
    })
}

/// `POST /ui/api/keys`.
pub(super) async fn create_key(
    State(state): State<std::sync::Arc<AppState>>,
    guard: Guard,
    #[cfg(test)] before_lock: Option<axum::Extension<BeforeLock>>,
    body: Result<Json<CreateBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Json(body)) = body else {
        return invalid_body();
    };
    let checked = match preconditions(&state, &body).await {
        Ok(checked) => checked,
        Err(refused) => return *refused,
    };
    if let Some(field) = refused_field(&body) {
        return invalid_field(field);
    }
    if let Err(refused) = expired_by(body.expires_at) {
        return *refused;
    }
    #[cfg(test)]
    if let Some(axum::Extension(hook)) = &before_lock {
        (hook.0)();
    }
    let _ = (
        &checked.revision,
        &checked.auth,
        body.admin,
        body.rate_limit,
    );
    StatusCode::NOT_IMPLEMENTED.into_response()
}
