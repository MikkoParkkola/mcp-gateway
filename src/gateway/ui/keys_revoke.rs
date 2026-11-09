// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /ui/api/keys/{name}`: admit, revision-check and select exact targets.
//! Valid selections await the audited writer and cannot report success.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::config_file::{Gateway, read_gateway};
use super::errors::{flat_error, stale, structured_error};
use super::guard::Guard;
use crate::config_reload::Generation;
use crate::gateway::auth::digest_tag_of;
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
    let Some(context) = state.meta_mcp.reload_context() else {
        return super::errors::config_refusal().into_response();
    };
    let overlay = context.live_env().get();
    let file = config
        .auth
        .api_keys
        .iter()
        .map(|key| {
            Ok(KeyIdentity {
                name: key.name.as_str(),
                current: key.resolve_digest(&overlay)?,
                previous: key.resolve_previous_digest(&overlay)?,
            })
        })
        .collect::<crate::Result<Vec<_>>>();
    let Ok(file) = file else {
        return super::errors::config_refusal().into_response();
    };
    let running = generation.auth().api_keys();
    let live: Vec<_> = running
        .iter()
        .map(|key| KeyIdentity {
            name: key.name.as_str(),
            current: key.digest,
            previous: key.previous.as_ref().map(|slot| slot.digest),
        })
        .collect();
    if let Err(error) = select_target(
        &file,
        &live,
        &name,
        body.expected_key_tag.as_deref(),
        generation.auth().bearer_token.as_deref(),
    ) {
        return flat_error(StatusCode::CONFLICT, error).into_response();
    }
    flat_error(StatusCode::NOT_IMPLEMENTED, "not_implemented").into_response()
}

/// Digest-only inputs keep selection independent of secret-reference I/O.
struct KeyIdentity<'a> {
    name: &'a str,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl KeyIdentity<'_> {
    fn tags(&self) -> impl Iterator<Item = String> + '_ {
        std::iter::once(&self.current)
            .chain(self.previous.iter())
            .map(digest_tag_of)
    }
}

/// Pure A52 selection, to be repeated under the writer locks in chunk 3.
/// Duplicate names refuse with the name rather than picking an arbitrary row.
/// Different file/live current digests or a binding missing from either
/// selected record refuse as target_changed: neither may retarget a replacement.
/// An absent unbound name refuses as target_binding_required; a bound absent
/// name still contributes its tag to S for reconciliation.
/// Any S tag in another name's current/previous slot or the running static
/// bearer refuses as identity_in_use, regardless of expiry or caller identity.
#[cfg(test)]
#[path = "keys_revoke_select_tests.rs"]
mod select_tests;

fn select_target(
    file: &[KeyIdentity<'_>],
    live: &[KeyIdentity<'_>],
    name: &str,
    expected: Option<&str>,
    bearer: Option<&str>,
) -> Result<BTreeSet<String>, String> {
    let mut selected = Vec::new();
    for keys in [file, live] {
        let mut matches = keys.iter().filter(|key| key.name == name);
        let first = matches.next();
        if matches.next().is_some() {
            return Err(format!("duplicate target name: {name}"));
        }
        selected.extend(first);
    }
    if selected.len() == 2 && selected[0].current != selected[1].current {
        return Err("target_changed".into());
    }
    if let Some(tag) = expected {
        if selected
            .iter()
            .any(|key| !key.tags().any(|current| current == tag))
        {
            return Err("target_changed".into());
        }
    } else if selected.is_empty() {
        return Err("target_binding_required".into());
    }
    let mut tags: BTreeSet<_> = selected.iter().flat_map(|key| key.tags()).collect();
    tags.extend(expected.map(str::to_owned));
    let bearer_tag = bearer.map(|token| digest_tag_of(&Sha256::digest(token.as_bytes()).into()));
    if bearer_tag.as_ref().is_some_and(|tag| tags.contains(tag))
        || file
            .iter()
            .chain(live)
            .filter(|key| key.name != name)
            .any(|key| key.tags().any(|tag| tags.contains(&tag)))
    {
        return Err("identity_in_use".into());
    }
    Ok(tags)
}
