// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /ui/api/keys/{name}`: admit, revision-check and select exact targets.
//! Success requires the shared audited writer's lock-held absence receipt.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

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
use crate::config_persistence::keyedit::{Change, FieldPath, Segment, edit_in_place};
use crate::config_reload::{
    AuditPosture, Expected, GatewayAuth, Generation, IntentKind, RELOAD_LOCK_WAIT, Replace,
    ReplaceError, Replaced, RevokeCheck, refuse_multi_user_flip, replace_audited_revoke,
};
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
    if let Err(error) = select_config(
        &config,
        &context.live_env().get(),
        &generation,
        &name,
        body.expected_key_tag.as_deref(),
    ) {
        return flat_error(StatusCode::CONFLICT, error).into_response();
    }
    let Some(log) = state.transparency_log.clone() else {
        return flat_error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable").into_response();
    };
    let who =
        super::admin_audit::caller_who(&state, guard.client.as_ref(), guard.identity.as_ref());
    let audit = match AuditPosture::of(
        Some(log),
        GatewayAuth::of(state.live_config.running().auth.enabled),
    )
    .key_write(IntentKind::KeyRevoke, who, &name)
    {
        Ok(audit) => audit,
        Err(error) => return refused(&name, error),
    };
    let tags = Arc::new(OnceLock::new());
    let check = RevokeCheck {
        name: name.clone(),
        tags: tags.clone(),
        live: state.live_config.clone(),
    };
    let live = state.live_config.clone();
    let env = context.live_env().clone();
    let target_name = name.clone();
    let replace = Replace {
        expected: Expected::Revision(revision),
        replaced: Replaced::Discard,
        secrets: None,
        compute: Box::new(move |bytes| {
            let text = std::str::from_utf8(bytes).map_err(|_| "config_refused".to_owned())?;
            let mut config: crate::config::Config =
                crate::yaml::from_str(text).map_err(|_| "config_refused".to_owned())?;
            let selected = select_config(
                &config,
                &env.get(),
                &live.generation(),
                &name,
                body.expected_key_tag.as_deref(),
            )?;
            let at = config.auth.api_keys.iter().position(|key| key.name == name);
            config.auth.api_keys.retain(|key| key.name != name);
            refuse_multi_user_flip(live.running(), &config.auth)
                .map_err(|_| "restart_required".to_owned())?;
            let template = remove_key(text, at)?;
            tags.set(selected)
                .map_err(|_| "target_changed".to_owned())?;
            Ok(template)
        }),
    };
    let result = replace_audited_revoke(context, replace, audit, RELOAD_LOCK_WAIT, check)
        .await
        .map(|receipt| serde_json::json!({"name": receipt.name, "revoked": true, "revision": receipt.revision.as_str()}));
    revoke_response(&target_name, result)
}

/// Remove the selected file entry while preserving the surrounding YAML.
fn remove_key(
    text: &str,
    at: Option<usize>,
) -> Result<crate::config_persistence::keyedit::Template, String> {
    let changes: Vec<_> = at
        .into_iter()
        .map(|at| {
            (
                FieldPath(vec![
                    Segment::Key("auth".into()),
                    Segment::Key("api_keys".into()),
                    Segment::Index(at),
                ]),
                Change::Remove,
            )
        })
        .collect();
    edit_in_place(text, &changes).map_err(|_| "not_written".to_owned())
}

fn revoke_response(name: &str, result: Result<serde_json::Value, ReplaceError>) -> Response {
    match result {
        Ok(body) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(body),
        )
            .into_response(),
        Err(error) => refused(name, error),
    }
}

/// Only the receipt proves success; never infer it from disk or reauthenticate.
fn refused(name: &str, error: ReplaceError) -> Response {
    let (status, message) = match error {
        ReplaceError::Stale { current } => return stale(&current).into_response(),
        ReplaceError::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the config is being written; retry",
        ),
        ReplaceError::AuditRefused(_) | ReplaceError::NoAuditLog => {
            (StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable")
        }
        ReplaceError::NoConfigFile => (StatusCode::CONFLICT, "no_config_file"),
        ReplaceError::ConfigRefused(_) => return super::errors::config_refusal().into_response(),
        ReplaceError::Refused(error) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": error, "revoked": false})),
            )
                .into_response();
        }
        ReplaceError::Unsupported(_)
        | ReplaceError::Stage(_)
        | ReplaceError::Write(_)
        | ReplaceError::Secrets(_) => (StatusCode::INTERNAL_SERVER_ERROR, "not_written"),
        ReplaceError::ReloadRefused(_) => return uncertain(name, "reload_refused"),
        ReplaceError::RollbackFailed { .. } => return uncertain(name, "rollback_failed"),
        ReplaceError::Unconfirmed { .. } => return uncertain(name, "unconfirmed"),
        ReplaceError::Failed(_) => return uncertain(name, "failed"),
    };
    flat_error(status, message).into_response()
}

fn uncertain(name: &str, variant: &'static str) -> Response {
    tracing::warn!(
        name,
        variant,
        "key revoke: the config write outcome is uncertain"
    );
    flat_error(StatusCode::INTERNAL_SERVER_ERROR, "state_uncertain").into_response()
}

/// Resolve the exact file and live identities, both at admission and under locks.
fn select_config(
    config: &crate::config::Config,
    overlay: &crate::config::EnvOverlay,
    generation: &Generation,
    name: &str,
    expected: Option<&str>,
) -> Result<BTreeSet<String>, String> {
    let file = config
        .auth
        .api_keys
        .iter()
        .map(|key| {
            Ok(KeyIdentity {
                name: key.name.as_str(),
                current: key.resolve_digest(overlay)?,
                previous: key.resolve_previous_digest(overlay)?,
            })
        })
        .collect::<crate::Result<Vec<_>>>();
    let file = file.map_err(|_| "config_refused".to_owned())?;
    let running = generation.auth().api_keys();
    let live: Vec<_> = running
        .iter()
        .map(|key| KeyIdentity {
            name: key.name.as_str(),
            current: key.digest,
            previous: key.previous.as_ref().map(|slot| slot.digest),
        })
        .collect();
    select_target(
        &file,
        &live,
        name,
        expected,
        generation.auth().bearer_token.as_deref(),
    )
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

/// Pure A52 selection, repeated under the writer locks before editing.
/// Duplicate names refuse with the name rather than picking an arbitrary row.
/// Different file/live current digests or a binding missing from either
/// selected record refuse as `target_changed`: neither may retarget a replacement.
/// An absent unbound name refuses as `target_binding_required`; a bound absent
/// name still contributes its tag to S for reconciliation.
/// Any S tag in another name's current/previous slot or the running static
/// bearer refuses as `identity_in_use`, regardless of expiry or caller identity.
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
