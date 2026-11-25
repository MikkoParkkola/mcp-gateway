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

use super::config_file::{Gateway, read_gateway};
use super::errors::{flat_error, gate_refusal, stale, structured_error};
use super::guard::Guard;
use crate::config_persistence::keyedit::{
    Change, ComputeRefusal, FieldPath, GiveUp, Segment, edit_in_place,
};
use crate::config_reload::{
    AuditPosture, Decision, Expected, GatewayAuth, Generation, IntentKind, RELOAD_LOCK_WAIT,
    Replace, ReplaceError, Replaced, RevokeCheck, StatusChange, Waiting, replace_audited_revoke,
    restart_pending_decision, waiting_first_key, waiting_names,
};
use crate::gateway::auth::{digest_tag_of, presented_digest};
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
    let account = who.account.clone();
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
    let refusal = Arc::new(OnceLock::new());
    let kept = refusal.clone();
    let stop = Arc::new(OnceLock::new());
    let stopped = Arc::clone(&stop);
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
        status_change: StatusChange::Refuse,
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
            let at = take_out(&mut config, &name, (&live, &env.get()), &stopped)?;
            let template = remove_key(text, at, &kept)?;
            tags.set(selected)
                .map_err(|_| "target_changed".to_owned())?;
            Ok(template)
        }),
    };
    let result = replace_audited_revoke(
        context,
        replace,
        audit,
        crate::config_reload::history::Source::Ui { who: account },
        RELOAD_LOCK_WAIT,
        check,
    )
        .await
        .map(|receipt| serde_json::json!({"name": receipt.name, "revoked": true, "revision": receipt.revision.as_str()}));
    revoke_response(&target_name, result, (refusal.get(), stop.get()), &state)
}

/// Drops the entry called `name` from `config` (the file as read; the
/// selection already refused a duplicate name) and judges the rest with
/// [`judge_removal`]. Gives the entry's index for the in-place edit.
fn take_out(
    config: &mut crate::config::Config,
    name: &str,
    (live, overlay): (
        &crate::config_reload::LiveConfig,
        &crate::config::EnvOverlay,
    ),
    stop: &OnceLock<Stopped>,
) -> Result<Option<usize>, String> {
    let published = live.generation();
    let waiting_before = waiting_names(&published, config);
    let index = (config.auth.api_keys.iter()).position(|entry| entry.name == name);
    if let Some(index) = index {
        config.auth.api_keys.remove(index);
    }
    let left = waiting_first_key(live.running(), &published, config, overlay);
    judge_removal(left, &waiting_before, stop)?;
    Ok(index)
}

/// The route's own answer for a revoke its compute stopped.
fn stopped_answer(stopped: &Stopped) -> Response {
    match stopped {
        Stopped::Waiting(keys) => super::errors::restart_pending(keys),
        Stopped::Invalid(message) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "invalid", "message": message, "revoked": false})),
        )
            .into_response(),
    }
}

/// Why the compute stopped a revoke that the route answers itself; the
/// writer only sees [`ANSWERED_HERE`].
enum Stopped {
    /// API keys would still wait in gateway.yaml: the shared 409, naming them.
    Waiting(Vec<String>),
    /// The file without the key fails a check: the invalid answer, its text.
    Invalid(String),
}

/// The compute's refusal text when [`Stopped`] holds the answer.
const ANSWERED_HERE: &str = "answered_by_the_route";

/// The file without the key, judged by the first-key question (`candidate`)
/// and the shared decision, with `file_waiting` the keys the file as read
/// holds that the published table lacks. Removing every waiting key ends the
/// wait and goes ahead, as does an ordinary revoke. A removal that changes
/// the status of a gateway on which nothing waits keeps its old refusal.
fn judge_removal(
    candidate: Waiting,
    file_waiting: &[String],
    stop: &OnceLock<Stopped>,
) -> Result<(), String> {
    let stopped = match restart_pending_decision(&candidate, file_waiting.to_vec()) {
        Decision::Pending(waiting) => Stopped::Waiting(waiting.names().to_vec()),
        Decision::Invalid(refusal) => Stopped::Invalid(refusal.sentence().to_owned()),
        Decision::Continue => match candidate {
            Waiting::No | Waiting::Yes { .. } => return Ok(()),
            Waiting::Faulty { .. } if file_waiting.is_empty() => {
                return Err("restart_required".to_owned());
            }
            Waiting::Faulty { reason, .. } => Stopped::Invalid(format!(
                "{reason}; the API keys {} still wait in gateway.yaml, and nothing was written",
                file_waiting.join(", ")
            )),
        },
    };
    // One compute per write and a refusal ends it, so the cell is empty here.
    let _ = stop.set(stopped);
    Err(ANSWERED_HERE.to_owned())
}

/// Remove the selected file entry while preserving the surrounding YAML.
/// keyedit's own refusal is kept in `refusal` for the answer; the writer still
/// sees only `not_written`.
fn remove_key(
    text: &str,
    at: Option<usize>,
    refusal: &OnceLock<ComputeRefusal>,
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
    edit_in_place(text, &changes).map_err(|error| {
        // One compute per write and a refusal ends it, so the cell is empty here.
        let _ = refusal.set(error);
        "not_written".to_owned()
    })
}

/// keyedit's refusal as the operator's answer: its cause, its reason and the
/// config file's path, plus `instructions` only for the hand-edit text of
/// keyedit's revocation check. That text is told apart by two checks, both
/// required: one of that check's codes (flow, anchor), and the prefix
/// `instructions()` starts each such text with (`config_persistence_keyedit_revoke.rs`).
/// Status, error and revoked are unchanged, so a client reading only those
/// keeps working. keyedit's reasons name keys and lines, never a value.
fn keyedit_refusal(code: GiveUp, reason: &str, path: &std::path::Path) -> serde_json::Value {
    let mut body = serde_json::json!({
        "error": "not_written",
        "revoked": false,
        "code": code.as_str(),
        "reason": reason,
        "path": path.display().to_string(),
    });
    if matches!(code, GiveUp::Flow | GiveUp::Anchor) && reason.starts_with("to revoke key `") {
        body["instructions"] = reason.into();
    }
    body
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "keys_revoke_instructions_body_tests.rs"]
mod keys_revoke_instructions_body_tests;

/// The route's answer. A `not_written` refusal that keyedit explains answers
/// with keyedit's cause, its reason and the config file's path.
fn revoke_response(
    name: &str,
    result: Result<serde_json::Value, ReplaceError>,
    (keyedit, stopped): (Option<&ComputeRefusal>, Option<&Stopped>),
    state: &AppState,
) -> Response {
    // The compute stopped the revoke and holds the answer itself.
    if let (Err(ReplaceError::Refused(error)), Some(stopped)) = (&result, stopped)
        && error == ANSWERED_HERE
    {
        return stopped_answer(stopped);
    }
    if let Err(ReplaceError::Refused(error)) = &result
        && error == "not_written"
        && let Some(ComputeRefusal::Unprovable { code, reason }) = keyedit
        && let Some(path) = state.config_path.as_deref()
    {
        // Not cached, like the success answer: the body names the file.
        return (
            StatusCode::CONFLICT,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(keyedit_refusal(*code, reason, path)),
        )
            .into_response();
    }
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
        ReplaceError::Gated(refusal) => return gate_refusal(refusal),
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
        | ReplaceError::WriterRefused { .. }
        | ReplaceError::Secrets(_) => (StatusCode::INTERNAL_SERVER_ERROR, "not_written"),
        ReplaceError::ReloadRefused { .. } => return uncertain(name, "reload_refused"),
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
        .map(|key| {
            let (current, previous) = key.accepted_digests();
            KeyIdentity {
                name: key.name.as_str(),
                current: *current,
                previous: previous.copied(),
            }
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
#[cfg(tp3)]
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
    let bearer_tag = bearer.map(|token| digest_tag_of(&presented_digest(token)));
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
