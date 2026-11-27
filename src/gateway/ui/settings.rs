// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settings previews and audited saves through the guarded config writer.

use crate::{
    gateway::{router::AppState, ui::guard::Guard},
    wiped_bytes::WipedBytes,
};
use axum::{
    Extension, Json,
    extract::{State, rejection::JsonRejection},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::sync::Arc;

#[cfg(test)]
#[derive(Clone)]
pub(super) enum SettingsStoreForTest {
    Store(super::secret_slots::Store),
    // Inject the opener outcome without probing the host keychain or waiting.
    OpenRefused(super::secret_slots::Unopened),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiffBody {
    fields: Vec<FieldBody<ValueBody>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SaveBody {
    base_revision: String,
    fields: Vec<FieldBody<SaveValueBody>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldBody<S> {
    field: String,
    backend: Option<String>,
    index: Option<usize>,
    value: S,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ValueBody {
    Set(serde_json::Value),
    Remove(bool),
    Secret(bool),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum SaveValueBody {
    Set(serde_json::Value),
    Remove(bool),
    Secret(#[serde(deserialize_with = "secret")] WipedBytes),
}

/// Move the parser's owned string allocation directly into the wiping owner.
fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<WipedBytes, D::Error> {
    String::deserialize(deserializer).map(|s| WipedBytes::new(s.into_bytes()))
}

use super::errors::{
    RESTART_BUSY, Retry, config_refusal, config_refusal_read, flat_error, gate_refusal,
    no_config_file, no_reload_read, no_reload_write, stale, structured_error,
};
use super::secret_slots::{self, Unopened};
use crate::config_persistence::keyedit::{FiniteF64, GiveUp, Scalar};
use crate::config_reload::ui_fields::{FieldId, Param, PreviewEdit, PreviewValue, ValueKind};
use crate::config_reload::{
    AuditPosture, BusyReason, FileRevision, GatewayAuth, NO_AUDIT_LOG, Patch, PatchStep,
    PreviewRefused, RELOAD_LOCK_WAIT, RefusalClass, ReloadOutcome, SaveEdit, SaveOutcome,
    SaveValue, SecretTarget, Shown, UiPreview, UiRefused, UiSaved, path_text, ui_diff, ui_save,
};
use crate::gateway::auth::{MintingKey, QuotaPrincipal, ResolvedAuthConfig, SessionMintedBy};
use axum::http::{
    StatusCode,
    header::{HeaderValue, RETRY_AFTER},
};

const FAILED: &str =
    "the save did not complete; gateway.yaml may have changed, so preview it again before retrying";
const LOADER_REFUSED: &str = "the change would be refused by the config loader";

fn invalid_body() -> Response {
    flat_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_body").into_response()
}

fn retry(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn field_error(id: FieldId, code: &'static str, reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error": code, "field": id.spec().id, "reason": reason})),
    )
        .into_response()
}

fn identify<S>(body: FieldBody<S>, entry: usize) -> Result<(FieldId, Param, S), Box<Response>> {
    let Some(id) = FieldId::of(&body.field) else {
        return Err(Box::new(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "unknown_field", "entry": entry})),
            )
                .into_response(),
        ));
    };
    Ok((
        id,
        Param {
            backend: body.backend,
            index: body.index,
        },
        body.value,
    ))
}

fn scalar(id: FieldId, value: &serde_json::Value, asked: Asked) -> Result<Scalar, Box<Response>> {
    let Some(kind) = id.spec().kind else {
        return Err(Box::new(answer(UiRefused::WrongKind(id), asked)));
    };
    let converted = match kind {
        ValueKind::Bool => value.as_bool().map(Scalar::Bool),
        ValueKind::Int { .. } => value.as_i64().map(Scalar::Int),
        ValueKind::Num { .. } => value.as_f64().and_then(FiniteF64::new).map(Scalar::Num),
        ValueKind::Str { .. } | ValueKind::Enum(_) => {
            value.as_str().map(|v| Scalar::Str(v.to_owned()))
        }
    };
    converted.ok_or_else(|| {
        Box::new(field_error(
            id,
            "bad_value",
            "value does not match the field's type",
        ))
    })
}

pub(super) async fn settings_diff(
    State(state): State<Arc<AppState>>,
    #[cfg(test)] _store: Option<Extension<SettingsStoreForTest>>,
    guard: Guard,
    body: Result<Json<DiffBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Json(body)) = body else {
        return invalid_body();
    };
    if body
        .fields
        .iter()
        .any(|f| matches!(f.value, ValueBody::Remove(false) | ValueBody::Secret(false)))
    {
        return invalid_body();
    }
    let Some(ctx) = state.meta_mcp.reload_context() else {
        return no_reload_read().into_response();
    };
    let mut edit = PreviewEdit::default();
    for (entry, body) in body.fields.into_iter().enumerate() {
        let (id, param, value) = match identify(body, entry) {
            Ok(field) => field,
            Err(response) => return *response,
        };
        let value = match value {
            ValueBody::Set(value) => match scalar(id, &value, Asked::Diff) {
                Ok(value) => PreviewValue::Set(value),
                Err(response) => return *response,
            },
            ValueBody::Remove(_) => PreviewValue::Remove,
            ValueBody::Secret(_) => PreviewValue::Secret,
        };
        edit.fields.push((id, param, value));
    }
    match ui_diff(&ctx, &edit).await {
        Ok(preview) => Json(preview_body(preview)).into_response(),
        Err(refusal) => answer_for(
            refusal,
            &edit
                .fields
                .iter()
                .map(|(id, ..)| id.spec().id)
                .collect::<Vec<_>>(),
            Asked::Diff,
        ),
    }
}

/// Display names can collide or change; the stable key principal carries the restriction.
pub(crate) fn caller_is_cli_key(
    auth: &ResolvedAuthConfig,
    bearer_quota: Option<&QuotaPrincipal>,
    session: Option<&MintingKey>,
) -> bool {
    bearer_quota.is_some_and(|quota| auth.is_cli_key_quota(quota))
        || session.is_some_and(|minter| auth.is_cli_key_quota(&minter.quota))
}

#[allow(
    clippy::too_many_lines,
    reason = "the CLI-key and audit-log refusals must come before the store opens, and the outcome is attached on every exit, writer refusals included: one scope keeps both"
)]
pub(super) async fn settings_save(
    State(state): State<Arc<AppState>>,
    #[cfg(test)] store_for_test: Option<Extension<SettingsStoreForTest>>,
    guard: Guard,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    session: Option<Extension<SessionMintedBy>>,
    body: Result<Json<SaveBody>, JsonRejection>,
) -> Response {
    // The writer's word and intent id; any refusal before it reads refused.
    let mut answered: (SaveOutcome, Option<String>) = (SaveOutcome::Refused, None);
    let mut response = async {
        if let Err(refused) = guard.admit() {
            return refused.into_response();
        }
        let Ok(Json(body)) = body else {
            return invalid_body();
        };
        // Refuse the whole edit before opening the store: even a secret stored
        // ahead of the config write must not outlive a CLI key's approver.
        if body
            .fields
            .iter()
            .any(|field| field.field.starts_with("auth."))
            && caller_is_cli_key(
                generation.auth(),
                guard
                    .client
                    .as_ref()
                    .and_then(|client| client.quota_principal.as_ref()),
                session.as_ref().map(|Extension(SessionMintedBy(key))| key),
            )
        {
            return super::guard::Refused::Forbidden.into_response();
        }
        let Some(base) = FileRevision::from_text(&body.base_revision) else {
            return invalid_body();
        };
        if body
            .fields
            .iter()
            .any(|f| matches!(f.value, SaveValueBody::Remove(false)))
        {
            return invalid_body();
        }
        let Some(ctx) = state.meta_mcp.reload_context() else {
            return no_reload_write().into_response();
        };
        let mut edit = SaveEdit::default();
        for (entry, body) in body.fields.into_iter().enumerate() {
            let (id, param, value) = match identify(body, entry) {
                Ok(field) => field,
                Err(response) => return *response,
            };
            let value = match value {
                SaveValueBody::Set(value) => match scalar(id, &value, Asked::Save) {
                    Ok(value) => SaveValue::Set(value),
                    Err(response) => return *response,
                },
                SaveValueBody::Remove(_) => SaveValue::Remove,
                SaveValueBody::Secret(value) => SaveValue::Secret(value),
            };
            edit.fields.push((id, param, value));
        }
        let fields: Vec<_> = edit.fields.iter().map(|(id, ..)| id.spec().id).collect();
        // WRITE.4: turning auth on needs a log the next start can write.
        // Asked before the store opens, so a refused save opens nothing.
        if !state.live_config.running().auth.enabled
            && let Err(unusable) = next_start_log(&state, &ctx, &edit)
        {
            return audit_log_required(&unusable);
        }
        let secrets = if edit
            .fields
            .iter()
            .any(|(_, _, value)| matches!(value, SaveValue::Secret(_)))
        {
            let dir = ctx
                .config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf();
            let config = ctx.live_config.get();
            #[cfg(test)]
            let opened = match store_for_test {
                Some(Extension(SettingsStoreForTest::OpenRefused(why))) => Err(why),
                Some(Extension(SettingsStoreForTest::Store(store))) => {
                    secret_slots::open_store(config.secrets.store, dir)
                        .await
                        .map(|(_, vault)| (store, vault))
                }
                None => secret_slots::open_store(config.secrets.store, dir).await,
            };
            #[cfg(not(test))]
            let opened = secret_slots::open_store(config.secrets.store, dir).await;
            match secret_target(opened) {
                Ok(target) => Some(target),
                Err(response) => return *response,
            }
        } else {
            None
        };
        let posture = AuditPosture::of(
            state.transparency_log.clone(),
            GatewayAuth::of(state.live_config.running().auth.enabled),
        );
        let audited = posture.requires_audit();
        let who =
            super::admin_audit::caller_who(&state, guard.client.as_ref(), guard.identity.as_ref());
        let (config_path, live) = (ctx.config_path.clone(), Arc::clone(&ctx.live_config));
        let answer = ui_save(ctx, posture, base, edit, secrets, &who, RELOAD_LOCK_WAIT).await;
        answered = (answer.outcome, answer.intent_id.map(|id| id.0));
        match answer.result {
            Ok(saved) => saved_answer(&saved, &fields, &live, &config_path, audited),
            Err(refusal) => answer_for(refusal, &fields, Asked::Save),
        }
    }
    .await;
    attach_outcome(&mut response, answered.0, answered.1);
    response
}

/// The save's outcome word, and its intent's id when it appended one, on
/// the request's own `admin_action` (WRITE.2): no `intent_id` key at all
/// when there is no intent.
fn attach_outcome(response: &mut Response, outcome: SaveOutcome, intent_id: Option<String>) {
    let mut detail = serde_json::Map::new();
    detail.insert("save_outcome".into(), outcome.as_str().into());
    if let Some(id) = intent_id {
        detail.insert("intent_id".into(), id.into());
    }
    response
        .extensions_mut()
        .insert(super::admin_audit::AuditDetail(detail));
}

/// The 409 of a save that would turn auth on with no log the next start can
/// write; nothing was written.
pub(super) const AUDIT_LOG_REQUIRED: (&str, &str) = (
    "AUDIT_LOG_REQUIRED",
    "auth cannot be turned on until the next start has an audit log it can write",
);

/// When `edit` turns auth on: the log the published config (what a restart
/// boots) names, judged by permissions alone.
fn next_start_log(
    state: &AppState,
    ctx: &crate::config_reload::ReloadContext,
    edit: &SaveEdit,
) -> Result<(), super::settings_log_check::Unusable> {
    let turns_on = edit.fields.iter().any(|(id, _, value)| {
        id.spec().id == "auth.enabled" && matches!(value, SaveValue::Set(Scalar::Bool(true)))
    });
    if !turns_on {
        return Ok(());
    }
    let held = state.transparency_log.as_ref().map(|log| log.path());
    let cwd = std::env::current_dir().unwrap_or_default();
    super::settings_log_check::usable_log(
        &ctx.live_config.get(),
        held.as_deref(),
        crate::home_dir::home_dir().as_deref(),
        &cwd,
        &super::settings_log_check::access,
    )
}

fn audit_log_required(unusable: &super::settings_log_check::Unusable) -> Response {
    use super::settings_log_check::Unusable;
    let fix = match unusable {
        Unusable::Off => "enable security.transparency_log with a path".to_owned(),
        Unusable::NotWritable(path) => format!("{} cannot be written", path.display()),
    };
    let message = format!("{}: {fix}", AUDIT_LOG_REQUIRED.1);
    structured_error(StatusCode::CONFLICT, AUDIT_LOG_REQUIRED.0, message).into_response()
}

/// A saved answer's notice: its code and sentence. Both can stand on one
/// save, so they share one `notices` array.
pub(super) const OUTSIDE_CHANGE_APPLIED: (&str, &str) = (
    "OUTSIDE_CHANGE_APPLIED",
    "this save's reload also loaded edits someone made to gateway.yaml outside the UI; see the reload for any that wait for a restart",
);
/// The save of a gateway with auth off and no audit log: it goes ahead with
/// no record, and says so.
pub(super) const NOT_AUDITED: (&str, &str) = (
    "NOT_AUDITED",
    "no audit record was written: this gateway has auth off and no audit log",
);

/// The answer to a completed save, with the restart keys while one is pending.
fn saved_answer(
    saved: &UiSaved,
    fields: &[&str],
    live: &crate::config_reload::LiveConfig,
    config_path: &std::path::Path,
    audited: bool,
) -> Response {
    let pending = saved.reload.restart_required;
    let notices: Vec<serde_json::Value> = [
        (saved.outside_change, OUTSIDE_CHANGE_APPLIED),
        (!audited, NOT_AUDITED),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, (code, message))| json!({"code": code, "message": message}))
    .collect();
    let mut body = json!({
        "revision": saved.revision.as_str(), "changed": saved.changed,
        "restart_required": restart_fields(fields, &saved.reload),
        "reload": saved.reload, "comments": "kept", "notices": notices,
    });
    // A restart would boot the published config.
    let refusal = pending
        .then(|| crate::gateway::next_start_refusal(&live.get()))
        .flatten();
    if let Some(keys) =
        super::restart_confirm::restart_advice(pending, refusal.as_deref(), Some(config_path))
        && let Some(answer) = body.as_object_mut()
    {
        answer.extend(keys);
    }
    Json(body).into_response()
}

fn preview_body(preview: UiPreview) -> serde_json::Value {
    let mut body = json!({"revision": preview.revision.as_str()});
    show(&mut body, preview.shown);
    body
}

fn show(body: &mut serde_json::Value, shown: Shown) {
    match shown {
        Shown::Diff(diff) => body["diff"] = json!(diff.render()),
        Shown::Patch(patch) => body["patch"] = patch_steps(patch),
    }
}

fn patch_steps(patch: Patch) -> serde_json::Value {
    // Derive explanations from the typed cause, never diagnostic payloads.
    let reason = match patch.code {
        GiveUp::Comment => "the edit would remove a comment",
        GiveUp::Flow => "a flow collection is on the path",
        GiveUp::Anchor => "the value has an anchor, a tag or an alias",
        GiveUp::InlineEmpty => "the mapping is written empty inline",
        GiveUp::NullSequence => "the list is written empty inline",
        GiveUp::DashLine => "a key on the element's dash line would be removed",
        GiveUp::SequenceShape => "the edit would change the sequence shape",
        GiveUp::NotPlainKey => "a key on the path is not a plain key",
        GiveUp::SecretSpan => "the change cannot be shown masked",
        GiveUp::Other => "the edit cannot be proven in place",
    };
    json!(patch.steps.into_iter().map(|step| {
        let (op, location, value) = match step {
            PatchStep::Set { path: location, value } => ("set", location, value),
            PatchStep::Remove { path: location } => ("remove", location, None),
            PatchStep::SetSecret { path: location } => ("set_secret", location, None),
        };
        let mut step = json!({"op": op, "path": path_text(&location), "code": patch.code.as_str(), "reason": reason});
        if let Some(value) = value { step["value"] = json!(value); }
        if let Some(line) = patch.line { step["line"] = json!(line); }
        step
    }).collect::<Vec<_>>())
}

/// Which route asked: the diff is a read, so its shared refusals stay 503;
/// the save is a write, so a refusal that attempted nothing is 409.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Asked {
    Diff,
    Save,
}

fn answer_for(refusal: UiRefused, fields: &[&str], asked: Asked) -> Response {
    let variant = match &refusal {
        UiRefused::WrongKind(_) => "wrong_kind",
        UiRefused::BadValue(..) => "bad_value",
        UiRefused::BadParam(..) => "bad_param",
        UiRefused::Invalid(_) => "invalid",
        UiRefused::ReloadRefused { .. } => "reload_refused",
        UiRefused::Unsupported(_) => "unsupported",
        UiRefused::NoAuditLog => "no_audit_log",
        UiRefused::AuditRefused => "audit_refused",
        UiRefused::Unprovable(_) => "unprovable",
        UiRefused::Stale(_) => "stale",
        UiRefused::StaleUnpreviewable(_) => "stale_unpreviewable",
        UiRefused::Preview(_) => "preview",
        UiRefused::Busy(_) => "busy",
        UiRefused::Down(_) => "down",
        UiRefused::SecretsRefused { .. } => "secrets_refused",
        // A writer refusal keeps the failed write's audit code, as before.
        UiRefused::WriterRefused | UiRefused::Failed(_) => "failed",
    };
    let class = if let UiRefused::ReloadRefused { class } = &refusal {
        Some(class)
    } else {
        None
    };
    tracing::warn!(variant = variant, class = ?class, fields = ?fields);
    if matches!(refusal, UiRefused::Invalid(_)) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "invalid", "message": LOADER_REFUSED, "fields": fields,
            })),
        )
            .into_response();
    }
    answer(refusal, asked)
}

fn bad_value(id: FieldId, reason: &str) -> Response {
    let mut allowed = vec![
        "expected a boolean".to_owned(),
        "expected an integer".to_owned(),
        "expected a number".to_owned(),
        "expected a string".to_owned(),
        "out of range".to_owned(),
        "a control character".to_owned(),
    ];
    match id.spec().kind {
        Some(ValueKind::Num { min }) => allowed.push(format!("below {min}")),
        Some(ValueKind::Str {
            max_chars: Some(max),
        }) => allowed.push(format!("over {max} characters")),
        Some(ValueKind::Enum(words)) => {
            allowed.push(format!("not one of {}", words.join(", ")));
        }
        Some(ValueKind::Bool | ValueKind::Int { .. } | ValueKind::Str { max_chars: None })
        | None => {}
    }
    let reason = allowed
        .iter()
        .find(|fixed| fixed.as_str() == reason)
        .map_or(
            "value does not satisfy the field's constraints",
            String::as_str,
        );
    field_error(id, "bad_value", reason)
}

/// The refusals that stay 5xx and that a client may retry as they are: the
/// design lists Retry-After for these only. A refusal that attempted nothing
/// gets its header from `refusal` instead.
fn retryable(refusal: &UiRefused) -> bool {
    matches!(
        refusal,
        UiRefused::Preview(PreviewRefused::Recovering)
            | UiRefused::SecretsRefused { timeout: true }
            | UiRefused::ReloadRefused {
                class: RefusalClass::ShuttingDown
            }
    )
}

/// The class of a settings refusal that attempted nothing (409), and whether
/// to retry; `None` keeps the arm's answer. `Busy`, `StaleUnpreviewable`,
/// `NoAuditLog` and `WriterRefused` come from a save only.
fn save_class(refusal: &UiRefused, asked: Asked) -> Option<Retry> {
    match (refusal, asked) {
        (UiRefused::Busy(_) | UiRefused::StaleUnpreviewable(_), _)
        | (UiRefused::Preview(PreviewRefused::Recovering), Asked::Save) => Some(Retry::Now),
        (UiRefused::NoAuditLog | UiRefused::WriterRefused, _)
        | (
            UiRefused::Preview(PreviewRefused::Untrusted(_) | PreviewRefused::Unread(_)),
            Asked::Save,
        ) => Some(Retry::No),
        _ => None,
    }
}

/// The core's parameter reasons are fixed texts from the field table; any
/// other text is answered with one fixed sentence, never echoed.
fn bad_param_reason(reason: &str) -> &'static str {
    match reason {
        "needs a backend" => "needs a backend",
        "takes no backend" => "takes no backend",
        "needs an index" => "needs an index",
        "takes no index" => "takes no index",
        "named twice" => "named twice",
        "a required alert field" => "a required alert field",
        "the backend name cannot be edited in place" => {
            "the backend name cannot be edited in place"
        }
        _ => "the field parameters are invalid",
    }
}

/// A reload refusal's answer, by the class of what refused it.
fn reload_refused(class: RefusalClass) -> Response {
    let error = |status, code, text| structured_error(status, code, text).into_response();
    match class {
        RefusalClass::Posture => error(
            StatusCode::CONFLICT,
            "posture_refused",
            "the change was refused by the gateway's network posture",
        ),
        RefusalClass::Invalid => error(StatusCode::UNPROCESSABLE_ENTITY, "invalid", LOADER_REFUSED),
        // The first-key question's own sentence names no value: shown.
        RefusalClass::KeyList(refusal) => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid",
            refusal.sentence(),
        ),
        RefusalClass::ShuttingDown => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "the gateway is shutting down; retry",
        ),
        RefusalClass::Internal => error(StatusCode::INTERNAL_SERVER_ERROR, "failed", FAILED),
        RefusalClass::RestartPending { waiting } => super::errors::restart_pending(waiting.names()),
    }
}

fn answer(refusal: UiRefused, asked: Asked) -> Response {
    let retryable = retryable(&refusal);
    let class = save_class(&refusal, asked);
    let error = |status, code, text| structured_error(status, code, text).into_response();
    let response = match refusal {
        UiRefused::WrongKind(id) => field_error(
            id,
            "wrong_kind",
            "the operation does not match the field's kind",
        ),
        UiRefused::BadValue(id, reason) => bad_value(id, &reason),
        UiRefused::BadParam(id, reason) => field_error(id, "bad_param", bad_param_reason(&reason)),
        UiRefused::Invalid(_) => error(StatusCode::UNPROCESSABLE_ENTITY, "invalid", LOADER_REFUSED),
        UiRefused::ReloadRefused { class } => reload_refused(class),
        UiRefused::Unsupported(_) => error(
            StatusCode::CONFLICT,
            "unsupported",
            "the edit cannot be followed in gateway.yaml",
        ),
        // No log is the posture (nothing started, 409); a refused append was
        // started (503). One body for both.
        UiRefused::NoAuditLog => error(StatusCode::CONFLICT, "audit_log_required", NO_AUDIT_LOG),
        UiRefused::AuditRefused => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_log_required",
            NO_AUDIT_LOG,
        ),
        // The writer refused before the target changed: the failed write's
        // body, unchanged, at the refusal's 409.
        UiRefused::WriterRefused => error(StatusCode::CONFLICT, "failed", FAILED),
        UiRefused::Unprovable(patch) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "not_in_place", "patch": patch_steps(patch)})),
        )
            .into_response(),
        UiRefused::Stale(preview) => {
            let (status, Json(mut body)) = stale(&preview.revision);
            show(&mut body, preview.shown);
            (status, Json(body)).into_response()
        }
        UiRefused::StaleUnpreviewable(_) => error(
            StatusCode::CONFLICT,
            "stale",
            "gateway.yaml changed and could not be previewed; retry",
        ),
        // A read (the diff) cannot answer now (503); a save attempted
        // nothing (409, through `save_class`).
        UiRefused::Preview(PreviewRefused::Recovering) => flat_error(
            match asked {
                Asked::Save => StatusCode::CONFLICT,
                Asked::Diff => StatusCode::SERVICE_UNAVAILABLE,
            },
            "the config write is recovering; retry",
        )
        .into_response(),
        UiRefused::Preview(PreviewRefused::NoConfigFile) => no_config_file().into_response(),
        UiRefused::Preview(PreviewRefused::Untrusted(_) | PreviewRefused::Unread(_)) => match asked
        {
            Asked::Save => config_refusal().into_response(),
            Asked::Diff => config_refusal_read().into_response(),
        },
        // Refused before anything was attempted: a 4xx (a 5xx means the outcome is
        // not confirmed). Still retryable, so it keeps its Retry-After.
        UiRefused::Busy(reason) => flat_error(
            StatusCode::CONFLICT,
            match reason {
                BusyReason::Locked => "the config is being written; retry",
                BusyReason::Restart => RESTART_BUSY,
            },
        )
        .into_response(),
        UiRefused::Down(down) => gate_refusal(down),
        UiRefused::SecretsRefused { timeout: true } => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the secret store did not answer; retry",
        )
        .into_response(),
        UiRefused::SecretsRefused { timeout: false } => flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the secret store refused the value",
        )
        .into_response(),
        UiRefused::Failed(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed", FAILED),
    };
    let response = if retryable { retry(response) } else { response };
    super::errors::classed(class, response)
}

fn restart_fields(fields: &[&str], reload: &ReloadOutcome) -> Vec<String> {
    fields
        .iter()
        .filter(|id| {
            reload
                .pending_restart_fields
                .iter()
                .any(|p| p == **id || id.starts_with(&format!("{p}.")))
        })
        .map(|id| (*id).to_owned())
        .collect()
}

fn secret_target(
    opened: Result<
        (
            secret_slots::Store,
            Result<crate::secret_store::Vault, crate::secret_store::StoreError>,
        ),
        Unopened,
    >,
) -> Result<SecretTarget, Box<Response>> {
    match opened {
        Ok((store, Ok(vault))) => Ok(SecretTarget { vault, store }),
        Ok((_, Err(_))) | Err(Unopened::Failed) => {
            Err(
                structured_error(StatusCode::INTERNAL_SERVER_ERROR, "failed", FAILED)
                    .into_response(),
            )
        }
        Err(Unopened::Unavailable) => Err(flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "secrets.store cannot take the settings values",
        )
        .into_response()),
        Err(Unopened::TimedOut) => Err(retry(
            flat_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the secret store did not answer; retry",
            )
            .into_response(),
        )),
    }
    .map_err(Box::new)
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_answer_tests.rs"]
mod answer_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_cli_tests.rs"]
mod cli_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_floor_tests.rs"]
mod floor_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_log_check_tests.rs"]
mod log_check_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "restart_advice_route_tests.rs"]
mod restart_advice_route_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_route_secret_tests.rs"]
mod route_secret_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_route_tests.rs"]
mod route_tests;
#[cfg(test)]
#[path = "settings_support_tests.rs"]
mod test_support;
#[cfg(tp3)]
#[cfg(test)]
#[path = "settings_unused_tests.rs"]
mod unused_route_tests;
