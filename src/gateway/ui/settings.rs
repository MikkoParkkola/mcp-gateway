// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settings previews and audited saves through the guarded config writer.

use crate::{
    gateway::{router::AppState, ui::guard::Guard},
    wiped_bytes::WipedBytes,
};
#[cfg(test)]
use axum::extract::Extension;
use axum::{
    Json,
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

use super::errors::{config_refusal, flat_error, no_config_file, stale, structured_error};
use super::secret_slots::{self, Unopened};
use crate::config_persistence::keyedit::{FiniteF64, GiveUp, Scalar};
use crate::config_reload::ui_fields::{FieldId, Param, PreviewEdit, PreviewValue, ValueKind};
use crate::config_reload::{
    AuditPosture, FileRevision, GatewayAuth, NO_AUDIT_LOG, Patch, PatchStep, PreviewRefused,
    RELOAD_LOCK_WAIT, RefusalClass, ReloadOutcome, SaveEdit, SaveValue, SecretTarget, Shown,
    UiPreview, UiRefused, path_text, ui_diff, ui_save,
};
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

fn unavailable() -> Response {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Config reload is not enabled on this gateway",
    )
    .into_response()
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

fn scalar(id: FieldId, value: &serde_json::Value) -> Result<Scalar, Box<Response>> {
    let Some(kind) = id.spec().kind else {
        return Err(Box::new(answer(UiRefused::WrongKind(id))));
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
        return unavailable();
    };
    let mut edit = PreviewEdit::default();
    for (entry, body) in body.fields.into_iter().enumerate() {
        let (id, param, value) = match identify(body, entry) {
            Ok(field) => field,
            Err(response) => return *response,
        };
        let value = match value {
            ValueBody::Set(value) => match scalar(id, &value) {
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
        ),
    }
}

pub(super) async fn settings_save(
    State(state): State<Arc<AppState>>,
    #[cfg(test)] store_for_test: Option<Extension<SettingsStoreForTest>>,
    guard: Guard,
    body: Result<Json<SaveBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Json(body)) = body else {
        return invalid_body();
    };
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
        return unavailable();
    };
    let mut edit = SaveEdit::default();
    for (entry, body) in body.fields.into_iter().enumerate() {
        let (id, param, value) = match identify(body, entry) {
            Ok(field) => field,
            Err(response) => return *response,
        };
        let value = match value {
            SaveValueBody::Set(value) => match scalar(id, &value) {
                Ok(value) => SaveValue::Set(value),
                Err(response) => return *response,
            },
            SaveValueBody::Remove(_) => SaveValue::Remove,
            SaveValueBody::Secret(value) => SaveValue::Secret(value),
        };
        edit.fields.push((id, param, value));
    }
    let fields: Vec<_> = edit.fields.iter().map(|(id, ..)| id.spec().id).collect();
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
    match ui_save(ctx, posture, base, edit, secrets, RELOAD_LOCK_WAIT).await {
        Ok(saved) => Json(json!({
            "revision": saved.revision.as_str(), "changed": saved.changed,
            "restart_required": restart_fields(&fields, &saved.reload),
            "reload": saved.reload, "comments": "kept",
        }))
        .into_response(),
        Err(refusal) => answer_for(refusal, &fields),
    }
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

fn answer_for(refusal: UiRefused, fields: &[&str]) -> Response {
    let variant = match &refusal {
        UiRefused::WrongKind(_) => "wrong_kind",
        UiRefused::BadValue(..) => "bad_value",
        UiRefused::BadParam(..) => "bad_param",
        UiRefused::Invalid(_) => "invalid",
        UiRefused::ReloadRefused { .. } => "reload_refused",
        UiRefused::Unsupported(_) => "unsupported",
        UiRefused::NoAuditLog => "no_audit_log",
        UiRefused::Unprovable(_) => "unprovable",
        UiRefused::Stale(_) => "stale",
        UiRefused::StaleUnpreviewable(_) => "stale_unpreviewable",
        UiRefused::Preview(_) => "preview",
        UiRefused::Busy => "busy",
        UiRefused::SecretsRefused { .. } => "secrets_refused",
        UiRefused::Failed(_) => "failed",
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
    answer(refusal)
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

/// The refusals a client may retry as they are: the design lists Retry-After
/// for these 503s only; the others need someone to change the config first.
fn retryable(refusal: &UiRefused) -> bool {
    matches!(
        refusal,
        UiRefused::Busy
            | UiRefused::StaleUnpreviewable(_)
            | UiRefused::Preview(PreviewRefused::Recovering)
            | UiRefused::SecretsRefused { timeout: true }
            | UiRefused::ReloadRefused {
                class: RefusalClass::ShuttingDown
            }
    )
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

fn answer(refusal: UiRefused) -> Response {
    let retryable = retryable(&refusal);
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
        UiRefused::ReloadRefused { class } => match class {
            RefusalClass::Posture => error(
                StatusCode::CONFLICT,
                "posture_refused",
                "the change was refused by the gateway's network posture",
            ),
            RefusalClass::Invalid => {
                error(StatusCode::UNPROCESSABLE_ENTITY, "invalid", LOADER_REFUSED)
            }
            RefusalClass::ShuttingDown => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "shutting_down",
                "the gateway is shutting down; retry",
            ),
            RefusalClass::Internal => error(StatusCode::INTERNAL_SERVER_ERROR, "failed", FAILED),
        },
        UiRefused::Unsupported(_) => error(
            StatusCode::CONFLICT,
            "unsupported",
            "the edit cannot be followed in gateway.yaml",
        ),
        UiRefused::NoAuditLog => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_log_required",
            NO_AUDIT_LOG,
        ),
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
            StatusCode::SERVICE_UNAVAILABLE,
            "stale",
            "gateway.yaml changed and could not be previewed; retry",
        ),
        UiRefused::Preview(PreviewRefused::Recovering) => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the config write is recovering; retry",
        )
        .into_response(),
        UiRefused::Preview(PreviewRefused::NoConfigFile) => no_config_file().into_response(),
        UiRefused::Preview(PreviewRefused::Untrusted(_) | PreviewRefused::Unread(_)) => {
            config_refusal().into_response()
        }
        // Refused before anything was attempted: a 4xx (a 5xx means the outcome is
        // not confirmed). Still retryable, so it keeps its Retry-After.
        UiRefused::Busy => {
            flat_error(StatusCode::CONFLICT, "the config is being written; retry").into_response()
        }
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
    if retryable { retry(response) } else { response }
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

#[cfg(test)]
#[path = "settings_answer_tests.rs"]
mod answer_tests;
#[cfg(test)]
#[path = "settings_route_secret_tests.rs"]
mod route_secret_tests;
#[cfg(test)]
#[path = "settings_route_tests.rs"]
mod route_tests;
#[cfg(test)]
#[path = "settings_support_tests.rs"]
mod test_support;
#[cfg(test)]
#[path = "settings_unused_tests.rs"]
mod unused_route_tests;
