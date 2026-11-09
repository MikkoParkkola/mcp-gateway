// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend routes' one write path: the audited byte writer, with each
//! route's own answer carried out of the writer's compute.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::super::errors::{
    config_path_unavailable, config_refusal, flat_error, no_config_file, structured_error,
};
use super::super::secret_slots;
use crate::config::Config;
use crate::config_persistence::keyedit::{SlotId, Template};
use crate::config_persistence::{NOT_IN_PLACE, edit_text, not_in_place};
use crate::config_reload::{
    BackendOp, ConfigWriteError, Expected, IntentKind, NO_AUDIT_LOG, ReloadOutcome, Replace,
    ReplaceError, Replaced,
};
use crate::gateway::router::AppState;
use crate::secret_store::{SaveError, StoreError};

/// A route edit's own answer, carried out of the writer's boxed compute.
type Decided<T> = Arc<parking_lot::Mutex<Option<Result<T, (StatusCode, String)>>>>;

/// The compute's refusal when the route's own answer is in its cell.
const ROUTE_ANSWERED: &str = "the backend route answered the edit itself";
/// The compute's refusal when a slot's key is not on the edited backend: a
/// bug in the route, never the caller's.
const SLOT_MISSING: &str = "a secret slot names a value the edit did not leave";

/// The answer when the configured store cannot take values on this host.
pub(super) const STORE_UNAVAILABLE: &str = "secrets.store cannot take these values; set secrets.store, or give each value as a secret reference";

/// The values a write stores instead of writing them: each `(header?, key)`
/// on the edited backend becomes a slot the writer fills with its store
/// reference, and `step` saves the values (in the same order).
pub(super) struct Slotted {
    pub(super) slots: Vec<(bool, String)>,
    pub(super) step: crate::config_reload::SecretStep,
}

/// A backend write's result: the route's value, the reload, and each stored
/// secret's field with the reference gateway.yaml now holds.
pub(super) struct Written<T> {
    pub(super) value: T,
    pub(super) reload: ReloadOutcome,
    pub(super) secrets: Vec<(String, String)>,
}

/// Run one route's `edit` of backend `name` through the audited byte writer:
/// gateway.yaml is spliced in place or the edit is refused, its intent comes
/// first on an audited gateway, and a reload that refuses the new bytes puts
/// the old ones back. With `slotted`, each slot's value on `name` is written
/// as the store's reference, never as text. `Err` is the answer to send
/// (boxed: a response is large).
pub(super) async fn write_backend<T, F>(
    state: &AppState,
    operation: BackendOp,
    name: &str,
    slotted: Option<Slotted>,
    edit: F,
) -> Result<Written<T>, Box<axum::response::Response>>
where
    T: Send + 'static,
    F: FnOnce(&mut Config) -> Result<T, (StatusCode, String)> + Send + 'static,
{
    let Some(path) = state.config_path.clone() else {
        return Err(Box::new(config_path_unavailable().into_response()));
    };
    // Fails closed: a write with no reload to check it would leave the file
    // ahead of the running gateway, unaudited.
    let Some(context) = state.meta_mcp.reload_context() else {
        return Err(Box::new(
            flat_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Config reload is not enabled on this gateway",
            )
            .into_response(),
        ));
    };
    // Checked before any lock, so a missing file leaves nothing behind; a
    // file deleted after this check is caught again from the writer's answer.
    if absent(&path).await {
        return Err(Box::new(no_config_file().into_response()));
    }
    let decided: Decided<T> = Arc::default();
    let cell = Arc::clone(&decided);
    let (slots, secrets) = match slotted {
        Some(Slotted { slots, step }) => (slots, Some(step)),
        None => (Vec::new(), None),
    };
    let ids: Vec<SlotId> = slots
        .iter()
        .map(|(header, key)| secret_slots::backend_slot(name, *header, key))
        .collect();
    let backend = name.to_owned();
    let compute = move |bytes: &[u8]| -> Result<Template, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
        let spliced = edit_text(text, |config| {
            let verdict = edit(config);
            let refused = verdict.is_err();
            *cell.lock() = Some(verdict);
            if refused {
                return Err(ROUTE_ANSWERED);
            }
            // After the route's own checks, which see the value as given: each
            // slot's value becomes the placeholder the writer fills with the
            // store's reference once the entry exists.
            if slots.is_empty() {
                return Ok(());
            }
            let Some(b) = config.backends.get_mut(&backend) else {
                return Err(SLOT_MISSING);
            };
            for ((header, key), id) in slots.iter().zip(&ids) {
                let map = if *header { &mut b.headers } else { &mut b.env };
                let Some(value) = map.get_mut(key) else {
                    return Err(SLOT_MISSING);
                };
                *value = Template::placeholder_for(id);
            }
            Ok(())
        });
        match spliced {
            Ok(spliced) if ids.is_empty() => Ok(Template::plain(spliced.into_bytes())),
            Ok(spliced) => Template::from_placeholders(spliced.into_bytes(), &ids)
                .map_err(|_| SLOT_MISSING.to_owned()),
            // Today's comment-loss answer: the lines a rewrite would drop,
            // under a fixed label, never the server's own path.
            Err(why) if why == NOT_IN_PLACE => {
                let label = std::path::Path::new("gateway.yaml");
                *cell.lock() = Some(Err((StatusCode::CONFLICT, not_in_place(label, text))));
                Err(ROUTE_ANSWERED.to_owned())
            }
            Err(why) => Err(why.to_owned()),
        }
    };
    let replace = Replace {
        expected: Expected::Any,
        compute: Box::new(compute),
        replaced: Replaced::Discard,
        secrets,
    };
    let kind = IntentKind::Backend {
        operation,
        backend: name.to_owned(),
    };
    let written = super::super::write_audited(state, context, replace, kind).await;
    let answered = decided.lock().take();
    match (written, answered) {
        (Err(ReplaceError::Refused(why)), Some(Err((code, message)))) if why == ROUTE_ANSWERED => {
            Err(Box::new(flat_error(code, message).into_response()))
        }
        (Ok(outcome), Some(Ok(value))) => Ok(Written {
            value,
            reload: outcome.reload,
            secrets: outcome.secrets,
        }),
        (Ok(_), _) => Err(Box::new(incomplete("no_answer"))),
        (Err(e), _) => Err(Box::new(refused_write(&e))),
    }
}

/// gateway.yaml is not there before any lock: answered `no_config_file`
/// with nothing taken or written (no lock sidecar beside a missing file).
async fn absent(path: &std::path::Path) -> bool {
    matches!(tokio::fs::metadata(path).await, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// A 500 with fixed text: an inner error can quote a configured value, so
/// only the variant name is logged.
fn unwritten(variant: &'static str) -> axum::response::Response {
    tracing::warn!(variant, "backend route: the config write failed");
    flat_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the backend change was not written",
    )
    .into_response()
}

/// A 500 for a write whose outcome on disk is unknown: a failed rollback,
/// or a failure anywhere in the writer. Fixed text, as [`unwritten`].
fn incomplete(variant: &'static str) -> axum::response::Response {
    tracing::warn!(variant, "backend route: the config write failed");
    flat_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the backend change could not be completed; gateway.yaml may have changed, so inspect it before retrying",
    )
    .into_response()
}

/// The answer to a backend write the writer refused.
fn refused_write(e: &ReplaceError) -> axum::response::Response {
    match e {
        // A busy gateway has written nothing, so this is a retry-me, not a
        // failure. 500 would tell the operator their edit broke something.
        ReplaceError::Busy => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ConfigWriteError::Busy.to_string(),
        )
        .into_response(),
        ReplaceError::Stale { .. } => structured_error(
            StatusCode::CONFLICT,
            "stale",
            "gateway.yaml changed during the write; retry",
        )
        .into_response(),
        // The gateway's own posture, fixed text: the operator can act on it.
        ReplaceError::NoAuditLog => structured_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_log_required",
            NO_AUDIT_LOG,
        )
        .into_response(),
        ReplaceError::Unconfirmed { .. } => {
            tracing::warn!(
                variant = "unconfirmed",
                "backend route: the config write failed"
            );
            flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the change could not be recorded; the next config write settles it",
            )
            .into_response()
        }
        ReplaceError::Refused(_) => unwritten("refused"),
        ReplaceError::AuditRefused(_) => unwritten("audit_refused"),
        ReplaceError::ReloadRefused { .. } => unwritten("reload_refused"),
        ReplaceError::Unsupported(_) => unwritten("unsupported"),
        ReplaceError::Stage(_) => unwritten("stage"),
        ReplaceError::Write(_) => unwritten("write"),
        // The bytes on disk are not known: say so, never "not written".
        ReplaceError::RollbackFailed { .. } => incomplete("rollback_failed"),
        ReplaceError::Failed(_) => incomplete("failed"),
        // The store's own text never leaves: fixed answers by kind.
        ReplaceError::Secrets(SaveError::Refused(StoreError::Unavailable(_))) => flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            STORE_UNAVAILABLE,
        )
        .into_response(),
        ReplaceError::Secrets(SaveError::Refused(StoreError::TooLarge { .. })) => structured_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "value_too_large",
            "a value is larger than the secret store holds; nothing was written",
        )
        .into_response(),
        // A timed-out create may still land: its entry is kept and listed as
        // unused, never deleted (the store's own rule).
        ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut)) => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the secret store did not answer in time; nothing was written, and an entry it may still write is kept and listed as unused; retry",
        )
        .into_response(),
        ReplaceError::Secrets(SaveError::Refused(_)) => flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the secret store could not take the values now; nothing was written; retry",
        )
        .into_response(),
        ReplaceError::Secrets(_) => unwritten("secrets"),
        // gateway.yaml went while the writer held it: the shared 409.
        ReplaceError::NoConfigFile => no_config_file().into_response(),
        // The guard refused gateway.yaml or its recovery files. Its text
        // names the file and the fix: the log gets it, the answer never does.
        ReplaceError::ConfigRefused(why) => {
            tracing::warn!(
                variant = "config_refused",
                detail = %why,
                "backend route: the config write refused gateway.yaml"
            );
            config_refusal().into_response()
        }
    }
}

#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
