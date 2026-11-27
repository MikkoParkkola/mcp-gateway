// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend routes' one write path: the audited byte writer, with each
//! route's own answer carried out of the writer's compute.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::super::errors::{
    WriteRoute, config_path_unavailable, flat_error, incomplete, no_config_file, no_reload_write,
    refused_write,
};
use super::super::secret_slots;
use crate::config::Config;
use crate::config_persistence::keyedit::{SlotId, Template};
use crate::config_persistence::{NOT_IN_PLACE, edit_text, not_in_place};
use crate::config_reload::{
    BackendOp, Expected, IntentKind, ReloadOutcome, Replace, ReplaceError, Replaced, StatusChange,
};
use crate::gateway::router::AppState;

/// A route edit's own answer, carried out of the writer's boxed compute.
type Decided<T> = Arc<parking_lot::Mutex<Option<Result<T, (StatusCode, String)>>>>;

/// The compute's refusal when the route's own answer is in its cell.
const ROUTE_ANSWERED: &str = "the backend route answered the edit itself";
/// The compute's refusal when a slot's key is not on the edited backend: a
/// bug in the route, never the caller's.
const SLOT_MISSING: &str = "a secret slot names a value the edit did not leave";

/// How this route's refused writes are logged and answered.
const BACKEND_WRITE: WriteRoute = WriteRoute {
    log: "backend route",
    change: "the backend change",
};

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
    guard: &super::super::guard::Guard,
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
        return Err(Box::new(no_reload_write().into_response()));
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
        status_change: StatusChange::Refuse,
    };
    let kind = IntentKind::Backend {
        operation,
        backend: name.to_owned(),
    };
    let who = super::super::admin_audit::caller_who(
        state,
        guard.client.as_ref(),
        guard.identity.as_ref(),
    );
    let written = super::super::write_audited(state, context, replace, kind, &who).await;
    let answered = decided.lock().take();
    match (written, answered) {
        (Err(ReplaceError::Refused(why)), Some(Err((code, message)))) if why == ROUTE_ANSWERED => {
            Err(Box::new(flat_error(code, message).into_response()))
        }
        (Ok(outcome), Some(Ok(value))) => match outcome.reload {
            crate::config_reload::ReplaceReload::Applied(reload) => Ok(Written {
                value,
                reload,
                secrets: outcome.secrets,
            }),
            // A backend write passes `Refuse`; the writer never holds it.
            crate::config_reload::ReplaceReload::HeldForRestart { .. } => {
                Err(Box::new(incomplete(BACKEND_WRITE, "held_for_restart")))
            }
        },
        (Ok(_), _) => Err(Box::new(incomplete(BACKEND_WRITE, "no_answer"))),
        (Err(e), _) => Err(Box::new(refused_write(BACKEND_WRITE, &e))),
    }
}

/// gateway.yaml is not there before any lock: answered `no_config_file`
/// with nothing taken or written (no lock sidecar beside a missing file).
async fn absent(path: &std::path::Path) -> bool {
    matches!(tokio::fs::metadata(path).await, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
