// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend routes' one write path: the audited byte writer, with each
//! route's own answer carried out of the writer's compute.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::super::errors::{config_path_unavailable, flat_error, no_config_file, structured_error};
use crate::config::Config;
use crate::config_persistence::keyedit::Template;
use crate::config_persistence::{NOT_IN_PLACE, edit_text, not_in_place};
use crate::config_reload::{
    BackendOp, ConfigWriteError, Expected, IntentKind, NO_AUDIT_LOG, ReloadOutcome, Replace,
    ReplaceError, Replaced,
};
use crate::gateway::router::AppState;

/// A route edit's own answer, carried out of the writer's boxed compute.
type Decided<T> = Arc<parking_lot::Mutex<Option<Result<T, (StatusCode, String)>>>>;

/// The compute's refusal when the route's own answer is in its cell.
const ROUTE_ANSWERED: &str = "the backend route answered the edit itself";

/// Run one route's `edit` of backend `name` through the audited byte writer:
/// gateway.yaml is spliced in place or the edit is refused, its intent comes
/// first on an audited gateway, and a reload that refuses the new bytes puts
/// the old ones back. `Err` is the answer to send (boxed: a response is large).
pub(super) async fn write_backend<T, F>(
    state: &AppState,
    operation: BackendOp,
    name: &str,
    edit: F,
) -> Result<(T, ReloadOutcome), Box<axum::response::Response>>
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
    // ponytail: checked before the lock; a file deleted after this check
    // reaches the writer, whose read fails and answers 500.
    if matches!(tokio::fs::metadata(&path).await, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(Box::new(no_config_file().into_response()));
    }
    let decided: Decided<T> = Arc::default();
    let cell = Arc::clone(&decided);
    let compute = move |bytes: &[u8]| -> Result<Template, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
        let spliced = edit_text(text, |config| {
            let verdict = edit(config);
            let refused = verdict.is_err();
            *cell.lock() = Some(verdict);
            if refused { Err(ROUTE_ANSWERED) } else { Ok(()) }
        });
        match spliced {
            Ok(spliced) => Ok(Template::plain(spliced.into_bytes())),
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
        secrets: None,
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
        (Ok(outcome), Some(Ok(value))) => Ok((value, outcome.reload)),
        (Ok(_), _) => Err(Box::new(unwritten("no_answer"))),
        (Err(e), _) => Err(Box::new(refused_write(&e))),
    }
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
        ReplaceError::Refused(why) if why == NO_AUDIT_LOG => structured_error(
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
        ReplaceError::ReloadRefused(_) => unwritten("reload_refused"),
        ReplaceError::Unsupported(_) => unwritten("unsupported"),
        ReplaceError::Stage(_) => unwritten("stage"),
        ReplaceError::Write(_) => unwritten("write"),
        // The bytes on disk are not known: say so, never "not written".
        ReplaceError::RollbackFailed { .. } => incomplete("rollback_failed"),
        ReplaceError::Failed(_) => incomplete("failed"),
        ReplaceError::Secrets(_) => unwritten("secrets"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn message(e: &ReplaceError) -> (StatusCode, String) {
        let response = refused_write(e);
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// A failed rollback, and a write that failed anywhere, may have left
    /// gateway.yaml changed: the answer never says nothing was written.
    #[tokio::test]
    async fn a_failed_rollback_or_write_answers_state_neutral_text() {
        let failures = [
            ReplaceError::RollbackFailed {
                journal: std::path::PathBuf::from("j"),
                error: "e".to_owned(),
            },
            ReplaceError::Failed("e".to_owned()),
        ];
        for e in &failures {
            let (status, text) = message(e).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{e:?}: {text}");
            assert!(!text.contains("not written"), "{e:?}: {text}");
            assert!(text.contains("may have changed"), "{e:?}: {text}");
        }
    }
}
