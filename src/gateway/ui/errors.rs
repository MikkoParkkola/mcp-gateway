// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use axum::Json;
use axum::http::{HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::config_reload::{
    ConfigWriteError, FileRevision, NO_AUDIT_LOG, RELOAD_RESTARTING, RELOAD_STOPPING, RefusalClass,
    ReplaceError,
};
use crate::gateway::http_error::{flat_error_body, json_body, structured_error_body};
use crate::gateway::restart_config_floor::Refusal;
use crate::secret_store::{SaveError, StoreError};

pub(super) fn flat_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, flat_error_body(message))
}

pub(super) fn structured_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, structured_error_body(code, message))
}

/// The reason a UI write is told to retry while a restart is being prepared.
pub(super) const RESTART_BUSY: &str = "a restart is being prepared; retry";

/// The one answer to a config-gate refusal of a UI write, for every write
/// route: all are 409s, since nothing was tried; busy alone is retryable and
/// carries `Retry-After`.
pub(super) fn gate_refusal(refusal: Refusal) -> Response {
    let ending = |code, message| structured_error(StatusCode::CONFLICT, code, message);
    match refusal {
        Refusal::Busy | Refusal::ReplayOwed => {
            let mut busy = flat_error(StatusCode::CONFLICT, RESTART_BUSY).into_response();
            busy.headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
            busy
        }
        Refusal::Restarting => ending("restarting", RELOAD_RESTARTING).into_response(),
        Refusal::Stopping => ending("stopping", RELOAD_STOPPING).into_response(),
    }
}

/// A UI write that would keep API keys still waiting in gateway.yaml: 409,
/// naming them. Says nothing was written and which change does go through;
/// never speaks of a restart, since only the Gateway page's own start check
/// can say whether the file would start.
pub(super) fn restart_pending(waiting: &[String]) -> Response {
    let quoted = waiting
        .iter()
        .map(|key| ["`", key.as_str(), "`"].concat())
        .collect::<Vec<_>>()
        .join(", ");
    let message = if let [_single] = waiting {
        format!(
            "gateway.yaml holds the waiting API key {quoted}; nothing was written. A change \
             that keeps it is refused. To end the wait, revoke it, or restore a version \
             without it: that change is applied."
        )
    } else {
        format!(
            "gateway.yaml holds the waiting API keys {quoted}; nothing was written. A change \
             that keeps any of them is refused. Only a change that takes out every one is \
             applied: restore a version without them, or edit gateway.yaml by hand. They \
             cannot be revoked one at a time."
        )
    };
    json_body(
        StatusCode::CONFLICT,
        json!({"error": "restart_pending", "message": message, "waiting_keys": waiting}),
    )
    .into_response()
}

/// The 409 of a gateway.yaml revision that moved: the one to retry against.
pub(super) fn stale(current: &FileRevision) -> (StatusCode, Json<Value>) {
    json_body(
        StatusCode::CONFLICT,
        json!({"error": "stale", "current": current.as_str()}),
    )
}

/// Why a config write found no gateway.yaml to write into, and the way
/// forward: every web UI route that edits the file answers it.
const NO_CONFIG_FILE: &str = "no gateway.yaml exists yet; create one with `mcp-gateway init --profile local` (see QUICKSTART), then retry";

/// 409 `no_config_file`: nothing is written; the operator creates the file.
pub(super) fn no_config_file() -> (StatusCode, Json<Value>) {
    structured_error(StatusCode::CONFLICT, "no_config_file", NO_CONFIG_FILE)
}

/// gateway.yaml could not be read, or the read guard refused it or its
/// recovery files. Fixed text for every route that writes it: the reason
/// names the file, so it goes to the log only.
pub(super) fn config_refusal() -> (StatusCode, Json<Value>) {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "gateway.yaml could not be loaded",
    )
}

pub(super) fn admin_auth_required() -> (StatusCode, Json<Value>) {
    flat_error(StatusCode::FORBIDDEN, "Admin authentication required")
}

pub(super) fn auth_required(status: StatusCode) -> (StatusCode, Json<Value>) {
    flat_error(status, "Authentication required")
}

const NO_RELOAD: &str = "Config reload is not enabled on this gateway";

/// A read on a gateway with no reload context: it cannot answer right now (503).
pub(super) fn no_reload_read() -> (StatusCode, Json<Value>) {
    flat_error(StatusCode::SERVICE_UNAVAILABLE, NO_RELOAD)
}

/// A write on a gateway with no reload context attempted nothing, so it is refused
/// (409): a 4xx means nothing was tried, a 5xx that the outcome is not confirmed.
pub(super) fn no_reload_write() -> (StatusCode, Json<Value>) {
    flat_error(StatusCode::CONFLICT, NO_RELOAD)
}

pub(super) fn config_path_unavailable() -> (StatusCode, Json<Value>) {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Config file path not available; cannot persist changes",
    )
}

/// The answer when the configured store cannot take values on this host.
pub(super) const STORE_UNAVAILABLE: &str = "secrets.store cannot take these values; set secrets.store, or give each value as a secret reference";

/// The UI route answering a refused write: `log` opens each of its log
/// lines, and `change` is what its fixed 500 answers say was not done.
#[derive(Clone, Copy)]
pub(super) struct WriteRoute {
    pub(super) log: &'static str,
    pub(super) change: &'static str,
}

/// A 500 with fixed text: an inner error can quote a configured value, so
/// only the variant name is logged.
fn unwritten(route: WriteRoute, variant: &'static str) -> axum::response::Response {
    tracing::warn!(variant, "{}: the config write failed", route.log);
    flat_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("{} was not written", route.change),
    )
    .into_response()
}

/// A 500 for a write whose outcome on disk is unknown: a failed rollback,
/// or a failure anywhere in the writer. Fixed text, as [`unwritten`].
pub(super) fn incomplete(route: WriteRoute, variant: &'static str) -> axum::response::Response {
    tracing::warn!(variant, "{}: the config write failed", route.log);
    flat_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("{} could not be completed; gateway.yaml may have changed, so inspect it before retrying", route.change),
    )
    .into_response()
}

/// The answer to a UI config write the writer refused, logged as `route`'s.
pub(super) fn refused_write(route: WriteRoute, e: &ReplaceError) -> axum::response::Response {
    match e {
        // A busy gateway has written nothing, so this is a retry-me, not a
        // failure. 500 would tell the operator their edit broke something.
        ReplaceError::Gated(refusal) => gate_refusal(*refusal),
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
                "{}: the config write failed",
                route.log
            );
            flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the change could not be recorded; the next config write settles it",
            )
            .into_response()
        }
        ReplaceError::Refused(_) => unwritten(route, "refused"),
        ReplaceError::AuditRefused(_) => unwritten(route, "audit_refused"),
        // The write keeps API keys still waiting in gateway.yaml.
        ReplaceError::ReloadRefused {
            class: RefusalClass::RestartPending { waiting },
            ..
        } => restart_pending(waiting.names()),
        // A key list refused with the first-key question's own sentence,
        // which names no value: a 422 that shows it.
        ReplaceError::ReloadRefused {
            class: RefusalClass::KeyList(refusal),
            ..
        } => structured_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid",
            refusal.sentence(),
        )
        .into_response(),
        ReplaceError::ReloadRefused { .. } => unwritten(route, "reload_refused"),
        ReplaceError::Unsupported(_) => unwritten(route, "unsupported"),
        ReplaceError::Stage(_) => unwritten(route, "stage"),
        ReplaceError::Write(_) => unwritten(route, "write"),
        // The writer's own refusal names the file and user ids only: shown
        // as it is, with its code, since nothing was written (409).
        ReplaceError::WriterRefused { code, text } => {
            tracing::warn!(code, "{}: the config write was refused", route.log);
            structured_error(StatusCode::CONFLICT, code, text.as_str()).into_response()
        }
        // The bytes on disk are not known: say so, never "not written".
        ReplaceError::RollbackFailed { .. } => incomplete(route, "rollback_failed"),
        ReplaceError::Failed(_) => incomplete(route, "failed"),
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
        ReplaceError::Secrets(_) => unwritten(route, "secrets"),
        // gateway.yaml went while the writer held it: the shared 409.
        ReplaceError::NoConfigFile => no_config_file().into_response(),
        // The guard refused gateway.yaml or its recovery files. Its text
        // names the file and the fix: the log gets it, the answer never does.
        ReplaceError::ConfigRefused(why) => {
            tracing::warn!(
                variant = "config_refused",
                detail = %why,
                "{}: the config write refused gateway.yaml",
                route.log
            );
            config_refusal().into_response()
        }
    }
}

#[cfg(tp3)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_auth_required_shape_is_stable() {
        let (status, body) = admin_auth_required();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.0, json!({ "error": "Admin authentication required" }));
    }

    #[test]
    fn auth_required_preserves_caller_status() {
        let (status, body) = auth_required(StatusCode::UNAUTHORIZED);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.0, json!({ "error": "Authentication required" }));
    }

    #[test]
    fn config_path_unavailable_shape_is_stable() {
        let (status, body) = config_path_unavailable();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body.0,
            json!({ "error": "Config file path not available; cannot persist changes" })
        );
    }

    #[test]
    fn flat_error_uses_error_field() {
        let (status, body) = flat_error(StatusCode::CONFLICT, "example");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0, json!({ "error": "example" }));
    }

    #[test]
    fn structured_error_uses_error_and_message_fields() {
        let (status, body) = structured_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "bad capability name",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.0,
            json!({
                "error": "invalid_name",
                "message": "bad capability name",
            })
        );
    }
}
