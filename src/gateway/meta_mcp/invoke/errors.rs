// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recovery classification of dispatch errors.

use serde_json::{Value, json};

use super::audit;
use crate::gateway::recovery::{
    ErrorCategory, MetaSurface, RecoveryContext, Revive, SurfaceRequest, attach_recovery,
    recovery_for_surface,
};
use crate::gateway::router::CallerStanding;
use crate::{Error, Result};

// ============================================================================
// Recovery classification helpers
// ============================================================================

/// A dispatched failure as the caller receives it: a tool result, not a
/// JSON-RPC protocol error, carrying `isError`, the text and a recovery hint,
/// so the model gets actionable guidance without breaking the MCP framing.
/// The audit record still says `error` with the failure's code (D1-d.2). A11:
/// an upstream-rejection mark sets the hint's code and retry flag. Shared by
/// the first dispatch and a bridged continuation, so both answer alike.
pub(super) fn dispatch_error_result(
    e: &Error,
    tool: &str,
    server: &str,
    surface: MetaSurface,
) -> Value {
    audit::note_dispatch_failure(e);
    let (category, detail) = classify_dispatch_error(e);
    let mut hint = recovery_for_surface(
        category,
        RecoveryContext {
            tool: Some(tool),
            backend: Some(server),
            detail: Some(&detail),
            ..Default::default()
        },
        surface,
    );
    if let Some(rejection) = crate::personal_accounts::refusal::upstream_rejection(e) {
        rejection.error_code.clone_into(&mut hint.error_code);
        hint.retry = rejection.retry;
    }
    let answer = attach_recovery(
        json!({
            "isError": true,
            "content": [{"type": "text", "text": e.to_string()}],
        }),
        hint,
    );
    // MIK-7939: the hint is the gateway's text, never a receipt's.
    super::gateway_writes::note(super::gateway_writes::Layer::Value, &["recovery"], &answer);
    answer
}

impl super::MetaMcp {
    /// The meta-tools `caller` can see, for recovery hints: Code Mode (the
    /// gateway's or this request's `?codemode=`) exposes only `gateway_search`
    /// and `gateway_execute`, and `exposed_meta_tools` can hide either mode's
    /// discovery tool. `gateway_revive_server` is offered only when this caller
    /// may list and call it, by the predicate `tools/list` uses (MIK-7974).
    pub(super) fn hint_surface(
        &self,
        caller: &super::super::MetaMcpCallerContext<'_>,
    ) -> MetaSurface {
        const REVIVE: &str = "gateway_revive_server";
        let surface =
            if self.code_mode_enabled || caller.surface_request == SurfaceRequest::CodeMode {
                MetaSurface::CodeMode
            } else if self.meta_tool_exposure.is_exposed(REVIVE)
                && CallerStanding::of_admin_flag(caller.is_admin).permits(REVIVE)
            {
                MetaSurface::Standard(Revive::Offered)
            } else {
                MetaSurface::Standard(Revive::Hidden)
            };
        match surface.discovery_tool() {
            Some(tool) if !self.meta_tool_exposure.is_exposed(tool) => MetaSurface::Undiscoverable,
            _ => surface,
        }
    }
}

/// Map a dispatch [`Error`] to an [`ErrorCategory`] and a human-readable detail
/// string suitable for embedding in a [`RecoveryHint`].
pub(super) fn classify_dispatch_error(error: &Error) -> (ErrorCategory, String) {
    match error {
        Error::CircuitOpen {
            backend,
            last_failure,
        } => (
            ErrorCategory::CircuitBreakerTrip,
            match last_failure {
                Some(reason) => {
                    format!(
                        "Circuit breaker is open for backend '{backend}'; last failure: {reason}"
                    )
                }
                None => format!("Circuit breaker is open for backend '{backend}'"),
            },
        ),
        _ if error.is_gateway_throttle() => (ErrorCategory::RateLimited, error.to_string()),
        Error::BackendNotFound(name) | Error::ToolNotFound(name) => {
            (ErrorCategory::NotFound, format!("Not found: '{name}'"))
        }
        Error::BackendTimeout(msg) => (ErrorCategory::Timeout, msg.clone()),
        Error::BackendUnavailable(msg) | Error::Transport(msg) | Error::TransportConnect(msg) => {
            (ErrorCategory::BackendError, msg.clone())
        }
        // Protocol errors carry upstream HTTP failures as their message
        // (e.g. "API returned 429 Too Many Requests"). Inspect the text so a
        // rate limit or transient 5xx is not mislabelled as a param error.
        Error::Protocol(msg) => (classify_from_detail(Some(msg)), msg.clone()),
        Error::JsonRpc { message, .. } => (ErrorCategory::BackendError, message.clone()),
        // A capability 429 arrives as a typed `Http` error and no longer says
        // "429" in its message, so the prose classifier above cannot see it.
        // Without this arm the hint silently degrades to `BackendError` and the
        // client is told to retry immediately (GH475.RL.10).
        Error::Http(e) if e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS) => {
            (ErrorCategory::RateLimited, error.to_string())
        }
        _ => (ErrorCategory::BackendError, error.to_string()),
    }
}

/// How a dispatch counts against the error budgets.
///
/// A `bool` cannot express the third case: an outcome that is neither a success
/// nor a failure and must leave the window untouched (GH #475).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gateway::meta_mcp) enum BudgetOutcome {
    Success,
    Failure,
    /// Throttled: the backend answered "not so fast", or the gateway's own
    /// rate limiter refused before dispatch (F23). Neither is evidence about
    /// the backend's health, so neither is sampled.
    IgnoredRateLimit,
}

impl BudgetOutcome {
    /// Classify a dispatch result.
    ///
    /// Rate limiting is recognised through the same predicate the backend
    /// circuit breaker uses, so the two cannot disagree about what a throttled
    /// response is.
    ///
    /// MCP carries tool-level failures *inside* a successful response
    /// (`isError: true`), so a throttled backend can answer `Ok`. Reading only
    /// the `Result` shape would sample that as a healthy call and defeat RL.1
    /// for every backend that reports its 429 the protocol's own way.
    pub(in crate::gateway::meta_mcp) fn of(result: &Result<Value>) -> Self {
        match result {
            Ok(response) => Self::of_value(response),
            Err(error) => Self::of_error(error),
        }
    }

    /// [`Self::of`] for a result the backend answered.
    pub(in crate::gateway::meta_mcp) fn of_value(response: &Value) -> Self {
        let is_error = response
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Scanning the whole envelope is safe only because `isError`
        // gates it: on a successful result the same text is ordinary
        // payload and must not exempt anything.
        if is_error && crate::gateway::recovery::is_rate_limited(&response.to_string()) {
            Self::IgnoredRateLimit
        } else {
            // A non-rate-limit `isError: true` is a tool refusing a
            // request, not a backend in poor health: a bad argument or
            // a missing file would otherwise open a circuit on a
            // backend that answered correctly every time. It is
            // sampled as a success on purpose.
            Self::Success
        }
    }

    /// [`Self::of`] for a dispatch that failed.
    pub(in crate::gateway::meta_mcp) fn of_error(error: &Error) -> Self {
        // The gateway refused before asking the backend (F23, #2300).
        if error.is_gateway_throttle()
            || crate::gateway::recovery::is_rate_limited(&error.to_string())
        {
            Self::IgnoredRateLimit
        } else {
            Self::Failure
        }
    }
}

/// Infer an [`ErrorCategory`] from a backend error/detail string by scanning
/// for HTTP-status signals.
///
/// Capability backends (and the `Error::Protocol` variant) surface upstream
/// HTTP failures as free-text messages rather than typed errors. Without this,
/// a `429 Too Many Requests` is reported as `INVALID_PARAM` with a
/// "fix your parameters" hint — wrong and unactionable, since the call is
/// correct and merely needs a retry after backoff.
///
/// Matching is case-insensitive and conservative: anything that does not match
/// a known signal falls back to [`ErrorCategory::Validation`], preserving the
/// prior behaviour for genuine schema violations.
pub(super) fn classify_from_detail(detail: Option<&str>) -> ErrorCategory {
    let Some(text) = detail else {
        return ErrorCategory::Validation;
    };
    let lower = text.to_ascii_lowercase();

    // Rate limiting — retryable after backoff, NOT a param error.
    //
    // Delegated to the shared predicate so this classifier and the backend
    // circuit breaker cannot disagree about what a rate-limit response is
    // (GH #475). The narrowing lives there, with its rationale.
    if crate::gateway::recovery::is_rate_limited(text) {
        return ErrorCategory::RateLimited;
    }

    // Timeouts / gateway-timeout — backend was reachable but slow.
    if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("408")
        || lower.contains("504")
        || lower.contains("gateway timeout")
    {
        return ErrorCategory::Timeout;
    }

    // Transient server-side failures — safe to retry once.
    if lower.contains("500")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("internal server error")
        || lower.contains("bad gateway")
        || lower.contains("service unavailable")
    {
        return ErrorCategory::BackendError;
    }

    ErrorCategory::Validation
}

#[cfg(test)]
#[path = "hint_surface_tests.rs"]
mod hint_surface_tests;
