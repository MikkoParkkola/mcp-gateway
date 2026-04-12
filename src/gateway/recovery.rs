//! Structured recovery hints for tool-call errors (issue #115).
//!
//! When a tool call fails the gateway attaches a `recovery` object to the MCP
//! error response so that the LLM caller can understand *what* went wrong and
//! *how* to fix it without guessing from a plain-text message.
//!
//! The `recovery` field is **additive** — the existing `isError` + `content`
//! fields are never touched.  Downstream consumers that do not know about
//! `recovery` will simply ignore it.
//!
//! # Response shape
//!
//! ```json
//! {
//!   "isError": true,
//!   "content": [{"type": "text", "text": "Validation failed for 'flights.search'"}],
//!   "recovery": {
//!     "error_code": "INVALID_PARAM",
//!     "message": "departure_date must be YYYY-MM-DD",
//!     "suggest": "Reformat the date and retry",
//!     "fix_example": {"departure_date": "2026-04-18"},
//!     "related_tools": [],
//!     "retry": true
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Public types
// ============================================================================

/// Classification of an error that occurred during tool dispatch.
///
/// Each variant maps to a canonical error code and a default recovery
/// strategy that guides the LLM on how to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// A required parameter was missing, had the wrong type, or violated a
    /// schema constraint (e.g. wrong date format, enum value out of range).
    Validation,
    /// The backend returned an error (non-2xx HTTP, JSON-RPC error payload,
    /// or a transport-level failure after the connection was established).
    BackendError,
    /// The circuit breaker for the target backend is currently open.
    /// Requests will be rejected without being forwarded.
    CircuitBreakerTrip,
    /// No backend or capability with the requested name is registered.
    NotFound,
    /// The request was rejected because a rate limit was exceeded.
    RateLimited,
    /// The backend did not respond within the configured timeout.
    Timeout,
}

/// Machine-readable error codes embedded in recovery hints.
pub mod error_codes {
    /// A required parameter was missing, had the wrong type, or violated a schema constraint.
    pub const INVALID_PARAM: &str = "INVALID_PARAM";
    /// The requested tool was not found on any connected backend.
    pub const TOOL_NOT_FOUND: &str = "TOOL_NOT_FOUND";
    /// The backend could not be reached (connection refused, DNS failure, etc.).
    pub const BACKEND_UNREACHABLE: &str = "BACKEND_UNREACHABLE";
    /// The request was rejected because a rate limit was exceeded.
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    /// The circuit breaker for the backend is open — requests are being shed.
    pub const CIRCUIT_OPEN: &str = "CIRCUIT_OPEN";
    /// The backend did not respond within the configured timeout.
    pub const BACKEND_TIMEOUT: &str = "BACKEND_TIMEOUT";
    /// The backend returned an error response.
    pub const BACKEND_ERROR: &str = "BACKEND_ERROR";
}

/// Recovery guidance attached to a failed tool-call response.
///
/// All fields except `error_code`, `message`, and `retry` are optional —
/// they are populated only when the gateway has enough context to provide
/// actionable advice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryHint {
    /// Machine-readable error code (see [`error_codes`]).
    pub error_code: String,
    /// Human-readable description of the problem.
    pub message: String,
    /// Concrete suggestion for the LLM on how to recover.
    pub suggest: String,
    /// An example of a corrected request body (for validation errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_example: Option<Value>,
    /// Other tools in the same namespace that might achieve the same goal.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_tools: Vec<String>,
    /// Whether the same call (possibly after correction) is safe to retry.
    pub retry: bool,
}

// ============================================================================
// Context passed to recovery_for
// ============================================================================

/// Additional context provided by the call site to enrich the hint.
#[derive(Debug, Default)]
pub struct RecoveryContext<'a> {
    /// The tool name that was being called.
    pub tool: Option<&'a str>,
    /// The backend / server name.
    pub backend: Option<&'a str>,
    /// Optional override for the human-readable message (e.g. the raw error
    /// string from the backend).
    pub detail: Option<&'a str>,
    /// Example corrected arguments (validation errors only).
    pub fix_example: Option<Value>,
    /// Levenshtein-close tool names suggested by the gateway ("did you mean?").
    pub related_tools: Vec<String>,
}

// ============================================================================
// Core mapping function
// ============================================================================

/// Map an [`ErrorCategory`] + optional context to a [`RecoveryHint`].
///
/// This is the single entry point used by the gateway when constructing a
/// structured error response.  Call sites only need to classify the error;
/// the default message and suggestion come from this function.
#[must_use]
#[allow(clippy::too_many_lines)] // match arms are inherently verbose; splitting would add no clarity
pub fn recovery_for(category: ErrorCategory, ctx: RecoveryContext<'_>) -> RecoveryHint {
    let tool_label = ctx.tool.unwrap_or("<unknown tool>");
    let backend_label = ctx.backend.unwrap_or("<unknown backend>");

    match category {
        ErrorCategory::Validation => RecoveryHint {
            error_code: error_codes::INVALID_PARAM.to_string(),
            message: ctx.detail.map_or_else(
                || format!("Validation failed for '{tool_label}'"),
                str::to_string,
            ),
            suggest:
                "Check the tool's input schema, correct the offending parameter(s), and retry."
                    .to_string(),
            fix_example: ctx.fix_example,
            related_tools: ctx.related_tools,
            retry: true,
        },

        ErrorCategory::BackendError => RecoveryHint {
            error_code: error_codes::BACKEND_ERROR.to_string(),
            message: ctx.detail.map_or_else(
                || format!("Backend '{backend_label}' returned an error for tool '{tool_label}'"),
                str::to_string,
            ),
            suggest: "Inspect the error message for details. \
                      The issue may be a transient server error — retrying once is safe."
                .to_string(),
            fix_example: None,
            related_tools: ctx.related_tools,
            retry: true,
        },

        ErrorCategory::CircuitBreakerTrip => RecoveryHint {
            error_code: error_codes::CIRCUIT_OPEN.to_string(),
            message: ctx.detail.map_or_else(
                || {
                    format!(
                        "Circuit breaker is open for backend '{backend_label}' — \
                         requests are being rejected to protect the system."
                    )
                },
                str::to_string,
            ),
            suggest: "Wait for the circuit breaker to recover (automatic) or use \
                      `gateway_revive_server` to reset it manually. \
                      Do not retry in a tight loop."
                .to_string(),
            fix_example: None,
            related_tools: ctx.related_tools,
            retry: false,
        },

        ErrorCategory::NotFound => RecoveryHint {
            error_code: error_codes::TOOL_NOT_FOUND.to_string(),
            message: ctx.detail.map_or_else(
                || format!("Tool '{tool_label}' was not found on backend '{backend_label}'"),
                str::to_string,
            ),
            suggest: if ctx.related_tools.is_empty() {
                "Use `gateway_list_tools` to discover available tools.".to_string()
            } else {
                format!(
                    "Did you mean one of: {}? \
                     Use `gateway_list_tools` to see all available tools.",
                    ctx.related_tools.join(", ")
                )
            },
            fix_example: None,
            related_tools: ctx.related_tools,
            retry: false,
        },

        ErrorCategory::RateLimited => RecoveryHint {
            error_code: error_codes::RATE_LIMITED.to_string(),
            message: ctx.detail.map_or_else(
                || {
                    format!(
                        "Rate limit exceeded for tool '{tool_label}' on backend '{backend_label}'"
                    )
                },
                str::to_string,
            ),
            suggest: "Slow down — wait a moment before retrying. \
                      Consider batching requests if high throughput is needed."
                .to_string(),
            fix_example: None,
            related_tools: ctx.related_tools,
            retry: true,
        },

        ErrorCategory::Timeout => RecoveryHint {
            error_code: error_codes::BACKEND_TIMEOUT.to_string(),
            message: ctx.detail.map_or_else(
                || {
                    format!(
                        "Backend '{backend_label}' did not respond in time \
                         for tool '{tool_label}'"
                    )
                },
                str::to_string,
            ),
            suggest: "The backend may be temporarily overloaded. \
                      Retry once after a short delay."
                .to_string(),
            fix_example: None,
            related_tools: ctx.related_tools,
            retry: true,
        },
    }
}

// ============================================================================
// Convenience: attach a recovery hint to an existing JSON response value
// ============================================================================

/// Inject a [`RecoveryHint`] into a JSON `Value` (must be an object) under
/// the `"recovery"` key.
///
/// If serialization of the hint fails the original value is returned
/// unchanged — recovery hints are advisory and must not cause cascading
/// failures.
pub fn attach_recovery(mut value: Value, hint: RecoveryHint) -> Value {
    if let Value::Object(ref mut map) = value
        && let Ok(hint_value) = serde_json::to_value(hint)
    {
        map.insert("recovery".to_string(), hint_value);
    }
    value
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_for(tool: &str) -> RecoveryContext<'_> {
        RecoveryContext {
            tool: Some(tool),
            backend: Some("mybackend"),
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // Error category → hint field assertions
    // -----------------------------------------------------------------------

    #[test]
    fn validation_hint_has_correct_code_and_retry() {
        let hint = recovery_for(ErrorCategory::Validation, ctx_for("flights.search"));
        assert_eq!(hint.error_code, error_codes::INVALID_PARAM);
        assert!(
            hint.retry,
            "validation errors should be retryable after correction"
        );
    }

    #[test]
    fn circuit_breaker_hint_is_not_retryable() {
        let hint = recovery_for(
            ErrorCategory::CircuitBreakerTrip,
            ctx_for("payments.charge"),
        );
        assert_eq!(hint.error_code, error_codes::CIRCUIT_OPEN);
        assert!(
            !hint.retry,
            "circuit-open errors must not encourage immediate retry"
        );
    }

    #[test]
    fn not_found_hint_surfaces_related_tools() {
        let ctx = RecoveryContext {
            tool: Some("flights.searc"),
            backend: Some("travel"),
            related_tools: vec!["flights.search".to_string(), "flights.list".to_string()],
            ..Default::default()
        };
        let hint = recovery_for(ErrorCategory::NotFound, ctx);
        assert_eq!(hint.error_code, error_codes::TOOL_NOT_FOUND);
        assert_eq!(hint.related_tools.len(), 2);
        assert!(
            hint.suggest.contains("flights.search"),
            "suggest should mention the related tools"
        );
        assert!(!hint.retry);
    }

    #[test]
    fn validation_hint_includes_fix_example() {
        let ctx = RecoveryContext {
            tool: Some("flights.search"),
            backend: Some("travel"),
            detail: Some("departure_date must be YYYY-MM-DD"),
            fix_example: Some(json!({"departure_date": "2026-04-18"})),
            ..Default::default()
        };
        let hint = recovery_for(ErrorCategory::Validation, ctx);
        let example = hint.fix_example.unwrap();
        assert_eq!(example["departure_date"], "2026-04-18");
    }

    #[test]
    fn timeout_and_rate_limited_are_retryable() {
        let hint_t = recovery_for(ErrorCategory::Timeout, ctx_for("slow.tool"));
        let hint_r = recovery_for(ErrorCategory::RateLimited, ctx_for("hot.tool"));
        assert!(hint_t.retry);
        assert!(hint_r.retry);
    }

    // -----------------------------------------------------------------------
    // attach_recovery — backward compat
    // -----------------------------------------------------------------------

    #[test]
    fn attach_recovery_adds_field_without_touching_existing_fields() {
        let original = json!({
            "isError": true,
            "content": [{"type": "text", "text": "Something went wrong"}]
        });
        let hint = recovery_for(
            ErrorCategory::BackendError,
            RecoveryContext {
                tool: Some("some.tool"),
                backend: Some("backend"),
                ..Default::default()
            },
        );
        let enriched = attach_recovery(original, hint);

        // Original fields intact
        assert_eq!(enriched["isError"], true);
        assert!(enriched["content"].is_array());

        // Recovery field added
        let recovery = &enriched["recovery"];
        assert_eq!(recovery["error_code"], error_codes::BACKEND_ERROR);
        assert!(recovery["retry"].as_bool().unwrap());
    }

    #[test]
    fn attach_recovery_on_non_object_is_noop() {
        let scalar = json!("just a string");
        let hint = recovery_for(ErrorCategory::Timeout, ctx_for("tool"));
        let result = attach_recovery(scalar.clone(), hint);
        // Should return unchanged (not an object)
        assert_eq!(result, scalar);
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_hint_serializes_related_tools_only_when_non_empty() {
        // Empty related_tools → field omitted
        let hint = recovery_for(ErrorCategory::Timeout, ctx_for("tool"));
        let v = serde_json::to_value(&hint).unwrap();
        assert!(
            v.get("related_tools").is_none(),
            "related_tools should be omitted when empty"
        );

        // Non-empty related_tools → field present
        let ctx = RecoveryContext {
            tool: Some("tool"),
            related_tools: vec!["other.tool".to_string()],
            ..Default::default()
        };
        let hint2 = recovery_for(ErrorCategory::NotFound, ctx);
        let v2 = serde_json::to_value(&hint2).unwrap();
        assert!(v2.get("related_tools").is_some());
    }

    #[test]
    fn recovery_hint_fix_example_omitted_when_none() {
        let hint = recovery_for(ErrorCategory::BackendError, ctx_for("tool"));
        let v = serde_json::to_value(&hint).unwrap();
        assert!(
            v.get("fix_example").is_none(),
            "fix_example should be omitted when None"
        );
    }
}
