//! Destructive-tool confirmation gate (OWASP ASI09 — Human Trust Exploitation).
//!
//! Before executing any meta-tool annotated with `destructiveHint: true`, the
//! gateway sends an `elicitation/create` request to the connected MCP client so
//! the human operator can confirm or decline the action.
//!
//! # Protocol behaviour
//!
//! - **Elicitation supported**: the client receives an `elicitation/create`
//!   message; the call is aborted unless the client responds `"accept"`.
//! - **Elicitation not supported / no session**: the action proceeds after a
//!   `WARN` log entry.  This matches the MCP spec guidance that servers MUST NOT
//!   break when a client omits optional capabilities.
//!
//! # Usage
//!
//! ```ignore
//! match require_destructive_confirmation(&proxy, session_id, "kill server 'payments'").await {
//!     ConfirmationOutcome::Confirmed => { /* execute */ }
//!     ConfirmationOutcome::Declined  => return /* abort, surface denial */ ,
//!     ConfirmationOutcome::Unsupported => { /* proceed with warning already logged */ }
//! }
//! ```

use std::time::Duration;

use tracing::warn;

use crate::gateway::proxy::{ProxyManager, SamplingError};
use crate::protocol::ElicitationCreateParams;

/// Timeout for a single elicitation round-trip.
const ELICITATION_TIMEOUT: Duration = Duration::from_secs(120);

/// Outcome of a destructive-action confirmation request.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmationOutcome {
    /// The operator explicitly accepted; proceed with execution.
    Confirmed,
    /// The operator declined or cancelled; abort execution.
    Declined,
    /// Elicitation could not be delivered (no session, timeout, transport
    /// failure).  The caller should proceed with a warning already emitted.
    Unsupported,
}

/// Returns `true` when the given meta-tool name carries `destructiveHint: true`.
///
/// The set is derived from `meta_mcp_tool_defs.rs`.  Only
/// `gateway_kill_server` currently sets the flag.
#[must_use]
pub fn is_destructive_meta_tool(tool_name: &str) -> bool {
    matches!(tool_name, "gateway_kill_server")
}

/// Send an `elicitation/create` confirmation request and wait for the operator
/// response before a destructive meta-tool is executed.
///
/// Returns [`ConfirmationOutcome`] — the caller decides what to do with it.
///
/// # Arguments
///
/// * `proxy`      — gateway proxy manager that owns the SSE broadcast channel.
/// * `session_id` — active MCP session ID (from the `Mcp-Session-Id` header).
/// * `action_desc` — short, human-readable description of the action about to
///   be taken (e.g. `"kill server 'payments'"`).
pub async fn require_destructive_confirmation(
    proxy: &ProxyManager,
    session_id: &str,
    action_desc: &str,
) -> ConfirmationOutcome {
    let params = build_confirmation_params(action_desc);

    match proxy
        .forward_elicitation_with_response(session_id, &params, ELICITATION_TIMEOUT)
        .await
    {
        Ok(response) => parse_elicitation_response(&response, action_desc),
        Err(SamplingError::NoSession) => {
            warn!(
                action = action_desc,
                "Destructive meta-tool invoked without active SSE session; \
                 proceeding without human confirmation (OWASP ASI09 partial)"
            );
            ConfirmationOutcome::Unsupported
        }
        Err(SamplingError::Timeout(d)) => {
            warn!(
                action = action_desc,
                timeout_secs = d.as_secs(),
                "Elicitation confirmation timed out; proceeding without confirmation \
                 (OWASP ASI09 partial)"
            );
            ConfirmationOutcome::Unsupported
        }
        Err(e) => {
            warn!(
                action = action_desc,
                error = %e,
                "Elicitation delivery failed; proceeding without confirmation \
                 (OWASP ASI09 partial)"
            );
            ConfirmationOutcome::Unsupported
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Build the [`ElicitationCreateParams`] for a destructive-action confirmation.
fn build_confirmation_params(action_desc: &str) -> ElicitationCreateParams {
    ElicitationCreateParams {
        message: format!(
            "Are you sure you want to {action_desc}? \
             This is destructive and cannot be undone. \
             Reply 'accept' to confirm or 'decline' to cancel."
        ),
        requested_schema: None,
    }
}

/// Map an elicitation JSON response body to a [`ConfirmationOutcome`].
///
/// Per MCP 2025-11-25 spec, `action` is one of `"accept"`, `"decline"`, or
/// `"cancel"`.  Anything other than `"accept"` is treated as a denial.
fn parse_elicitation_response(
    response: &serde_json::Value,
    action_desc: &str,
) -> ConfirmationOutcome {
    let action = response
        .get("action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("decline");

    if action == "accept" {
        ConfirmationOutcome::Confirmed
    } else {
        warn!(
            action_desc = action_desc,
            operator_response = action,
            "Operator declined destructive meta-tool (OWASP ASI09)"
        );
        ConfirmationOutcome::Declined
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── is_destructive_meta_tool ─────────────────────────────────────────────

    #[test]
    fn destructive_tool_gateway_kill_server_is_recognised() {
        // GIVEN/WHEN/THEN: kill server is the only destructive meta-tool
        assert!(is_destructive_meta_tool("gateway_kill_server"));
    }

    #[test]
    fn non_destructive_tools_are_not_recognised() {
        // GIVEN: a selection of non-destructive meta-tools
        let non_destructive = [
            "gateway_invoke",
            "gateway_list_servers",
            "gateway_search_tools",
            "gateway_revive_server",
            "gateway_get_stats",
            "gateway_reload_config",
            "gateway_kill_server_TYPO",
        ];
        // WHEN/THEN: none are flagged as destructive
        for name in &non_destructive {
            assert!(
                !is_destructive_meta_tool(name),
                "'{name}' should NOT be destructive"
            );
        }
    }

    // ── build_confirmation_params ────────────────────────────────────────────

    #[test]
    fn confirmation_params_contains_action_description() {
        // GIVEN: an action description
        let desc = "kill server 'payments'";
        // WHEN: building params
        let params = build_confirmation_params(desc);
        // THEN: message contains the description and the destructive warning
        assert!(params.message.contains(desc));
        assert!(params.message.contains("destructive"));
        assert!(params.message.contains("cannot be undone"));
        assert!(params.requested_schema.is_none());
    }

    // ── parse_elicitation_response ───────────────────────────────────────────

    #[test]
    fn accept_response_maps_to_confirmed() {
        // GIVEN: operator accepts
        let response = json!({"action": "accept"});
        // WHEN: parsing
        let outcome = parse_elicitation_response(&response, "kill server 'x'");
        // THEN: Confirmed
        assert_eq!(outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn decline_response_maps_to_declined() {
        // GIVEN: operator declines
        let response = json!({"action": "decline"});
        // WHEN/THEN
        assert_eq!(
            parse_elicitation_response(&response, "kill server 'x'"),
            ConfirmationOutcome::Declined
        );
    }

    #[test]
    fn cancel_response_maps_to_declined() {
        // GIVEN: operator cancels (treated same as decline per spec)
        let response = json!({"action": "cancel"});
        // WHEN/THEN
        assert_eq!(
            parse_elicitation_response(&response, "kill server 'x'"),
            ConfirmationOutcome::Declined
        );
    }

    #[test]
    fn missing_action_field_maps_to_declined() {
        // GIVEN: malformed response with no action field
        let response = json!({"content": {}});
        // WHEN/THEN: safe default is decline
        assert_eq!(
            parse_elicitation_response(&response, "kill server 'x'"),
            ConfirmationOutcome::Declined
        );
    }

    #[test]
    fn unknown_action_value_maps_to_declined() {
        // GIVEN: unknown action (e.g. future spec extension)
        let response = json!({"action": "snooze"});
        // WHEN/THEN: unknown -> decline (fail-safe)
        assert_eq!(
            parse_elicitation_response(&response, "kill server 'x'"),
            ConfirmationOutcome::Declined
        );
    }
}
