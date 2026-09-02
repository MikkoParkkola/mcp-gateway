// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Destructive-tool confirmation prompt.
//!
//! **This is a courtesy, not a security control.** It asks the connected client
//! to confirm with the human before a destructive meta-tool runs, and it
//! proceeds when the client cannot ask — see the outcome table below. A caller
//! that wants to skip it simply declares no elicitation capability, so it stops
//! nobody who is trying to get past it.
//!
//! What actually restricts these tools is the admin requirement: every tool this
//! covers is in the admin set, so a caller without a credential cannot reach one
//! at all. That is the control; this is the confirmation an honest client offers
//! its user.
//!
//! It is documented this way deliberately. An earlier version of this header
//! cited OWASP ASI09, which reads as a control and invites over-trust in a
//! prompt that waves things through.
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

use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;

use tracing::warn;

use crate::gateway::meta_mcp_tool_defs::{build_code_mode_tools, build_meta_tools};
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

/// What the gateway does when it cannot ask.
///
/// Named as a policy rather than decided inline, because the two eras get
/// different answers and the difference is deliberate rather than an oversight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationPolicy(&'static str);

impl ConfirmationPolicy {
    /// Refuse the call. There is no way to ask, so it does not run.
    pub const REFUSE: &'static str = "refuse";
    /// Run it, having logged that nobody was asked.
    pub const PROCEED_WITH_WARNING: &'static str = "proceed-with-warning";

    /// The policy for a request written against 2026-07-28.
    ///
    /// Refuse. The old behaviour proceeded on a warning when elicitation was
    /// unsupported **or there was no session** — and this revision deletes
    /// sessions, so *every* modern destructive call would take that branch. A
    /// gate that is open for everyone is not a gate, and the modern path has no
    /// history of working differently to protect.
    pub const fn for_modern() -> Self {
        Self(Self::REFUSE)
    }

    /// The policy for a request written against an earlier revision.
    ///
    /// Unchanged. A 2025 client that never declared elicitation has been served
    /// this way for the life of the gateway; tightening it here would be a
    /// breaking change made in passing rather than decided. The asymmetry is
    /// the point: the modern path starts closed because it has never been open.
    pub const fn for_legacy() -> Self {
        Self(Self::PROCEED_WITH_WARNING)
    }

    /// What to do when confirmation cannot be obtained.
    #[must_use]
    pub const fn on_unconfirmable(self) -> &'static str {
        self.0
    }
}

/// How a caller can be asked to confirm a destructive action.
///
/// Carried in the caller context so the gate lives at the dispatcher, where
/// every transport passes, instead of on one transport's edge. A transport
/// that has no way to reach an operator says so here; it does not get to skip
/// the gate by not running the code that holds it.
pub enum ConfirmationChannel<'a> {
    /// An asker may exist. `proxy` reaches it; `policy` says what to do when
    /// the ask fails. Constructed even when no session is present: "found no
    /// session" is an outcome of asking, decided by `policy`, not a property
    /// of the transport.
    Elicit {
        /// Proxy manager owning the elicitation channel.
        proxy: &'a ProxyManager,
        /// What to do when confirmation cannot be obtained.
        policy: ConfirmationPolicy,
    },
    /// No asker can exist on this transport. The action is refused; nothing
    /// is elicited.
    Unavailable,
}

/// A human-readable description of the destructive action, for the operator
/// prompt and for the refusal message.
///
/// Takes the tool's `arguments` object, not the enclosing request params: the
/// enclosing object compiles just as well and silently yields the fallback
/// text for every action.
#[must_use]
pub fn describe_destructive_action(tool_name: &str, arguments: &serde_json::Value) -> String {
    match tool_name {
        "gateway_kill_server" => {
            let server = arguments
                .get("server")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(UNKNOWN_SERVER);
            format!("kill server '{server}'")
        }
        other => format!("execute destructive meta-tool '{other}'"),
    }
}

/// Stand-in used when a destructive call names no target.
const UNKNOWN_SERVER: &str = "<unknown>";

/// The tools a `tools/list` says are destructive.
///
/// Derived from the `destructiveHint` annotation rather than a match arm. The
/// gate was written for one tool name, so a tool added later with the same
/// annotation inherited nothing — which is how a gate ends up guarding one door
/// in a building that grew.
#[must_use]
pub fn destructive_tools_from_annotations(tools: &serde_json::Value) -> HashSet<String> {
    tools
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|tool| {
                    tool.get("annotations")
                        .and_then(|a| a.get("destructiveHint"))
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                })
                .filter_map(|tool| {
                    tool.get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The floor: kept governed regardless of what the annotations say, so an
/// annotation dropped by accident from `meta_mcp_tool_defs.rs` cannot quietly
/// ungovern the one destructive tool the gate was originally written for.
const FLOOR_TOOL_NAME: &str = "gateway_kill_server";

/// The meta-tool names this gate governs, computed once from the compile-time
/// tool definitions rather than rebuilt on every call.
///
/// Built with every feature flag enabled — stats, cost report, webhooks, and
/// config reload — so a destructive tool gated behind a disabled feature is
/// still governed once that feature turns on; the gate must not depend on
/// which flags happen to be set at startup. Code Mode's two tools are
/// included too, since Code Mode replaces the traditional tool list rather
/// than adding to it, and the gate must cover whichever surface is active.
///
/// Backend and capability tools are deliberately absent: they are not part of
/// `meta_mcp_tool_defs.rs`, `infer_destructive_tool()` only guesses their
/// hints by substring match, and `ConfirmationPolicy::for_modern()` is an
/// unconditional refusal — governing them here would refuse a large slice of
/// the tool surface with no confirmation path. See the module docs.
static DESTRUCTIVE_META_TOOLS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut tools = build_meta_tools(true, true, true, true, 0, 0);
    tools.extend(build_code_mode_tools());
    let json = serde_json::to_value(&tools).unwrap_or(serde_json::Value::Null);
    let mut governed = destructive_tools_from_annotations(&json);
    governed.insert(FLOOR_TOOL_NAME.to_string());
    governed
});

/// Whether a meta-tool is one the confirmation gate governs.
///
/// Derived from [`DESTRUCTIVE_META_TOOLS`], itself derived from the
/// `destructiveHint` annotation on the gateway's own compile-time meta-tool
/// definitions in `meta_mcp_tool_defs.rs` — not from a hardcoded match arm.
/// A tool added later with the same annotation is governed automatically,
/// which is how a gate stops guarding one door in a building that grew.
#[must_use]
pub fn is_destructive_meta_tool(tool_name: &str) -> bool {
    DESTRUCTIVE_META_TOOLS.contains(tool_name)
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
                 proceeding without human confirmation"
            );
            ConfirmationOutcome::Unsupported
        }
        Err(SamplingError::Timeout(d)) => {
            warn!(
                action = action_desc,
                timeout_secs = d.as_secs(),
                "Elicitation confirmation timed out; proceeding without confirmation \
                "
            );
            ConfirmationOutcome::Unsupported
        }
        Err(e) => {
            warn!(
                action = action_desc,
                error = %e,
                "Elicitation delivery failed; proceeding without confirmation \
                "
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
        // GIVEN/WHEN/THEN: kill server is governed (the explicit floor)
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

    #[test]
    fn read_only_meta_tool_gateway_list_servers_is_not_governed() {
        // GIVEN: a read-only, non-destructive meta-tool definition
        // WHEN/THEN: the gate does not govern it
        assert!(!is_destructive_meta_tool("gateway_list_servers"));
    }

    #[test]
    fn unknown_or_backend_tool_name_is_not_governed() {
        // GIVEN: names that are not compile-time meta-tool definitions at all
        // (backend/capability tool names, or plain garbage) — the confirmation
        // gate explicitly defers on these (team-lead scope: backend/capability
        // tools are OUT OF SCOPE for this gate; ConfirmationPolicy::for_modern()
        // is an unconditional refusal, so governing them would block a large
        // slice of the tool surface with no confirmation path).
        let deferred = [
            "some_backend_tool_delete_everything",
            "capability_stripe_charge_refund",
            "not_a_real_tool_at_all",
        ];
        // WHEN/THEN: none are governed by the meta-tool gate
        for name in &deferred {
            assert!(
                !is_destructive_meta_tool(name),
                "'{name}' should NOT be governed (deferred: backend/capability tool)"
            );
        }
    }

    #[test]
    fn every_meta_tool_with_destructive_hint_true_is_governed() {
        // GIVEN: the REAL compile-time meta-tool definitions, built with every
        // feature flag on (so a flag-gated destructive tool is still covered),
        // plus the Code Mode tool set.
        use crate::gateway::meta_mcp_tool_defs::{build_code_mode_tools, build_meta_tools};

        let mut tools = build_meta_tools(true, true, true, true, 0, 0);
        tools.extend(build_code_mode_tools());

        // WHEN/THEN: every tool whose annotations carry `destructiveHint: true`
        // is recognised by the gate — proven from the definitions themselves,
        // not from a name hardcoded in this test. A future destructive meta-tool
        // added to meta_mcp_tool_defs.rs without updating the gate fails this
        // assertion the moment it sets `destructive_hint: Some(true)`.
        let mut governed_count = 0;
        for tool in &tools {
            let carries_destructive_hint = tool
                .annotations
                .as_ref()
                .is_some_and(|a| a.destructive_hint == Some(true));
            if carries_destructive_hint {
                governed_count += 1;
                assert!(
                    is_destructive_meta_tool(&tool.name),
                    "'{}' carries destructiveHint:true but is NOT governed",
                    tool.name
                );
            }
        }
        // Sanity: the fixture actually exercised at least one destructive tool,
        // so this test cannot pass vacuously if every annotation were stripped.
        assert!(
            governed_count >= 1,
            "expected at least one destructive meta-tool in the fixture"
        );
    }

    #[test]
    fn governed_set_is_derived_not_hand_duplicated() {
        // GIVEN: the same annotation-filter helper the implementation must use,
        // applied independently in the test to the real compile-time defs.
        // Proves DESTRUCTIVE_META_TOOLS is DERIVED from annotations (this test
        // fails to compile until that static exists — the RED before
        // `is_destructive_meta_tool` stops being a hardcoded match arm) rather
        // than a second, hand-maintained copy of the same predicate.
        use crate::gateway::meta_mcp_tool_defs::{build_code_mode_tools, build_meta_tools};

        let mut tools = build_meta_tools(true, true, true, true, 0, 0);
        tools.extend(build_code_mode_tools());
        let json = serde_json::to_value(&tools).expect("tool defs must serialize");
        let mut expected = destructive_tools_from_annotations(&json);
        expected.insert("gateway_kill_server".to_string()); // the floor

        // WHEN/THEN: the gate's governed set is exactly this, no more no less.
        assert_eq!(&*DESTRUCTIVE_META_TOOLS, &expected);
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
    // ── describe_destructive_action ──────────────────────────────────────────

    #[test]
    fn kill_server_description_names_the_target() {
        // GIVEN: the tool's own arguments object, carrying the target
        let arguments = json!({"server": "brave"});
        // WHEN/THEN: the description names the server the operator agrees to lose
        assert_eq!(
            describe_destructive_action("gateway_kill_server", &arguments),
            "kill server 'brave'"
        );
    }

    #[test]
    fn kill_server_without_a_target_falls_back_rather_than_panicking() {
        // GIVEN: a call that names no server (the gate still has to say something)
        let arguments = json!({});
        // WHEN/THEN: the stand-in appears in place of a name, and nothing panics
        assert_eq!(
            describe_destructive_action("gateway_kill_server", &arguments),
            "kill server '<unknown>'"
        );
    }

    #[test]
    fn the_enclosing_params_object_yields_the_fallback_not_the_server_name() {
        // GIVEN: the ENCLOSING request params, not the arguments object. This is
        // the mistake this function's doc comment warns about: it type-checks,
        // and every action then silently describes itself as untargeted.
        let params = json!({
            "name": "gateway_kill_server",
            "arguments": {"server": "brave"}
        });
        // WHEN: described from the wrong level
        let described = describe_destructive_action("gateway_kill_server", &params);
        // THEN: the fallback, never the name buried one level down. Asserting the
        // absence as well as the equality is what makes this a check on the
        // degradation rather than on the fallback string: a describer that
        // reached into `arguments` would break the first assertion, and one that
        // found the name by some other route would break the second.
        assert_eq!(described, "kill server '<unknown>'");
        assert!(
            !described.contains("brave"),
            "the wrong level must not reach the target name: {described}"
        );
    }

    #[test]
    fn an_unrecognised_destructive_tool_is_described_by_name() {
        // GIVEN: a destructive tool this match has no arm for -- the annotations
        // can govern a tool the describer never learned about
        let arguments = json!({"server": "brave"});
        // WHEN/THEN: the operator is still told which tool, not just "something"
        assert_eq!(
            describe_destructive_action("gateway_future_wipe", &arguments),
            "execute destructive meta-tool 'gateway_future_wipe'"
        );
    }
}
