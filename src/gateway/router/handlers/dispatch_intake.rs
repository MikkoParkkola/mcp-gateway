// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The prelude of `meta_mcp_dispatch` (MIK-8143): identity, body, session,
//! signing, parse, request checks and owners, derived once per request.
//!
//! Moved verbatim from the dispatcher; each early `return <response>` became
//! `return Err(<response>)`, which the dispatcher returns unchanged.

use std::sync::Arc;

use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::{debug, warn};

use super::{
    TASKS_EXTENSION, events, listened_task_ids, owner::request_session_owner,
    reaches_tasks_extension, request_checks, session_id_header, tasks,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::recovery::SurfaceRequest;
use crate::gateway::router::AppState;
use crate::gateway::router::helpers::{
    build_accepted_response, build_error_response, build_error_response_with_data,
    build_http_error_response, build_response, extract_tools_call_params_ref, parse_request_ref,
};
use crate::gateway::session_id::SessionId;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::RequestId;
use crate::security::{
    AgentIdentity, extract_agent_identity, log_agent_identity, validate_agent_identity,
};
const DISPATCH_INTAKE_TARGET: &str = module_path!();

/// What the prelude hands the frame judge: consumed by value on the listen
/// arm, read by the postlude on every other.
pub(super) struct JudgeInputs {
    pub(super) read_guard: Option<Arc<crate::gateway::outbound::Guard>>,
    pub(super) read_key: Option<String>,
}

/// The facts the prelude derives, owned, for the method arms and the postlude.
pub(super) struct Intake<'r> {
    pub(super) headers: HeaderMap,
    pub(super) client: Option<AuthenticatedClient>,
    pub(super) cert_identity: Option<CertIdentity>,
    pub(super) oauth_agent_identity: Option<OAuthAgentIdentity>,
    /// What a stream opened by this request keeps of its identity (MIK-8350).
    view_facts: view_facts::ViewFacts,
    pub(super) verified_identity: Option<VerifiedIdentity>,
    pub(super) presented: events::Presented,
    pub(super) agent_identity: AgentIdentity,
    pub(super) code_mode_url_active: bool,
    pub(super) surface_request: SurfaceRequest,
    pub(super) grant_subject: Option<crate::identity_grants::GrantSubject>,
    pub(super) session_id: String,
    // Read only by the firewall's per-caller controls.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(super) existing_session_id: Option<String>,
    pub(super) chain_nonce: Option<String>,
    pub(super) request: Value,
    narrowed_listen: Option<Value>,
    pub(super) id: RequestId,
    pub(super) method: String,
    pub(super) era: crate::protocol::meta::Era,
    pub(super) is_modern: bool,
    pub(super) declared_capabilities: crate::protocol::meta::Declared,
    pub(super) protocol_revision_owned: Option<String>,
    pub(super) header_profile: Option<String>,
    pub(super) owner: String,
    pub(super) events_owner: String,
    pub(super) admission_owner: String,
    // Held, never read: the in-flight permit drops when the dispatcher
    // returns. The dispatcher binds `Intake` after `JudgeInputs`, so the
    // permit drops before the read guard, as the two locals did.
    _inflight_permit: Result<tokio::sync::SemaphorePermit<'r>, tokio::sync::AcquireError>,
    // Held, never read: while the request runs its provisional session is
    // not reaped, and the drop starts its idle clock (MIK-8504).
    _session_hold: Option<crate::gateway::streaming::SessionHold>,
    /// Served without a session because the provisional POST cap was
    /// full (MIK-8533). A keyless legacy caller still scores under the
    /// shared anonymous key, never as an unattributed modern request.
    pub(super) session_degraded: bool,
}

impl Intake<'_> {
    /// The request's params, or the private copy a `subscriptions/listen`
    /// narrowed to the caller's own tasks.
    pub(super) fn params(&self) -> Option<&Value> {
        self.narrowed_listen
            .as_ref()
            .or_else(|| self.request.get("params"))
    }

    /// The refusal a session tool gets on a request served without a session
    /// at the provisional cap (MIK-8533). Decided here, where the degrade is
    /// known: the meta layer sees only "no session" and answers in the 2026
    /// era's terms, which tell a 2025-era caller nothing it can act on.
    pub(super) fn degraded_session_tool_refusal(&self) -> Option<&'static str> {
        if !self.session_degraded {
            return None;
        }
        match self.external_tool() {
            "gateway_set_state" => Some(
                "Protocol error: The workflow state is per-session, and this request has no \
                 session because the gateway's provisional-session capacity is full. Send \
                 initialize to open a session, then retry with its id.",
            ),
            "gateway_set_profile" | "gateway_get_profile" => Some(
                "Protocol error: Routing profiles are per-session, and this request has no \
                 session because the gateway's provisional-session capacity is full. Send \
                 initialize to open a session, then retry with its id.",
            ),
            _ => None,
        }
    }

    /// The name the response policy and answer shape key on: the tool for a
    /// `tools/call`, else the method. Read from the request, not copied
    /// (MIK-8014 design item 5).
    pub(super) fn external_tool(&self) -> &str {
        if self.method == "tools/call" {
            extract_tools_call_params_ref(self.params()).0
        } else {
            &self.method
        }
    }
}

/// The key a `/mcp` caller's explicit cancel of its own call `id` is
/// registered and looked up under (MIK-7642 PR.C, design r6 PR.C): the route,
/// the caller's key (`identity::caller_key`: its subject, else its
/// authenticated credential), its session (none for a modern-by-header
/// caller, whose session id is empty), and the client's id.
pub(super) fn mcp_cancel_key(
    caller: (
        Option<&crate::identity_grants::GrantSubject>,
        Option<&CertIdentity>,
        Option<&AuthenticatedClient>,
    ),
    session_id: &str,
    id: &Value,
) -> Option<crate::gateway::router::inflight_calls::CallKey> {
    let owner = crate::gateway::router::identity::caller_key(caller.0, caller.1, caller.2);
    let session = (!session_id.is_empty()).then_some(session_id);
    crate::gateway::router::inflight_calls::CallKey::new("/mcp", Some(&owner), session, id)
}

#[cfg(test)]
#[path = "dispatch_intake_cancel_key_tests.rs"]
mod cancel_key_tests;

#[cfg(test)]
#[path = "dispatch_intake_judgement_tests.rs"]
mod judgement_tests;

#[cfg(test)]
#[path = "dispatch_intake_presented_tests.rs"]
mod presented_tests;

#[path = "dispatch_intake_run.rs"]
mod run;
pub(super) use run::intake;
#[path = "dispatch_intake_session.rs"]
mod session;
#[path = "dispatch_intake_view_facts.rs"]
mod view_facts;
