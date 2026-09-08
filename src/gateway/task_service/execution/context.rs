// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owned caller and admission twins. Nothing here is borrowed from the request future.

use serde_json::Value;

use crate::gateway::authz::ToolAuthorizer;
use crate::gateway::destructive_confirmation::ConfirmationChannel;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::router::{AppState, OwnedRouterAuthorizer, RouterAuthorizer};
use crate::idempotency::admission::{Mode, Request};
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::NO_RETRY;

/// Snapshot of the creating request's identity, rebuilt as a borrowed caller
/// context at dispatch. `task` is always `None` on the rebuilt context so the
/// worker cannot re-enter admission.
pub(crate) struct OwnedCallerContext {
    state: std::sync::Weak<AppState>,
    authorizer: OwnedRouterAuthorizer,
    api_key_name: Option<String>,
    agent_id: Option<String>,
    grant_subject: Option<GrantSubject>,
    verified_identity: Option<VerifiedIdentity>,
    is_admin: bool,
    input_capabilities: Declared,
    session_id: Option<String>,
}

impl OwnedCallerContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        state: std::sync::Weak<AppState>,
        authorizer: OwnedRouterAuthorizer,
        api_key_name: Option<String>,
        agent_id: Option<String>,
        grant_subject: Option<GrantSubject>,
        verified_identity: Option<VerifiedIdentity>,
        is_admin: bool,
        input_capabilities: Declared,
        session_id: Option<String>,
    ) -> Self {
        Self {
            state,
            authorizer,
            api_key_name,
            agent_id,
            grant_subject,
            verified_identity,
            is_admin,
            input_capabilities,
            session_id,
        }
    }

    pub(crate) fn state(&self) -> &std::sync::Weak<AppState> {
        &self.state
    }

    pub(crate) fn authorizer(&self) -> &OwnedRouterAuthorizer {
        &self.authorizer
    }

    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Rebuild the dispatch funnel. Retry metadata is not forwarded: admission
    /// already reserved the key in `Mode::Task`. Confirmation is honestly
    /// unavailable on the worker. Capabilities are the creating request's.
    pub(crate) fn dispatch_context<'a>(
        &'a self,
        _state: &'a AppState,
        authorizer: &'a RouterAuthorizer<'a>,
    ) -> MetaMcpCallerContext<'a> {
        let authorizer: &'a (dyn ToolAuthorizer + Sync) = authorizer;
        MetaMcpCallerContext {
            authorizer,
            api_key_name: self.api_key_name.as_deref(),
            agent_id: self.agent_id.as_deref(),
            grant_subject: self.grant_subject.clone(),
            verified_identity: self.verified_identity.as_ref(),
            is_admin: self.is_admin,
            input_capabilities: self.input_capabilities,
            confirmation: ConfirmationChannel::Unavailable,
            retry: &NO_RETRY,
            task: None,
        }
    }
}

/// `'static` admission identity. Rebuilt as `Request<'_>` with `Mode::Task` at
/// the one call site that admits.
pub(crate) struct OwnedAdmissionRequest {
    principal: String,
    key: String,
    operation: Value,
    representation: Value,
}

impl OwnedAdmissionRequest {
    pub(crate) fn new(
        principal: String,
        key: String,
        operation: Value,
        representation: Value,
    ) -> Self {
        Self {
            principal,
            key,
            operation,
            representation,
        }
    }

    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }

    pub(crate) fn borrow(&self) -> Request<'_> {
        Request {
            principal: &self.principal,
            key: &self.key,
            operation: &self.operation,
            representation: &self.representation,
            mode: Mode::Task,
        }
    }
}
