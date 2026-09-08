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
    /// The owner the durable task was admitted under, owned because the rebuilt
    /// context borrows it and a `String` computed at dispatch could not be.
    /// Taken as a parameter rather than derived: with authentication off there
    /// is no verified identity to derive it from, and re-deriving it here from
    /// a second source is how the worker's caller and the durable record
    /// disagree about who owns the task.
    credential_principal: String,
    is_admin: bool,
    input_capabilities: Declared,
    session_id: Option<String>,
    /// Classifier revision captured at admission. Borrowed into the rebuilt
    /// caller at dispatch. Not persisted on the durable task record.
    protocol_revision: Option<String>,
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
        credential_principal: String,
        is_admin: bool,
        input_capabilities: Declared,
        session_id: Option<String>,
        protocol_revision: Option<String>,
    ) -> Self {
        // The very string the admission request is keyed on, passed in from the
        // one construction site: it is the durable task's owner, not a display
        // name, and with authentication off no identity renders it.
        Self {
            state,
            authorizer,
            api_key_name,
            agent_id,
            grant_subject,
            verified_identity,
            credential_principal,
            is_admin,
            input_capabilities,
            session_id,
            protocol_revision,
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
            // A task is only ever built for a modern request — the intent
            // builder returns `None` for every other era — so this is a fact
            // about the request that created the task, not a default.
            is_modern: true,
            protocol_revision: self.protocol_revision.as_deref(),
            // The owner the durable record was admitted under. Read as the
            // admission fallback for an identity-less caller, which a task has
            // whenever authentication is off; carried so the worker's caller
            // cannot be a weaker principal than the request's.
            credential_principal: Some(self.credential_principal.as_str()),
            // No second lease. The worker's execution is admitted durably in
            // `Mode::Task`, and a `Mode::Sync` lease on the same principal and
            // key would refuse the very task it was taken for; there is also no
            // request future here to own one.
            execution: None,
            // Signing admission belongs to the request that prepared it: the
            // nonce is checked and registered once, before the handoff, and a
            // cloned prepared context here would tell the invoke funnel to skip
            // its policy recheck (it would consume no second nonce — the nonce
            // is already spent — but the skip is the harm). `None` keeps
            // `check_invocation_policy` — current authorization, tool name,
            // attestation and active profile — running on this dispatch, which
            // is what the worker needs, and it consumes no nonce.
            signing: None,
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
            era: crate::protocol::meta::Era::Modern,
            channel: &crate::gateway::input_bridge::NoClientChannel,
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
