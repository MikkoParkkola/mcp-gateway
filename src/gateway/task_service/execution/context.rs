// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Owned caller and admission twins. Nothing here is borrowed from the request future.

use serde_json::Value;

use crate::gateway::authz::ToolAuthorizer;
use crate::gateway::destructive_confirmation::ConfirmationChannel;
use crate::gateway::meta_mcp::dispatch_log::DispatchLog;
use crate::gateway::meta_mcp::{Authentication, MetaMcpCallerContext};
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::host::{HostAuthorizer, LiveHost, TaskHost};
use crate::idempotency::admission::{Mode, Request};
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;

/// Snapshot of the creating request's identity, rebuilt as a borrowed caller
/// context at dispatch. `task` is always `None` on the rebuilt context so the
/// worker cannot re-enter admission.
pub(crate) struct OwnedCallerContext {
    /// The transport the task runs for: the HTTP router's state or the stdio
    /// gateway's host (design D6 rev 5 item 1).
    host: TaskHost,
    authorizer: OwnedRouterAuthorizer,
    api_key_name: Option<String>,
    agent_id: Option<crate::security::OwnedProvenAgentId>,
    /// The creating request's declared agent label, so the task's calls audit
    /// it as the request's own would (#2259).
    agent_declared: Option<String>,
    grant_subject: Option<GrantSubject>,
    verified_identity: Option<VerifiedIdentity>,
    /// The owner the durable task was admitted under, owned because the rebuilt
    /// context borrows it and a `String` computed at dispatch could not be.
    /// Taken as a parameter rather than derived: with authentication off there
    /// is no verified identity to derive it from, and re-deriving it here from
    /// a second source is how the worker's caller and the durable record
    /// disagree about who owns the task.
    credential_principal: String,
    /// Whether the creating request authenticated. Carried, never inferred:
    /// with authentication off `credential_principal` is a non-empty constant.
    authentication: Authentication,
    /// How the creating request presented its credential (D1-c audit `who`).
    credential_kind: crate::security::audit::CredentialKind,
    is_admin: bool,
    input_capabilities: Declared,
    session_id: Option<String>,
    /// The creating or resuming request's caller key, which the A/B arm and the
    /// hints key on (G4). Derived from that live request, never from a record.
    caller_key: Option<String>,
    /// The creating or resuming request's meta-tool surface (MIK-7974).
    surface_request: crate::gateway::recovery::SurfaceRequest,
    /// Classifier revision captured at admission. Borrowed into the rebuilt
    /// caller at dispatch. Not persisted on the durable task record.
    protocol_revision: Option<String>,
    /// The creating request's `_meta` attestation token and nothing else of
    /// its retry fields: admission already reserved the key, and the retry
    /// pair named a question this worker never asked. Owned here so the
    /// rebuilt caller can borrow it; a surfaced tool's funnel envelope reads
    /// it at dispatch, where it is re-validated (MIK-7570.ATTEST.1 part 3).
    /// In memory only, like the rest of this struct.
    retry: RetryFields,
    /// The backend calls this context's dispatches completed (#2450): a plan's
    /// targets, persisted by the worker before it settles or parks the task.
    dispatch_log: std::sync::Arc<DispatchLog>,
}

impl OwnedCallerContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        host: TaskHost,
        authorizer: OwnedRouterAuthorizer,
        api_key_name: Option<String>,
        agent_id: Option<crate::security::OwnedProvenAgentId>,
        agent_declared: Option<String>,
        grant_subject: Option<GrantSubject>,
        verified_identity: Option<VerifiedIdentity>,
        credential_principal: String,
        authentication: Authentication,
        credential_kind: crate::security::audit::CredentialKind,
        is_admin: bool,
        input_capabilities: Declared,
        session_id: Option<String>,
        protocol_revision: Option<String>,
        attestation: Option<String>,
    ) -> Self {
        // The very string the admission request is keyed on, passed in from the
        // one construction site: it is the durable task's owner, not a display
        // name, and with authentication off no identity renders it.
        Self {
            host,
            authorizer,
            api_key_name,
            agent_id,
            agent_declared,
            grant_subject,
            verified_identity,
            credential_principal,
            authentication,
            credential_kind,
            is_admin,
            input_capabilities,
            session_id,
            caller_key: None,
            surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
            protocol_revision,
            retry: RetryFields {
                attestation,
                ..RetryFields::default()
            },
            dispatch_log: std::sync::Arc::default(),
        }
    }

    /// The request's caller key; `None` (stdio, no identity) falls back to the
    /// session id the context carries.
    #[must_use]
    pub(crate) fn with_caller_key(mut self, caller_key: Option<String>) -> Self {
        self.caller_key = caller_key.filter(|key| !key.is_empty());
        self
    }

    /// The request's meta-tool surface, so the task's hints follow it.
    ///
    /// Intended: a retry under the same idempotency key gets the task its key
    /// already created, with hints for the creating request's surface, as every
    /// idempotent replay returns the stored answer unchanged (MIK-7974).
    pub(crate) fn with_surface_request(
        mut self,
        surface_request: crate::gateway::recovery::SurfaceRequest,
    ) -> Self {
        self.surface_request = surface_request;
        self
    }

    pub(crate) fn dispatch_log(&self) -> &std::sync::Arc<DispatchLog> {
        &self.dispatch_log
    }

    pub(crate) fn host(&self) -> &TaskHost {
        &self.host
    }

    pub(crate) fn authorizer(&self) -> &OwnedRouterAuthorizer {
        &self.authorizer
    }

    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Hold the caller key for the length of one backend call, so an idle
    /// sweep cannot reclaim it under a call that outlasts `IDLE_TTL`
    /// (MIK-7828.FIX.2). Only an HTTP host tracks caller keys.
    pub(crate) fn hold_caller_key(
        &self,
        host: &LiveHost,
    ) -> Option<crate::gateway::session_lifecycle::KeyHold> {
        let LiveHost::Http(state) = host else {
            return None;
        };
        let key = self.caller_key.as_deref()?;
        Some(state.session_lifecycle.as_ref()?.hold(key))
    }

    /// Test-only: the owner the worker's caller carries as its credential
    /// principal (MIK-8293 S3b1's premise row).
    #[cfg(test)]
    pub(crate) fn credential_principal_for_test(&self) -> &str {
        &self.credential_principal
    }

    /// Rebuild the dispatch funnel.
    ///
    /// - Retry metadata is not forwarded: admission already reserved the key
    ///   in `Mode::Task`. The one exception is the creating request's
    ///   attestation token, which the funnel re-checks at dispatch.
    /// - Confirmation is unavailable on the worker.
    /// - Capabilities are the creating request's.
    pub(crate) fn dispatch_context<'a>(
        &'a self,
        host: &LiveHost,
        authorizer: &'a HostAuthorizer<'a>,
    ) -> MetaMcpCallerContext<'a> {
        self.dispatch_context_retrying(host, authorizer, &self.retry)
    }

    /// The retry fields of one input-round continuation: the gateway-sealed
    /// `requestState` and the accumulated answers, beside this context's own
    /// attestation token. Redeemed by the funnel as a client retry would be.
    pub(crate) fn continuation(
        &self,
        request_state: Option<String>,
        input_responses: Option<Value>,
    ) -> RetryFields {
        RetryFields {
            input_responses,
            request_state,
            ..self.retry.clone()
        }
    }

    /// [`Self::dispatch_context`] carrying `retry` instead of this context's
    /// own fields: the continuation of an input round.
    pub(crate) fn dispatch_context_retrying<'a>(
        &'a self,
        host: &LiveHost,
        authorizer: &'a HostAuthorizer<'a>,
        retry: &'a RetryFields,
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
            authentication: self.authentication,
            credential_kind: self.credential_kind,
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
            agent_id: self
                .agent_id
                .as_ref()
                .map(crate::security::OwnedProvenAgentId::as_proven),
            agent_declared: self
                .agent_declared
                .as_deref()
                .map(crate::security::DeclaredAgentLabel::new),
            grant_subject: self.grant_subject.clone(),
            // The stdio host's mark, so the reserved owner, the cache
            // principal and `LocalTransport` provenance survive the rebuild
            // (D6 rev 5 item 2). An HTTP host has none.
            stdio_nonce: host.stdio_nonce(),
            caller_key: self.caller_key.as_deref(),
            verified_identity: self.verified_identity.as_ref(),
            is_admin: self.is_admin,
            surface_request: self.surface_request,
            input_capabilities: self.input_capabilities,
            confirmation: ConfirmationChannel::Unavailable,
            retry,
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
