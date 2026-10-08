// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The authenticated caller context a `tools/call` dispatch carries.

use super::{
    Authentication, Declared, GrantSubject, InvokeScope, LOCAL_OPERATOR_PREFIX,
    LOCAL_OPERATOR_PRINCIPAL, admission, signing, support,
};

/// Authenticated caller context for a `tools/call` dispatch.
///
/// Deliberately has **no `Default`**: the authorizer is mandatory, and a derived default would let
/// a construction site acquire one by omission. Every site names the authorizer it means, which in
/// tests makes a permissive one visible in the test source rather than hidden in a struct default.
pub struct MetaMcpCallerContext<'a> {
    /// Explicit request era, classified by the transport from reserved metadata.
    pub is_modern: bool,
    /// Validated protocol revision this request is served under.
    ///
    /// Classifier output, never the duplicate-header sentinel. `None` skips
    /// outer response-cache get/set and, on an attached executor, inner cache.
    /// Distinct from `is_modern` and from any peer `era` field on this struct.
    pub protocol_revision: Option<&'a str>,
    /// Stable validated credential principal; display names are never authority.
    pub credential_principal: Option<&'a str>,
    /// Whether a credential was presented and validated. Explicit, never
    /// inferred from `credential_principal` (see [`Authentication`]).
    pub(crate) authentication: Authentication,
    /// How the credential was presented, for the audit record's `who`
    /// (D1-c). No `Default`: every construction site names it.
    pub(crate) credential_kind: crate::security::audit::CredentialKind,
    /// Outer execution owner; an inner step can mark dispatch but cannot settle it.
    pub(crate) execution: Option<&'a admission::SyncLease>,
    /// Private external origin and completed signing admission, never backend metadata.
    pub(crate) signing: Option<&'a signing::SigningInvocationContext>,
    /// Decides whether this caller may invoke a given backend tool.
    ///
    /// Borrowed, never stored: `AppState` owns `meta_mcp`, so holding an
    /// `Arc<AppState>` inside `MetaMcp` would be a cycle that never frees.
    pub authorizer: &'a (dyn crate::gateway::authz::ToolAuthorizer + Sync),
    /// Static or temporary API-key name, used for accounting and fallback grants.
    pub api_key_name: Option<&'a str>,
    /// The calling agent's PROVEN principal, for access decisions.
    ///
    /// A distinct type, not an `Option<&str>` beside a declared one: two
    /// interchangeable string fields would leave the wrong value representable
    /// at every call site. `ProvenAgentId` has no public constructor, so a
    /// caller-supplied label cannot reach an authorization input without a
    /// compile error.
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// The calling agent's DECLARED tag, for audit and cost attribution only.
    ///
    /// Recorded alongside the proven principal and never instead of it: a
    /// record that collapses them cannot distinguish "agent-a proved it" from
    /// "someone said agent-a", which is the signal funded change 4 exists to
    /// create.
    pub agent_declared: Option<crate::security::DeclaredAgentLabel<'a>>,
    /// Verified caller subject for identity-grant evaluation.
    pub grant_subject: Option<GrantSubject>,
    /// Full verified end-user identity, when present. Carried (not collapsed to
    /// `grant_subject`) so the backend-invoke boundary can propagate the real
    /// user to a backend that requires it (MIK-6704 / ADR-007 R2).
    pub verified_identity: Option<&'a crate::key_server::oidc::VerifiedIdentity>,
    /// Set by the two stdio context builders only (no constructor outside
    /// `gateway::server`); binds continuations to the stdio client.
    pub(crate) stdio_nonce: Option<&'a crate::gateway::server::StdioNonce>,
    /// The caller's `router::identity::caller_key`, set by HTTP only; see `experiment_key`.
    pub(crate) caller_key: Option<&'a str>,
    /// Whether the caller holds admin: meta-tools with admin-only PARAMETERS cannot be gated by
    /// the tool-name allow-list in `router::authorization`, which knows only whole tools.
    pub is_admin: bool,
    /// The meta-tool surface this request asked for; recovery hints follow it (MIK-7974).
    pub(crate) surface_request: crate::gateway::recovery::SurfaceRequest,
    /// What this caller declared on **this** request.
    ///
    /// A parsed set rather than a single "may be asked for input" bit, because MRTR.9 refuses per
    /// requested method and MRTR.9a per requested *mode*: a client that declared `elicitation` and
    /// not `sampling` may be sent one and not the other, and one that declared elicitation in form
    /// mode alone may not be sent a url request. On stdio a modern call reads its own `_meta` and a
    /// legacy call the handshake; absent means absent, and a caller that declared nothing is never
    /// sent a continuation.
    pub input_capabilities: Declared,
    /// How this caller can be asked to confirm a destructive action.
    ///
    /// A transport that has no way to reach an operator carries
    /// [`ConfirmationChannel::Unavailable`] and its destructive calls are
    /// refused. Deciding that here, rather than at one edge, is what makes the
    /// gate apply to every transport that dispatches.
    pub confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel<'a>,
    /// The multi-round-trip fields this call carried, already parsed.
    ///
    /// Borrowed inbound shape, still attacker-controlled: `request_state` here
    /// is whatever the client sent back, and only becomes trustworthy once the
    /// gateway opens it as one of its own sealed envelopes. Nothing downstream
    /// may forward this field to a backend verbatim.
    pub retry: &'a crate::protocol::mrtr::RetryFields,
    /// Background-task intent, taken after the destructive confirmation gate.
    /// `None` on every synchronous call and on the worker's rebuilt context.
    pub task: Option<crate::gateway::task_service::TaskIntent>,
    /// Which protocol era this caller declared on **this** request.
    ///
    /// Carried rather than re-derived: both production sites already hold the
    /// `RequestShape` classification that `initialize` advertises against, and
    /// a second era predicate computed downstream is exactly the drift
    /// [`crate::protocol::meta::classify_request`] exists to prevent.
    ///
    /// No `Default`, for the same reason the authorizer has none — a defaulted
    /// era is a site that silently claims an era it never saw.
    ///
    /// Read by the input bridge, which serves `Legacy` callers only.
    pub era: crate::protocol::meta::Era,
    /// How this caller can be sent a request of the gateway's own — a bridged
    /// `sampling/createMessage` or `elicitation/create`.
    ///
    /// Distinct from `confirmation`, which answers a narrower question and
    /// would become a general client-request pipe if reused for this. A
    /// transport with nowhere to send carries
    /// [`crate::gateway::input_bridge::NoClientChannel`], so "cannot ask" is a
    /// channel that refuses rather than an absent one every read site must
    /// remember to check.
    pub channel: &'a dyn crate::gateway::input_bridge::ClientChannel,
}

impl<'a> MetaMcpCallerContext<'a> {
    /// The fields the chokepoint reads, as the view discovery is judged by.
    #[must_use]
    pub fn scope(&self) -> InvokeScope<'_> {
        InvokeScope {
            authorizer: self.authorizer,
            is_admin: self.is_admin,
            api_key_name: self.api_key_name,
            agent_id: self.agent_id,
            grant_subject: self.grant_subject.as_ref(),
        }
    }

    /// The principal text that keys this caller's retained results (MIK-7272.OWNER.3).
    ///
    /// The stdio mark names the local operator ([`LOCAL_OPERATOR_PRINCIPAL`]); other
    /// text can never spell it, since text with the reserved prefix is dropped.
    /// With no credential, a proven agent or certificate subject (MIK-7688).
    pub(crate) fn owner_principal(&self) -> Option<&'a str> {
        if self.stdio_nonce.is_some() {
            return Some(LOCAL_OPERATOR_PRINCIPAL);
        }
        self.credential_principal
            .filter(|text| !text.is_empty() && !text.starts_with(LOCAL_OPERATOR_PREFIX))
            .or_else(|| support::proven_subject_owner(self))
    }

    /// How this caller was established. The stdio transport's mark decides
    /// `LocalTransport`; principal text alone never does (MIK-7272.OWNER.3).
    pub(crate) fn provenance(&self) -> crate::identity_propagation::CallerProvenance {
        match self.stdio_nonce {
            Some(mark) => crate::identity_propagation::CallerProvenance::local_transport(mark),
            None => {
                crate::identity_propagation::CallerProvenance::classify(self.credential_principal)
            }
        }
    }

    /// The same caller, presenting different multi-round-trip fields.
    ///
    /// A chain runs its steps as one caller, and only the step that was
    /// stopped may redeem the answers. Rebuilding the context per step is what
    /// keeps that structural: `task` is not carried, because a chain step
    /// never begins a background task of its own — the intent was already
    /// taken at the dispatch gate above.
    pub(crate) fn with_retry<'b>(
        &self,
        retry: &'b crate::protocol::mrtr::RetryFields,
    ) -> MetaMcpCallerContext<'b>
    where
        'a: 'b,
    {
        MetaMcpCallerContext {
            is_modern: self.is_modern,
            protocol_revision: self.protocol_revision,
            credential_principal: self.credential_principal,
            authentication: self.authentication,
            credential_kind: self.credential_kind,
            execution: self.execution,
            signing: self.signing,
            authorizer: self.authorizer,
            api_key_name: self.api_key_name,
            agent_id: self.agent_id,
            agent_declared: self.agent_declared,
            grant_subject: self.grant_subject.clone(),
            verified_identity: self.verified_identity,
            stdio_nonce: self.stdio_nonce,
            caller_key: self.caller_key,
            is_admin: self.is_admin,
            surface_request: self.surface_request,
            input_capabilities: self.input_capabilities,
            confirmation: self.confirmation.clone(),
            retry,
            task: None,
            era: self.era,
            channel: self.channel,
        }
    }
}
