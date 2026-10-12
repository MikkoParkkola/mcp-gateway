// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the router's answer to "what is this listener shown of this
//! backend?", for the per-listener `list_changed` filter. The multiplexer owns
//! the streams but not the visibility state, so it asks this.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use super::{AppState, OwnedRouterAuthorizer};
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{HeldCredential, current_caller};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::streaming::{
    DeadReason, Judged, LiveCtx, PendingRefresh, ResolvedCaller, ViewDigest, ViewJudge, ViewSubject,
};

/// Judges from the state the caller holds. Borrowed for the span of one
/// fan-out, so nothing stores a pointer back into the state that owns the
/// multiplexer (a stored one would also stop `Arc::get_mut` on the state).
pub(super) struct RouterViewJudge<'s> {
    state: &'s AppState,
}

impl<'s> RouterViewJudge<'s> {
    pub(super) fn new(state: &'s AppState) -> Self {
        Self { state }
    }
}

/// The same judge for one listen stream, which outlives the request that
/// opened it, so it holds the state.
pub(super) struct OwnedViewJudge {
    state: Arc<AppState>,
}

impl OwnedViewJudge {
    pub(super) fn shared(state: &Arc<AppState>) -> Arc<dyn ViewJudge> {
        Arc::new(Self {
            state: Arc::clone(state),
        })
    }
}

type Caller<'a> = (Option<&'a HeldCredential>, &'a ViewSubject);

impl ViewJudge for OwnedViewJudge {
    fn resolve<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
    ) -> BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(resolve_caller(&self.state, auth, caller))
    }

    fn digest(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
        backend: &str,
    ) -> ViewDigest {
        digest_for(&self.state, subject, caller, session_id, backend)
    }

    fn baseline(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
    ) -> HashMap<String, ViewDigest> {
        baseline_for(&self.state, subject, caller, session_id)
    }
}

impl ViewJudge for RouterViewJudge<'_> {
    fn resolve<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
    ) -> BoxFuture<'a, Judged<ResolvedCaller>> {
        Box::pin(resolve_caller(self.state, auth, caller))
    }

    fn digest(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
        backend: &str,
    ) -> ViewDigest {
        digest_for(self.state, subject, caller, session_id, backend)
    }

    fn baseline(
        &self,
        caller: &ResolvedCaller,
        subject: &ViewSubject,
        session_id: &str,
    ) -> HashMap<String, ViewDigest> {
        baseline_for(self.state, subject, caller, session_id)
    }
}

/// The caller the held credential resolves to, or why it does not: the
/// stream's identity window first, then the credential itself. This is the
/// only step that may reach an identity provider.
async fn resolve_caller(
    state: &AppState,
    auth: &AuthState,
    (credential, subject): Caller<'_>,
) -> Judged<ResolvedCaller> {
    let Some(current) = current_caller(auth, credential).await else {
        return Judged::Dead(DeadReason::Bearer);
    };
    let ctx = LiveCtx {
        agent: current.agent.as_ref(),
        caller_identity: state.meta_mcp.caller_identity(),
        cf_verifier: state.meta_mcp.access_verifier(),
    };
    if let Err(reason) = match subject.verify_held_cf(&ctx).await {
        Ok(()) => subject.live(&ctx),
        dead => dead,
    } {
        return Judged::Dead(reason);
    }
    Judged::Live(ResolvedCaller {
        client: current.client,
        identity: current.identity,
    })
}

/// What the resolved caller is shown of `backend` in session `session_id`,
/// under the same scope a POST of that caller would be judged under: the
/// identities the stream was opened with stand in for the ones a request
/// carries. Cache reads only.
fn digest_for(
    state: &AppState,
    subject: &ViewSubject,
    caller: &ResolvedCaller,
    session_id: &str,
    backend: &str,
) -> ViewDigest {
    let client = &caller.client;
    let oauth = subject.oauth_agent.as_ref();
    let cert = subject.cert.as_ref();
    let owned = OwnedRouterAuthorizer::capture(Some(client), oauth, cert);
    let authorizer = owned.borrow(state);
    // Only the proven half of an agent identity matters, and it comes from the
    // certificate and the verified token alone, never a header.
    let agent = crate::security::extract_agent_identity(
        &axum::http::HeaderMap::new(),
        None,
        cert,
        oauth.map(|a| a.client_id.as_str()),
    );
    // The identity the request carried (the adapter's, a token's) selects a
    // per-user catalogue slot; the credential's own is the fallback.
    let identity = subject
        .verified_identity
        .as_ref()
        .or(caller.identity.as_ref());
    let scope = InvokeScope {
        authorizer: &authorizer,
        is_admin: client.admin,
        api_key_name: Some(&client.name),
        agent_id: agent.proven_agent_id(),
        grant_subject: subject.grant_subject.as_ref(),
        caller: crate::identity_propagation::CallerProof::new(
            identity,
            crate::identity_propagation::CallerProvenance::classify(Some(
                client.principal.as_str(),
            )),
        ),
    };
    state.meta_mcp.visible_digest(
        backend,
        scope,
        (
            Some(session_id).filter(|s| !s.is_empty()),
            subject.code_mode_url,
        ),
    )
}

/// Every backend's view for the resolved caller.
fn baseline_for(
    state: &AppState,
    subject: &ViewSubject,
    caller: &ResolvedCaller,
    session_id: &str,
) -> HashMap<String, ViewDigest> {
    let mut names: Vec<String> = state
        .backends
        .all()
        .iter()
        .map(|b| b.name.clone())
        .collect();
    if let Some(capabilities) = state.meta_mcp.get_capabilities() {
        names.push(capabilities.name.clone());
    }
    names
        .into_iter()
        .map(|name| {
            let digest = digest_for(state, subject, caller, session_id, &name);
            (name, digest)
        })
        .collect()
}

/// The answer for a caller that no longer resolves when its stream opens:
/// what the auth layer says to an invalid credential, with no reason in it.
pub(super) fn dead_attach_refusal() -> axum::response::Response {
    crate::gateway::middleware::bearer_unauthorized_response("Invalid token")
}

/// Whether the URL asked for Code Mode by `?codemode=search_and_execute`: the
/// one test the intake and a stream's attach both use.
pub(super) fn code_mode_requested(query: Option<&str>) -> bool {
    query.is_some_and(|q| {
        q.split('&')
            .any(|pair| pair == "codemode=search_and_execute")
    })
}

impl AppState {
    /// What the caller of `session_id`, under `subject`, is shown now, to be
    /// recorded as told once the answer that shows it is delivered.
    pub(super) async fn begin_refresh(
        &self,
        session_id: &str,
        subject: &ViewSubject,
    ) -> PendingRefresh {
        self.multiplexer
            .read_refresh(session_id, subject, &RouterViewJudge::new(self))
            .await
    }

    /// A `tools/list`: recheck the caller's managed-grant slots (MIK-8356),
    /// then read the view the listing will show, as [`Self::begin_refresh`].
    pub(super) async fn begin_listing(
        &self,
        session_id: &str,
        subject: &ViewSubject,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) -> PendingRefresh {
        self.meta_mcp.revalidate_caller_slots(caller).await;
        self.begin_refresh(session_id, subject).await
    }

    /// A GET stream opened for `session_id` under `subject`: the view it
    /// judges with, baselined so the first change after attach is judged
    /// against what it saw.
    pub(super) async fn attach_view(
        self: &Arc<Self>,
        session_id: &str,
        subject: ViewSubject,
    ) -> Result<Option<crate::gateway::streaming::StreamView>, DeadReason> {
        self.multiplexer
            .attach_view(session_id, subject, OwnedViewJudge::shared(self))
            .await
    }

    /// [`Self::attach_view`] for a GET: the subject is read from the request
    /// the way the intake reads it for a POST.
    pub(super) async fn attach_get_view(
        self: &Arc<Self>,
        session_id: &str,
        (grant_subject, (headers, extensions), query): (
            Option<crate::identity_grants::GrantSubject>,
            (&axum::http::HeaderMap, &axum::http::Extensions),
            Option<&str>,
        ),
    ) -> Result<Option<crate::gateway::streaming::StreamView>, DeadReason> {
        let verified = extensions.get::<crate::key_server::oidc::VerifiedIdentity>();
        let (cf_assertion, proxy_peer) = super::identity::identity_source_facts(
            self.meta_mcp.caller_identity(),
            (headers, extensions),
            verified,
        );
        let subject = ViewSubject {
            grant_subject,
            oauth_agent: extensions
                .get::<crate::gateway::oauth::AgentIdentity>()
                .cloned(),
            cert: extensions.get::<crate::mtls::CertIdentity>().cloned(),
            code_mode_url: code_mode_requested(query),
            verified_identity: extensions
                .get::<crate::key_server::oidc::VerifiedIdentity>()
                .cloned(),
            adapter: extensions
                .get::<crate::gateway::openwebui_adapter::AdapterAssertion>()
                .copied(),
            cert_not_after: extensions
                .get::<crate::mtls::identity::CertNotAfter>()
                .map(|not_after| not_after.0),
            cf_assertion,
            proxy_peer,
        };
        self.attach_view(session_id, subject).await
    }

    /// `listener` judged by the view of the caller that opened it, under the
    /// subject captured now (MIK-8350 D11).
    pub(super) fn judged_listener(
        self: &Arc<Self>,
        mut listener: crate::gateway::subscription_registry::Listener,
        subject: ViewSubject,
    ) -> crate::gateway::subscription_registry::Listener {
        listener.set_views(OwnedViewJudge::shared(self), subject);
        listener
    }

    /// A switched profile changes what its caller is shown, and the switch's
    /// own answer is the notice: read the new view, to be recorded once the
    /// answer is delivered. Hands `response` back with it.
    pub(super) async fn after_call(
        &self,
        (session_id, subject): (&str, &ViewSubject),
        params: Option<&serde_json::Value>,
        response: crate::protocol::JsonRpcResponse,
    ) -> (crate::protocol::JsonRpcResponse, PendingRefresh) {
        let switched = params
            .and_then(|p| p.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some("gateway_set_profile");
        if switched && response.error.is_none() {
            let pending = self.begin_refresh(session_id, subject).await;
            return (response, pending);
        }
        (response, PendingRefresh::default())
    }
}
