// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the router's answer to "what is this listener shown of this
//! backend?", for the per-listener `list_changed` filter. The multiplexer owns
//! the streams but not the visibility state, so it asks this.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use super::{AppState, OwnedRouterAuthorizer};
use crate::gateway::auth::live::{HeldCredential, current_caller};
use crate::gateway::auth::{AuthState, AuthenticatedClient};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::streaming::{ViewDigest, ViewJudge, ViewSubject};

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

type Caller<'a> = (Option<&'a HeldCredential>, Option<&'a ViewSubject>);

impl ViewJudge for OwnedViewJudge {
    fn digest<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
        session_id: &'a str,
        backend: &'a str,
    ) -> BoxFuture<'a, Option<ViewDigest>> {
        Box::pin(digest_async(&self.state, auth, caller, session_id, backend))
    }

    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
        session_id: &'a str,
    ) -> BoxFuture<'a, HashMap<String, ViewDigest>> {
        Box::pin(baseline_async(&self.state, auth, caller, session_id))
    }
}

impl ViewJudge for RouterViewJudge<'_> {
    fn digest<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
        session_id: &'a str,
        backend: &'a str,
    ) -> BoxFuture<'a, Option<ViewDigest>> {
        Box::pin(digest_async(self.state, auth, caller, session_id, backend))
    }

    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: Caller<'a>,
        session_id: &'a str,
    ) -> BoxFuture<'a, HashMap<String, ViewDigest>> {
        Box::pin(baseline_async(self.state, auth, caller, session_id))
    }
}

/// What `client` is shown of `backend` in session `session_id`, under the same
/// scope a POST of that client would be judged under: the identities the
/// stream was opened with stand in for the ones a request carries.
fn digest_for(
    state: &AppState,
    subject: Option<&ViewSubject>,
    (client, identity): &(
        AuthenticatedClient,
        Option<crate::key_server::oidc::VerifiedIdentity>,
    ),
    session_id: &str,
    backend: &str,
) -> ViewDigest {
    let oauth = subject.and_then(|s| s.oauth_agent.as_ref());
    let cert = subject.and_then(|s| s.cert.as_ref());
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
    let scope = InvokeScope {
        authorizer: &authorizer,
        is_admin: client.admin,
        api_key_name: Some(&client.name),
        agent_id: agent.proven_agent_id(),
        grant_subject: subject.and_then(|s| s.grant_subject.as_ref()),
        caller: crate::identity_propagation::CallerProof::new(
            identity.as_ref(),
            crate::identity_propagation::CallerProvenance::classify(Some(
                client.principal.as_str(),
            )),
        ),
    };
    state
        .meta_mcp
        .visible_digest(backend, scope, Some(session_id).filter(|s| !s.is_empty()))
}

/// What the held credential is shown of `backend` now, or `None` when it no
/// longer resolves to a caller.
async fn digest_async(
    state: &AppState,
    auth: &AuthState,
    (credential, subject): Caller<'_>,
    session_id: &str,
    backend: &str,
) -> Option<ViewDigest> {
    let caller = current_caller(auth, credential).await?;
    Some(digest_for(state, subject, &caller, session_id, backend))
}

/// Every backend's view for the held credential, empty when it does not resolve.
async fn baseline_async(
    state: &AppState,
    auth: &AuthState,
    (credential, subject): Caller<'_>,
    session_id: &str,
) -> HashMap<String, ViewDigest> {
    let Some(caller) = current_caller(auth, credential).await else {
        return HashMap::new();
    };
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
            let digest = digest_for(state, subject, &caller, session_id, &name);
            (name, digest)
        })
        .collect()
}

impl AppState {
    /// The caller of `session_id` has just been shown its current view (a
    /// `tools/list` answer, a profile switch): record it as told.
    pub(super) async fn refresh_told(&self, session_id: &str) {
        self.multiplexer
            .refresh_told(session_id, &RouterViewJudge::new(self))
            .await;
    }

    /// A GET stream opened for `session_id`: bind the identities it was opened
    /// under and record what its caller is shown now, so the first change after
    /// attach is judged against it.
    pub(super) async fn attach_view(
        &self,
        session_id: &str,
        grant_subject: Option<crate::identity_grants::GrantSubject>,
        extensions: &axum::http::Extensions,
    ) {
        self.multiplexer.bind_view_subject(
            session_id,
            ViewSubject {
                grant_subject,
                oauth_agent: extensions
                    .get::<crate::gateway::oauth::AgentIdentity>()
                    .cloned(),
                cert: extensions.get::<crate::mtls::CertIdentity>().cloned(),
            },
        );
        self.multiplexer
            .take_baseline(session_id, &RouterViewJudge::new(self))
            .await;
    }

    /// `listener` judged by the view of the caller that opened it, under the
    /// identities captured now (MIK-8350 D11).
    pub(super) fn judged_listener(
        self: &Arc<Self>,
        mut listener: crate::gateway::subscription_registry::Listener,
        grant_subject: Option<crate::identity_grants::GrantSubject>,
        (oauth_agent, cert): (
            Option<crate::gateway::oauth::AgentIdentity>,
            Option<crate::mtls::CertIdentity>,
        ),
    ) -> crate::gateway::subscription_registry::Listener {
        listener.set_views(
            OwnedViewJudge::shared(self),
            ViewSubject {
                grant_subject,
                oauth_agent,
                cert,
            },
        );
        listener
    }

    /// A switched profile changes what its caller is shown, and the switch's
    /// own answer is the notice: record the new view as told. Hands `response`
    /// back.
    pub(super) async fn after_call(
        &self,
        session_id: &str,
        params: Option<&serde_json::Value>,
        response: crate::protocol::JsonRpcResponse,
    ) -> crate::protocol::JsonRpcResponse {
        let switched = params
            .and_then(|p| p.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some("gateway_set_profile");
        if switched && response.error.is_none() {
            self.refresh_told(session_id).await;
        }
        response
    }
}
