// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the router's answer to "what is this listener shown of this
//! backend?", for the per-listener `list_changed` filter. The multiplexer owns
//! the streams but not the visibility state, so it asks this.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use super::{AppState, OwnedRouterAuthorizer};
use crate::gateway::auth::{AuthState, AuthenticatedClient};
use crate::gateway::auth::live::{HeldCredential, current_caller};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::streaming::ViewJudge;
use crate::identity_grants::GrantSubject;

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
    /// The adapter identity the stream was opened under, captured once: it is
    /// part of what the stream's caller is shown (MIK-8350 D11).
    subject: Option<GrantSubject>,
}

impl OwnedViewJudge {
    pub(super) fn new(state: &Arc<AppState>, subject: Option<GrantSubject>) -> Arc<dyn ViewJudge> {
        Arc::new(Self {
            state: Arc::clone(state),
            subject,
        })
    }
}

impl ViewJudge for OwnedViewJudge {
    fn fingerprint<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
        backend: &'a str,
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(fingerprint_async(&self.state, self.subject.as_ref(), auth, credential, session_id, backend))
    }

    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
    ) -> BoxFuture<'a, HashMap<String, String>> {
        Box::pin(baseline_async(&self.state, self.subject.as_ref(), auth, credential, session_id))
    }
}

/// What `client` is shown of `backend` in session `session_id`, as the same
/// scope a POST of that client would be judged under.
fn fingerprint_for(
    state: &AppState,
    subject: Option<&GrantSubject>,
    (client, identity): &(
        AuthenticatedClient,
        Option<crate::key_server::oidc::VerifiedIdentity>,
    ),
    session_id: &str,
    backend: &str,
) -> String {
    let owned = OwnedRouterAuthorizer::capture(Some(client), None, None);
    let authorizer = owned.borrow(state);
    let scope = InvokeScope {
        authorizer: &authorizer,
        is_admin: client.admin,
        api_key_name: Some(&client.name),
        agent_id: None,
        grant_subject: subject,
        caller: crate::identity_propagation::CallerProof::new(
            identity.as_ref(),
            crate::identity_propagation::CallerProvenance::classify(Some(
                client.principal.as_str(),
            )),
        ),
    };
    state
        .meta_mcp
        .visible_fingerprint(backend, scope, Some(session_id).filter(|s| !s.is_empty()))
}

/// What `credential` is shown of `backend` now, or `None` when it no longer
/// resolves to a caller.
async fn fingerprint_async(
    state: &AppState,
    subject: Option<&GrantSubject>,
    auth: &AuthState,
    credential: Option<&HeldCredential>,
    session_id: &str,
    backend: &str,
) -> Option<String> {
    let caller = current_caller(auth, credential).await?;
    Some(fingerprint_for(state, subject, &caller, session_id, backend))
}

/// Every backend's fingerprint for `credential`, empty when it does not resolve.
async fn baseline_async(
    state: &AppState,
    subject: Option<&GrantSubject>,
    auth: &AuthState,
    credential: Option<&HeldCredential>,
    session_id: &str,
) -> HashMap<String, String> {
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
            let fingerprint = fingerprint_for(state, subject, &caller, session_id, &name);
            (name, fingerprint)
        })
        .collect()
}

impl ViewJudge for RouterViewJudge<'_> {
    fn fingerprint<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
        backend: &'a str,
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(fingerprint_async(
            self.state, None, auth, credential, session_id, backend,
        ))
    }

    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
    ) -> BoxFuture<'a, HashMap<String, String>> {
        Box::pin(baseline_async(self.state, None, auth, credential, session_id))
    }
}
