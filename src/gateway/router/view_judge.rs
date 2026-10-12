// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the router's answer to "what is this listener shown of this
//! backend?", for the per-listener `list_changed` filter. The multiplexer owns
//! the streams but not the visibility state, so it asks this.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use futures::future::BoxFuture;

use super::{AppState, OwnedRouterAuthorizer};
use crate::gateway::auth::{AuthState, AuthenticatedClient};
use crate::gateway::auth::live::{HeldCredential, current_client};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::streaming::ViewJudge;

/// Judges from the state the router holds; a weak handle, so the multiplexer
/// the state owns does not keep the state alive.
pub(super) struct RouterViewJudge {
    state: Weak<AppState>,
}

impl RouterViewJudge {
    pub(super) fn new(state: &Arc<AppState>) -> Arc<dyn ViewJudge> {
        Arc::new(Self {
            state: Arc::downgrade(state),
        })
    }
}

/// What `client` is shown of `backend` in session `session_id`, as the same
/// scope a POST of that client would be judged under.
fn fingerprint_for(
    state: &AppState,
    client: &AuthenticatedClient,
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
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::new(
            None,
            crate::identity_propagation::CallerProvenance::classify(Some(
                client.principal.as_str(),
            )),
        ),
    };
    state
        .meta_mcp
        .visible_fingerprint(backend, scope, Some(session_id).filter(|s| !s.is_empty()))
}

impl ViewJudge for RouterViewJudge {
    fn fingerprint<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
        backend: &'a str,
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move {
            let state = self.state.upgrade()?;
            let client = current_client(auth, credential).await?;
            Some(fingerprint_for(&state, &client, session_id, backend))
        })
    }

    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
    ) -> BoxFuture<'a, HashMap<String, String>> {
        Box::pin(async move {
            let Some(state) = self.state.upgrade() else {
                return HashMap::new();
            };
            let Some(client) = current_client(auth, credential).await else {
                return HashMap::new();
            };
            let mut names: Vec<String> = state.backends.all().iter().map(|b| b.name.clone()).collect();
            if let Some(capabilities) = state.meta_mcp.get_capabilities() {
                names.push(capabilities.name.clone());
            }
            names
                .into_iter()
                .map(|name| {
                    let fingerprint = fingerprint_for(&state, &client, session_id, &name);
                    (name, fingerprint)
                })
                .collect()
        })
    }
}
