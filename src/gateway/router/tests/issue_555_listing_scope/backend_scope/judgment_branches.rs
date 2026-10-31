// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Branches of the hiding judgment the request rows do not reach on their
//! own: a profile that leaves a backend out, agent auth with no agent on a
//! held catalogue, and a grant that refuses the backend first.

use std::collections::HashMap;

use super::*;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client};
use crate::gateway::meta_mcp::hiding::ListedCatalogue;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::router::caller_hiding::RouterHiding;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

/// A session profile that leaves `alpha` out hides it from a caller whose
/// policy admits its tools, and the listing leaves it out too.
#[tokio::test]
async fn a_backend_the_profile_leaves_out_is_hidden() {
    let profiles = HashMap::from([(
        "narrow".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["alpha".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "narrow")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let hiding = judgment(&state, None, Some(&agent_cert()));
    assert!(hiding.hides("alpha"), "the profile's left-out backend");
    assert!(!hiding.hides("beta"), "a backend the profile keeps");
    let (_, body) = post_as_agent_cert(
        &router,
        "/mcp",
        json!({ "name": "gateway_list_servers", "arguments": {} }),
    )
    .await;
    let listed = server_names(&serde_json::from_str(&body).expect("json"));
    assert!(
        !listed.iter().any(|n| n == "alpha") && listed.iter().any(|n| n == "beta"),
        "listed and not hidden disagree: {listed:?}"
    );
}

/// Agent auth with no validated agent admits no backend, so a held
/// catalogue's backend is hidden; an unregistered name is a miss already.
#[tokio::test]
async fn agent_auth_with_no_agent_hides_a_held_backend() {
    let f = with_agent_auth(Arc::new(crate::gateway::oauth::AgentRegistry::new())).await;
    assert!(
        matches!(
            f.state.meta_mcp.listed_catalogue("alpha"),
            ListedCatalogue::Tools { .. }
        ),
        "premise: alpha's catalogue is held"
    );
    let hiding = judgment(&f.state, None, None);
    assert!(hiding.hides("alpha"), "a held backend with no agent");
    assert!(!hiding.hides("no-such-backend"), "an unregistered name");
}

/// A grant that refuses the backend answers first, so the judgment does not
/// hide it: the grant's own refusal stands. With a grant on it, the same
/// certificate's rule hides it.
#[tokio::test]
async fn a_grant_refusal_is_the_grants_answer_not_a_hiding() {
    let (_, state) = with_mtls_state((&["*"], &["*"]), (&["beta"], &[])).await;
    let hides_beta = |backends: &str| {
        let client = AuthenticatedClient {
            backends: vec![backends.to_string()],
            ..anonymous_client()
        };
        RouterHiding::caller(
            Arc::clone(&state),
            OwnedRouterAuthorizer::capture(Some(&client), None, Some(&agent_cert())),
            None,
            None,
        )
        .hides("beta")
    };
    assert!(!hides_beta("alpha"), "a grant without beta");
    assert!(hides_beta("*"), "control: a grant on beta");
}
