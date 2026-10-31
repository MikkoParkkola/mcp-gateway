// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Branches of the hiding judgment the request rows do not reach on their
//! own: a profile that leaves a backend out, agent auth with no agent on a
//! held catalogue, and a grant that refuses the backend first.

use std::collections::HashMap;

use super::*;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client};
use crate::gateway::meta_mcp::hiding::ListedCatalogue;
use crate::gateway::record_principal::InternalPrincipal;
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
        // An anonymous caller limited by its grant: it presented no secret.
        let client = AuthenticatedClient {
            principal: InternalPrincipal::new(String::new()),
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

/// Profiles `open` (admits all) and `narrow` (leaves `alpha` out), the
/// default being `default`.
fn session_profiles(default: &str) -> ProfileRegistry {
    let profiles = HashMap::from([
        ("open".to_string(), RoutingProfileConfig::default()),
        (
            "narrow".to_string(),
            RoutingProfileConfig {
                deny_backends: Some(vec!["alpha".to_string()]),
                ..Default::default()
            },
        ),
    ]);
    ProfileRegistry::from_config(&profiles, default)
}

/// The per-backend route, the default profile `default`, a session `u1`
/// owns running `session_profile`: the router and the session's id.
async fn direct_under_session(default: &str, session_profile: &str) -> (axum::Router, String) {
    let registry = session_profiles(default);
    let (router, state) = with_mtls_tuned(
        Auth::Keys,
        move |meta| meta.with_profile_registry(registry),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let owner = crate::gateway::session_id::SessionOwner::Credential(
        crate::gateway::auth::principal_of("u1")
            .storage_form()
            .to_owned(),
    );
    let (session, _rx) = state.multiplexer.get_or_create_session_for(None, &owner);
    state
        .meta_mcp
        .session_profiles()
        .set_profile(&session, session_profile);
    (router, session)
}

/// A per-backend call judges hiding under the caller's own session profile,
/// as it routes: a backend the session admits is served though the default
/// profile leaves it out, and one the session leaves out answers as an
/// unregistered name though the default admits it.
#[tokio::test]
async fn a_direct_call_hides_by_its_session_profile() {
    let call = json!({ "name": "alpha_read", "arguments": {} });
    let (router, session) = direct_under_session("narrow", "open").await;
    let headers = [("mcp-session-id", session.as_str())];
    let (status, body) =
        post_cert_headers(&router, "/mcp/alpha", Some("u1"), call.clone(), &headers).await;
    assert!(
        status == 200 && !body.contains("Backend not found"),
        "a backend the session admits was refused: {status} {body}"
    );

    let (router, session) = direct_under_session("open", "narrow").await;
    let headers = [("mcp-session-id", session.as_str())];
    let hidden = post_cert_headers(&router, "/mcp/alpha", Some("u1"), call.clone(), &headers).await;
    let unregistered = post_cert_headers(
        &router,
        &format!("/mcp/{UNREGISTERED}"),
        Some("u1"),
        call,
        &headers,
    )
    .await;
    assert_alike(
        "per-backend route, session profile",
        "alpha",
        &hidden,
        &unregistered,
    );
}

/// The provider `caps` with `cap_open` and `cap_callback`, an admin-only
/// capability (it registers a caller-addressed callback).
async fn caps_with_callback() -> (Arc<crate::capability::CapabilityBackend>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("capability dir");
    let files = [
        ("cap_open", ""),
        ("cap_callback", "  registers_external_callback: true\n"),
    ];
    for (name, extra) in files {
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            super::super::capability_yaml(name, extra),
        )
        .expect("write capability");
    }
    let backend = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("load capabilities");
    assert_eq!(loaded, 2, "both capabilities load");
    (backend, dir)
}

/// A provider the default profile leaves out, for a certificate whose rule
/// admits everything: hidden, with nothing refusing it before the route
/// stage. `tool` on it must answer as on an unregistered name.
async fn assert_profile_hidden_provider_alike(tool: &str) {
    let profiles = HashMap::from([(
        "nocaps".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["caps".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "nocaps")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    let (caps, _dir) = caps_with_callback().await;
    state.meta_mcp.set_capabilities(caps);
    assert!(
        judgment(&state, None, Some(&agent_cert())).hides("caps"),
        "premise: the profile hides the provider"
    );
    let hidden = post_as_agent_cert(&router, "/mcp", invoke("caps", tool)).await;
    let unregistered = post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED, tool)).await;
    assert_alike(tool, "caps", &hidden, &unregistered);
}

/// The profile-withheld capability answer reads the caller's view: a hidden
/// provider's capability is not "defined" for this caller.
#[tokio::test]
async fn a_profile_hidden_providers_capability_answers_as_an_unregistered_name() {
    assert_profile_hidden_provider_alike("cap_open").await;
}

/// The admin-only capability rule reads the caller's view: a hidden
/// provider's admin-only capability is not refused as one.
#[tokio::test]
async fn a_profile_hidden_providers_admin_capability_answers_as_an_unregistered_name() {
    assert_profile_hidden_provider_alike("cap_callback").await;
}

/// A profile's backend deny refuses every tool by name, so it hides a cold
/// backend too: the call answers as an unregistered name, not with the
/// profile's refusal.
#[tokio::test]
async fn a_cold_backend_the_profile_leaves_out_answers_as_an_unregistered_name() {
    let profiles = HashMap::from([(
        "nobeta".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["beta".to_string()]),
            ..Default::default()
        },
    )]);
    let (router, state) = with_mtls_tuned(
        Auth::Off,
        move |meta| meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "nobeta")),
        (&["*"], &["*"]),
        (&[], &[]),
    )
    .await;
    go_cold(&state, "beta");
    assert!(judgment(&state, None, Some(&agent_cert())).hides("beta"));
    let hidden = post_as_agent_cert(&router, "/mcp", invoke("beta", "beta_tool")).await;
    let unregistered = post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED, "beta_tool")).await;
    assert_alike("cold, profile deny", "beta", &hidden, &unregistered);
}
