// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195: which credential a per-principal quota is charged to. The
//! authenticated API key first, then a validated agent token, then a client
//! certificate; an unauthenticated client never takes the slot.

use super::*;
use crate::gateway::auth::{AuthenticatedClient, QuotaPrincipal, anonymous_client};
use crate::gateway::authz::ToolAuthorizer;
use crate::gateway::oauth::{AgentIdentity, Scope};
use crate::mtls::CertIdentity;

fn agent(quota: &str) -> AgentIdentity {
    AgentIdentity {
        quota_principal: Some(QuotaPrincipal::configured_bearer(quota)),
        client_id: "agent-1".to_string(),
        agent_name: "runner".to_string(),
        scopes: vec![Scope::parse("tools:*").expect("scope must parse")],
        raw_scopes: vec!["tools:*".to_string()],
    }
}

fn cert(quota: &str) -> CertIdentity {
    CertIdentity {
        quota_principal: Some(QuotaPrincipal::configured_bearer(quota)),
        ..CertIdentity::default()
    }
}

#[tokio::test]
async fn a_quota_is_charged_to_the_strongest_authenticated_credential() {
    let (state, _store) = test_router_app_state_with_agent_auth_enabled().await;
    let key = AuthenticatedClient {
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: "key".to_string(),
        authenticated: true,
        quota_principal: Some(QuotaPrincipal::configured_bearer("key")),
        ..anonymous_client()
    };
    let anonymous = anonymous_client();
    let (agent, cert) = (agent("agent"), cert("cert"));
    let charged = |client, agent, cert| {
        super::authorization::RouterAuthorizer {
            state: &state,
            client,
            oauth_agent_identity: agent,
            cert_identity: cert,
            principal: None,
        }
        .quota_principal()
        .cloned()
    };
    let principal = |name| Some(QuotaPrincipal::configured_bearer(name));

    std::assert_eq!(
        charged(Some(&key), Some(&agent), Some(&cert)),
        principal("key"),
        "an authenticated key is charged first"
    );
    std::assert_eq!(
        charged(Some(&anonymous), Some(&agent), Some(&cert)),
        principal("agent"),
        "an unauthenticated client does not take the slot from a validated agent"
    );
    std::assert_eq!(
        charged(None, None, Some(&cert)),
        principal("cert"),
        "a certificate is charged when nothing stronger authenticated"
    );
    std::assert_eq!(
        charged(Some(&anonymous), None, None),
        None,
        "nobody to charge"
    );
}
