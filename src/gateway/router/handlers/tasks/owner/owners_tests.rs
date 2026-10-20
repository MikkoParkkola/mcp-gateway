// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pins `route_owners` across identity combinations for MIK-8498.TASKS.1.

use super::{AUTH_DISABLED_TASK_OWNER, agent_task_owner};
use crate::gateway::auth::AuthenticatedClient;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;

const SUBJECT_KEY: &str = "subject:5:proxy:5:alice";

fn agent(client_id: &str) -> crate::gateway::oauth::AgentIdentity {
    crate::gateway::oauth::AgentIdentity {
        client_id: client_id.to_string(),
        agent_name: client_id.to_string(),
        scopes: Vec::new(),
        raw_scopes: Vec::new(),
        quota_principal: None,
    }
}

async fn state(
    enabled: bool,
) -> (
    std::sync::Arc<crate::gateway::router::AppState>,
    tempfile::TempDir,
) {
    let auth = crate::config::AuthConfig {
        enabled,
        ..crate::config::AuthConfig::default()
    };
    crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await
}

fn key_holder(principal: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: principal.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: principal.to_string(),
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

fn proven_subject() -> GrantSubject {
    GrantSubject {
        authority: "proxy".to_string(),
        subject: "alice".to_string(),
        label: None,
    }
}

fn verified() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "user-1".to_string(),
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example".to_string(),
    }
}

fn check(label: &str, got: (String, String, String), want: (&str, &str, &str)) {
    assert_eq!(got.0, want.0, "{label}: task owner");
    assert_eq!(got.1, want.1, "{label}: events owner");
    assert_eq!(got.2, want.2, "{label}: admission owner");
}

#[tokio::test]
async fn route_owners_across_identity_combinations() {
    let (off, _off_store) = state(false).await;
    let (on, _on_store) = state(true).await;
    let agent_fixture = agent("agent-a");
    let subject_fixture = proven_subject();
    let client_fixture = key_holder("alpha");
    let verified_fixture = verified();
    let disabled = AUTH_DISABLED_TASK_OWNER;
    let agent_owner = agent_task_owner("agent-a");
    let credential_owner = format!(
        "{}{}",
        crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,
        "alpha"
    );
    let actor = VerifiedIdentity::stable_actor_id(&verified_fixture);

    check(
        "auth off, nothing",
        super::route_owners(&off, None, None, (None, None, None)),
        (disabled, disabled, ""),
    );
    check(
        "auth off, agent only",
        super::route_owners(&off, None, Some(&agent_fixture), (None, None, None)),
        (&agent_owner, disabled, &agent_owner),
    );
    check(
        "auth off, proven subject",
        super::route_owners(&off, None, None, (Some(&subject_fixture), None, None)),
        (SUBJECT_KEY, SUBJECT_KEY, SUBJECT_KEY),
    );
    // The task arm passes the agent, so only the events arm takes the
    // `(None, Some(subject))` branch.
    check(
        "auth off, agent and proven subject",
        super::route_owners(
            &off,
            None,
            Some(&agent_fixture),
            (Some(&subject_fixture), None, None),
        ),
        (&agent_owner, SUBJECT_KEY, &agent_owner),
    );
    check(
        "auth off, verified identity",
        super::route_owners(&off, Some(&verified_fixture), None, (None, None, None)),
        (&actor, &actor, &actor),
    );
    check(
        "auth on, nothing",
        super::route_owners(&on, None, None, (None, None, None)),
        ("", "", ""),
    );
    check(
        "auth on, agent only",
        super::route_owners(&on, None, Some(&agent_fixture), (None, None, None)),
        (&agent_owner, "", &agent_owner),
    );
    check(
        "auth on, authenticated API-key client",
        super::route_owners(&on, None, None, (None, None, Some(&client_fixture))),
        (&credential_owner, &credential_owner, &credential_owner),
    );
    check(
        "auth on, client and proven subject",
        super::route_owners(
            &on,
            None,
            None,
            (Some(&subject_fixture), None, Some(&client_fixture)),
        ),
        (SUBJECT_KEY, SUBJECT_KEY, SUBJECT_KEY),
    );
    check(
        "auth on, proven subject with no client",
        super::route_owners(&on, None, None, (Some(&subject_fixture), None, None)),
        ("", "", ""),
    );
    check(
        "auth on, verified identity and agent",
        super::route_owners(
            &on,
            Some(&verified_fixture),
            Some(&agent_fixture),
            (None, None, None),
        ),
        (&actor, &actor, &actor),
    );
    check(
        "auth on, client and agent",
        super::route_owners(
            &on,
            None,
            Some(&agent_fixture),
            (None, None, Some(&client_fixture)),
        ),
        (&credential_owner, &credential_owner, &credential_owner),
    );
}
