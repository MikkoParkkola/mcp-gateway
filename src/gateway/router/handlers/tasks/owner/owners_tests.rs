// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pins `route_owners` across identity combinations for MIK-8498.TASKS.1.

use super::{AUTH_DISABLED_TASK_OWNER, TaskCaller, TaskOwners, agent_task_owner};
use crate::gateway::auth::AuthenticatedClient;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

const SUBJECT_KEY: &str = "subject:5:proxy:5:alice";
const MTLS_SUBJECT_KEY: &str = "subject:4:mtls:10:spiffe://a";

fn agent(client_id: &str) -> crate::gateway::oauth::OAuthAgentIdentity {
    crate::gateway::oauth::OAuthAgentIdentity {
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
    crate::gateway::router::tests::FixtureDir,
) {
    let auth = crate::config::AuthConfig {
        enabled,
        ..crate::config::AuthConfig::default()
    };
    crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await
}

fn key_holder(secret: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: secret.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: crate::gateway::auth::principal_of(secret),
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

fn mtls_subject(subject: &str) -> GrantSubject {
    GrantSubject {
        authority: "mtls".to_string(),
        subject: subject.to_string(),
        label: None,
    }
}

fn spiffe_cert() -> CertIdentity {
    CertIdentity {
        common_name: None,
        organizational_unit: None,
        san_uris: vec!["spiffe://a".to_string()],
        san_dns_names: Vec::new(),
        display_name: String::new(),
        quota_principal: None,
    }
}

fn nameless_cert() -> CertIdentity {
    CertIdentity {
        common_name: None,
        organizational_unit: None,
        san_uris: Vec::new(),
        san_dns_names: Vec::new(),
        display_name: "Display".to_string(),
        quota_principal: None,
    }
}

struct Fixtures {
    agent: crate::gateway::oauth::OAuthAgentIdentity,
    subject: GrantSubject,
    client: AuthenticatedClient,
    verified: VerifiedIdentity,
    agent_owner: String,
    credential_owner: String,
    actor: String,
}

fn fixtures() -> Fixtures {
    let verified_fixture = verified();
    let actor = VerifiedIdentity::stable_actor_id(&verified_fixture);
    Fixtures {
        agent: agent("agent-a"),
        subject: proven_subject(),
        client: key_holder("alpha"),
        verified: verified_fixture,
        agent_owner: agent_task_owner("agent-a"),
        credential_owner: format!(
            "{}{}",
            crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,
            crate::gateway::auth::principal_of("alpha").storage_form()
        ),
        actor,
    }
}

fn caller<'a>(
    verified_identity: Option<&'a VerifiedIdentity>,
    agent: Option<&'a crate::gateway::oauth::OAuthAgentIdentity>,
    subject: Option<&'a GrantSubject>,
    client: Option<&'a AuthenticatedClient>,
) -> TaskCaller<'a> {
    TaskCaller {
        verified_identity,
        agent,
        subject,
        cert: None,
        client,
    }
}

fn check(label: &str, got: &TaskOwners, want: (&str, &str, &str)) {
    assert_eq!(got.task, want.0, "{label}: task owner");
    assert_eq!(got.events, want.1, "{label}: events owner");
    assert_eq!(got.admission, want.2, "{label}: admission owner");
}

#[tokio::test]
async fn route_owners_with_auth_off() {
    let (off, _off_store) = state(false).await;
    let fx = fixtures();
    let disabled = AUTH_DISABLED_TASK_OWNER;

    check(
        "auth off, nothing",
        &super::route_owners(&off, &caller(None, None, None, None)),
        (disabled, disabled, ""),
    );
    check(
        "auth off, agent only",
        &super::route_owners(&off, &caller(None, Some(&fx.agent), None, None)),
        (&fx.agent_owner, disabled, &fx.agent_owner),
    );
    check(
        "auth off, proven subject",
        &super::route_owners(&off, &caller(None, None, Some(&fx.subject), None)),
        (SUBJECT_KEY, SUBJECT_KEY, SUBJECT_KEY),
    );
    // The task arm passes the agent, so only the events arm takes the
    // `(None, Some(subject))` branch.
    check(
        "auth off, agent and proven subject",
        &super::route_owners(
            &off,
            &caller(None, Some(&fx.agent), Some(&fx.subject), None),
        ),
        (&fx.agent_owner, SUBJECT_KEY, &fx.agent_owner),
    );
    check(
        "auth off, verified identity",
        &super::route_owners(&off, &caller(Some(&fx.verified), None, None, None)),
        (&fx.actor, &fx.actor, &fx.actor),
    );
    check(
        "auth off, verified identity and proven subject",
        &super::route_owners(
            &off,
            &caller(Some(&fx.verified), None, Some(&fx.subject), None),
        ),
        (&fx.actor, &fx.actor, &fx.actor),
    );
}

#[tokio::test]
async fn route_owners_with_auth_on() {
    let (on, _on_store) = state(true).await;
    let fx = fixtures();

    check(
        "auth on, nothing",
        &super::route_owners(&on, &caller(None, None, None, None)),
        ("", "", ""),
    );
    check(
        "auth on, agent only",
        &super::route_owners(&on, &caller(None, Some(&fx.agent), None, None)),
        (&fx.agent_owner, "", &fx.agent_owner),
    );
    check(
        "auth on, authenticated API-key client",
        &super::route_owners(&on, &caller(None, None, None, Some(&fx.client))),
        (
            &fx.credential_owner,
            &fx.credential_owner,
            &fx.credential_owner,
        ),
    );
    check(
        "auth on, client and proven subject",
        &super::route_owners(
            &on,
            &caller(None, None, Some(&fx.subject), Some(&fx.client)),
        ),
        (SUBJECT_KEY, SUBJECT_KEY, SUBJECT_KEY),
    );
    check(
        "auth on, proven subject with no client",
        &super::route_owners(&on, &caller(None, None, Some(&fx.subject), None)),
        ("", "", ""),
    );
    check(
        "auth on, verified identity and agent",
        &super::route_owners(
            &on,
            &caller(Some(&fx.verified), Some(&fx.agent), None, None),
        ),
        (&fx.actor, &fx.actor, &fx.actor),
    );
    check(
        "auth on, client and agent",
        &super::route_owners(&on, &caller(None, Some(&fx.agent), None, Some(&fx.client))),
        (
            &fx.credential_owner,
            &fx.credential_owner,
            &fx.credential_owner,
        ),
    );
    let cert_subject = mtls_subject("spiffe://a");
    let cert = spiffe_cert();
    check(
        "auth on, client and certificate subject",
        &super::route_owners(
            &on,
            &TaskCaller {
                verified_identity: None,
                agent: None,
                subject: Some(&cert_subject),
                cert: Some(&cert),
                client: Some(&fx.client),
            },
        ),
        (MTLS_SUBJECT_KEY, MTLS_SUBJECT_KEY, MTLS_SUBJECT_KEY),
    );
    let placeholder_subject = mtls_subject("Display");
    let nameless = nameless_cert();
    check(
        "auth on, client and placeholder subject of a certificate naming nobody",
        &super::route_owners(
            &on,
            &TaskCaller {
                verified_identity: None,
                agent: None,
                subject: Some(&placeholder_subject),
                cert: Some(&nameless),
                client: Some(&fx.client),
            },
        ),
        (
            &fx.credential_owner,
            &fx.credential_owner,
            &fx.credential_owner,
        ),
    );
}
