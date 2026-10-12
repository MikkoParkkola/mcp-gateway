// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 D16: the identities a stream was opened under are part of its
//! view. Under an mTLS policy a caller shown nothing without its certificate
//! is told a visible change only if the stream carries that certificate.

use super::audience_access::AGENT_A;
use super::audience_fixture::{World, tool};

fn alpha_with(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

fn client_cert() -> crate::mtls::CertIdentity {
    crate::mtls::CertIdentity {
        common_name: Some("svc".to_string()),
        display_name: "svc".to_string(),
        ..Default::default()
    }
}

/// R8: a listen stream opened with a certificate is told a visible change; the
/// certificate it was opened with is part of its view (kills M33c).
#[tokio::test]
async fn r8_listen_with_a_certificate_is_told_a_visible_change() {
    let w = World::start_mtls().await;
    let mut ear = w
        .listen_with("k-std", |request| {
            request.extensions_mut().insert(client_cert());
        })
        .await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "the stream's certificate admits alpha, so its change is visible"
    );
}

/// R8 control: the same change sends a stream that presented no certificate
/// nothing, so the row above is told by the certificate and nothing else.
#[tokio::test]
async fn r8_control_listen_without_a_certificate_is_told_nothing() {
    let w = World::start_mtls().await;
    let mut ear = w.listen("k-std").await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "alpha is not shown without a certificate"
    );
}

/// R7: with agent auth on, a listen stream opened with an agent token is told
/// a visible change; the OAuth agent it was opened with is part of its view
/// (kills M33b).
#[tokio::test]
async fn r7_listen_with_an_agent_token_is_told_a_visible_change() {
    let w = World::start_agent(|meta| meta).await;
    let mut ear = w
        .listen(&super::audience_access::agent_token(AGENT_A))
        .await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "the agent's scope admits alpha, so its change is visible"
    );
}

/// A personal capability owned by the shared principal the two agents act as.
fn agent_cal(description: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: agent_cal\ndescription: {description}\n\
schema:\n  input:\n    type: object\n    properties: {{}}\n\
metadata:\n  exposure: personal\n  identity_owner:\n    authority: \"api_key\"\n    subject: public\n\
providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /cal\n      method: GET\n\
auth:\n  required: false\n  type: none\n"
    )
}

/// A grant on `agent_cal` for the shared principal, held by `agent_a` alone.
fn agent_a_grant() -> crate::identity_grants::LocalIdentityGrantStore {
    use crate::identity_grants::{
        GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant,
    };
    use crate::security::ProofSource;
    let shared = GrantSubject::new("api_key", "public", None);
    crate::identity_grants::LocalIdentityGrantStore::from_grants([IdentityGrant {
        grant_id: "g-agent-a".to_string(),
        subject: shared.clone(),
        agent: GrantAgent::Exact(GrantAgentKey {
            source: ProofSource::VerifiedJwtSubject,
            id: AGENT_A.to_string(),
        }),
        capability: "agent_cal".to_string(),
        tool: None,
        scope: GrantScope::Any,
        owner: Some(shared),
        expires_at: None,
        revoked_at: None,
        provenance: "mik-8350".to_string(),
        reason: "R9 proven agent id".to_string(),
    }])
}

/// R9: two agents act as one principal; a grant names agent A alone, so a
/// change to the capability it grants is told to A's stream and not to B's.
/// The proven agent id is part of the view (kills M33d).
#[tokio::test]
async fn r9_a_grant_for_one_agent_is_told_to_its_stream_alone() {
    use super::audience_access::{AGENT_B, agent_token};
    let w = World::start_agent(|meta| meta.with_identity_grants(agent_a_grant())).await;
    w.set_capability_yaml(&agent_cal("one"));
    w.settle().await;
    let (a, b) = (agent_token(AGENT_A), agent_token(AGENT_B));
    let seen = (
        w.discovered(&a, "caps").await,
        w.discovered(&b, "caps").await,
    );
    assert!(
        seen.0.contains(&"agent_cal".to_string()),
        "premise: agent A sees the capability: {seen:?}"
    );
    assert!(
        !seen.1.contains(&"agent_cal".to_string()),
        "premise: agent B does not: {seen:?}"
    );
    let mut ears = [w.listen(&a).await, w.listen(&b).await];
    w.settle().await;
    for ear in &mut ears {
        let _ = ear.told(&w).await;
    }
    w.set_capability_yaml(&agent_cal("two"));
    assert_eq!(
        ears[0].told(&w).await,
        1,
        "A's grant makes the change visible"
    );
    assert_eq!(
        ears[1].told(&w).await,
        0,
        "B holds no grant: nothing to tell"
    );
}
