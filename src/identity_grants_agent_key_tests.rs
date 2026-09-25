// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A4b: an exact grant is keyed by `(proof source, id)`, and a 3.x bare row is
//! refused at load rather than guessed into a source.

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};

use super::*;
use crate::security::{ProofSource, ProvenAgentId};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/identity_grants_3x")
        .join(name)
}

fn alice() -> GrantSubject {
    GrantSubject::new("api_key", "alice", None)
}

fn proven(id: &str, proof: ProofSource) -> OwnedProvenAgentId {
    ProvenAgentId::for_test(id, proof).into()
}

fn key(source: ProofSource, id: &str) -> GrantAgentKey {
    GrantAgentKey {
        source,
        id: id.to_string(),
    }
}

fn grant(grant_id: &str, agent: GrantAgent) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: alice(),
        agent,
        capability: "calendar_read".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: Some(alice()),
        expires_at: None,
        revoked_at: None,
        provenance: "unit-test".to_string(),
        reason: "A4b".to_string(),
    }
}

fn request(agent: Option<OwnedProvenAgentId>) -> IdentityGrantRequest {
    IdentityGrantRequest {
        identity: Some(alice()),
        agent_id: agent,
        capability: "calendar_read".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        exposure: CapabilityExposure::Personal,
        owner: Some(alice()),
        now: Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap(),
    }
}

/// T19 at the store: a JWT-keyed grant does not admit the mTLS `runner`.
/// C19a/C19b: each source admits its own caller, and the audit record says
/// which namespace matched.
#[test]
fn an_exact_grant_admits_only_the_source_it_names() {
    let jwt = LocalIdentityGrantStore::from_grants([grant(
        "g-jwt",
        GrantAgent::Exact(key(ProofSource::VerifiedJwtSubject, "runner")),
    )]);
    let mtls = LocalIdentityGrantStore::from_grants([grant(
        "g-mtls",
        GrantAgent::Exact(key(ProofSource::MutualTls, "runner")),
    )]);
    let mtls_runner = || Some(proven("runner", ProofSource::MutualTls));
    let jwt_runner = || Some(proven("runner", ProofSource::VerifiedJwtSubject));

    assert!(!jwt.evaluate(&request(mtls_runner())).allowed, "T19");
    assert!(!mtls.evaluate(&request(jwt_runner())).allowed, "T19 mirror");

    let c19a = mtls.evaluate(&request(mtls_runner()));
    assert!(c19a.allowed, "C19a");
    assert_eq!(c19a.audit.agent_id.as_deref(), Some("mtls:runner"));
    assert!(jwt.evaluate(&request(jwt_runner())).allowed, "C19b");
}

fn recommendation(agent: Option<OwnedProvenAgentId>) -> GrantRecommendationRequest {
    GrantRecommendationRequest {
        identity: Some(alice()),
        agent_id: agent,
        capability: "calendar_read".to_string(),
        tool: None,
        scope: GrantScope::Read,
        exposure: CapabilityExposure::Personal,
        owner: Some(alice()),
        data_class: GrantDataClass::Internal,
        tool_risk: GrantToolRisk::Low,
        requested_lease_seconds: None,
        reason: "A4b".to_string(),
        now: Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap(),
    }
}

/// R1: the lease names the proven pair, for both sources, so a lease fixed
/// to either source fails one half. C-R1: no proven agent keeps `Any`.
#[test]
fn a_lease_proposal_carries_the_proven_pair() {
    let store = LocalIdentityGrantStore::new();
    for proof in [ProofSource::VerifiedJwtSubject, ProofSource::MutualTls] {
        let lease = store
            .recommend(&recommendation(Some(proven("runner", proof))))
            .lease
            .expect("a personal capability without a grant gets a lease");
        assert_eq!(lease.agent, GrantAgent::Exact(key(proof, "runner")), "R1 {proof}");
    }
    let lease = store.recommend(&recommendation(None)).lease.unwrap();
    assert_eq!(lease.agent, GrantAgent::Any, "C-R1");
}

/// M1, from real 3.4.0 output in both encodings: YAML writes the bare row as
/// a tag (`agent: !exact runner`), JSON as a map (`{"exact": "runner"}`).
#[tokio::test]
async fn a_3x_bare_exact_grants_file_is_refused_naming_every_row() {
    for name in ["grants-3.4.0.yaml", "grants-3.4.0.json"] {
        let error = read_identity_grants_file(&fixture(name))
            .await
            .expect_err("a bare exact row must not load");
        for needle in ["g-runner", "g-bot", "runner", "build-bot", "mtls", "jwt", "any"] {
            assert!(error.contains(needle), "{name}: missing {needle}: {error}");
        }
        assert!(!error.contains("g-any"), "{name}: the any row is fine: {error}");
    }
}

async fn round_trip(name: &str, grants: Vec<IdentityGrant>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let file = IdentityGrantFile::new(grants);
    write_identity_grants_file(&path, &file).await.unwrap();
    assert_eq!(read_identity_grants_file(&path).await.unwrap(), file, "{name}");
}

/// C-M1: the refusal is row-scoped, so an `any`-only file still loads and
/// round-trips. Its sibling: a qualified file round-trips in both encodings.
#[tokio::test]
async fn any_and_qualified_grant_files_round_trip() {
    for name in ["any.yaml", "any.json"] {
        round_trip(name, vec![grant("g-any", GrantAgent::Any)]).await;
    }
    let qualified = || {
        vec![
            grant("g-jwt", GrantAgent::Exact(key(ProofSource::VerifiedJwtSubject, "runner"))),
            grant("g-mtls", GrantAgent::Exact(key(ProofSource::MutualTls, "spiffe://x/runner"))),
        ]
    };
    for name in ["qualified.yaml", "qualified.json"] {
        round_trip(name, qualified()).await;
    }
}

/// The spellings UPGRADING tells an operator to hand-write load as the key.
#[tokio::test]
async fn hand_written_qualified_rows_load_in_both_yaml_forms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("grants.yaml");
    let body = std::fs::read_to_string(fixture("grants-3.4.0.yaml"))
        .unwrap()
        .replace("agent: !exact runner", "agent: {exact: {source: jwt, id: runner}}")
        .replace(
            "agent: !exact build-bot",
            "agent: !exact {source: mtls, id: build-bot}",
        );
    std::fs::write(&path, body).unwrap();
    let file = read_identity_grants_file(&path).await.unwrap();
    let agents: Vec<_> = file.grants.iter().map(|g| g.agent.clone()).collect();
    assert_eq!(
        agents,
        vec![
            GrantAgent::Exact(key(ProofSource::VerifiedJwtSubject, "runner")),
            GrantAgent::Exact(key(ProofSource::MutualTls, "build-bot")),
            GrantAgent::Any,
        ]
    );
}
