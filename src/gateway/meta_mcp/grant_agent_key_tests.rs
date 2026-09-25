// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A4b T19 at the dispatch chokepoint: the proven pair reaches the grant
//! check unflattened, so a grant for one namespace does not admit the other.

use std::sync::Arc;

use super::*;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::router::CallerStanding;
use crate::identity_grants::{
    GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};
use crate::security::{ProofSource, ProvenAgentId};

const CAPABILITY: &str = r"
fulcrum: '1.0'
name: calendar_read
description: Read a personal calendar
schema:
  input:
    type: object
  output:
    type: object
metadata:
  exposure: personal
  identity_owner:
    authority: cloudflare_access
    subject: user-123
providers:
  primary:
    service: rest
    config:
      base_url: 'https://example.invalid'
      path: /calendar
      method: GET
";

fn subject() -> GrantSubject {
    GrantSubject::new("cloudflare_access", "user-123", None)
}

async fn meta_with_grant_for(source: ProofSource) -> (MetaMcp, tempfile::TempDir) {
    let grant = IdentityGrant {
        grant_id: "g-runner".to_string(),
        subject: subject(),
        agent: GrantAgent::Exact(GrantAgentKey {
            source,
            id: "runner".to_string(),
        }),
        capability: "calendar_read".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: Some(subject()),
        expires_at: None,
        revoked_at: None,
        provenance: "unit-test".to_string(),
        reason: "A4b T19".to_string(),
    };
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("calendar_read.yaml"), CAPABILITY).unwrap();
    let caps = Arc::new(CapabilityBackend::new(
        "personal_caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_identity_grants(LocalIdentityGrantStore::from_grants(vec![grant]));
    meta.set_capabilities(caps);
    (meta, dir)
}

fn decide(meta: &MetaMcp, proof: ProofSource) -> Result<()> {
    let subject = subject();
    let scope = InvokeScope {
        agent_id: Some(ProvenAgentId::for_test("runner", proof)),
        grant_subject: Some(&subject),
        ..InvokeScope::allow_all(CallerStanding::Standard)
    };
    meta.may_invoke("personal_caps", "calendar_read", scope, None)
}

/// T19: a grant written for JWT `sub` `runner` refuses the mTLS `runner`.
#[tokio::test]
async fn a_jwt_scoped_grant_refuses_an_mtls_caller_with_the_same_id() {
    let (meta, _dir) = meta_with_grant_for(ProofSource::VerifiedJwtSubject).await;
    let error = decide(&meta, ProofSource::MutualTls).expect_err("T19");
    assert!(error.to_string().contains("Identity grant denied"), "{error}");
}

/// C19a/C19b: each source admits its own caller through the same path.
#[tokio::test]
async fn an_exact_grant_admits_its_own_source_at_dispatch() {
    for proof in [ProofSource::MutualTls, ProofSource::VerifiedJwtSubject] {
        let (meta, _dir) = meta_with_grant_for(proof).await;
        decide(&meta, proof).unwrap_or_else(|e| panic!("{proof}: {e}"));
    }
}
