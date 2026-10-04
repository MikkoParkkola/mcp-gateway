// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7795: a propagated assertion is bound to its backend. The receiving side
//! verifies the signature against the gateway JWKS; a verifier configured for
//! another audience rejects it, and one configured for the right audience
//! accepts it. The other tests decode the claims without verifying.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use super::{BackendDescriptor, IdentityPropagation, SignedAssertionStrategy};
use crate::gateway::oauth::GatewayKeyPair;
use crate::key_server::oidc::VerifiedIdentity;

const AUDIENCE: &str = "https://memory.internal";

fn verify(token: &str, key: &GatewayKeyPair, audience: &str) -> bool {
    let jwk = key.jwks().keys.remove(0);
    let decoding = DecodingKey::from_ec_components(&jwk.x, &jwk.y).expect("the JWKS key decodes");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&["mcp-gateway"]);
    jsonwebtoken::decode::<serde_json::Value>(token, &decoding, &validation).is_ok()
}

#[tokio::test]
async fn a_verifier_for_another_audience_rejects_a_minted_assertion() {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let strategy = SignedAssertionStrategy::new(Arc::clone(&key), 300);
    let identity = VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    };
    let backend = BackendDescriptor {
        id: "memory".to_string(),
        audience: AUDIENCE.to_string(),
        ..Default::default()
    };

    let credential = strategy
        .propagate(&identity, &backend)
        .await
        .expect("an assertion is minted");
    let token = credential.headers[0]
        .1
        .strip_prefix("Bearer ")
        .expect("bearer prefix");

    assert!(
        verify(token, &key, AUDIENCE),
        "the right audience verifies, so the rejection below is the audience"
    );
    assert!(
        !verify(token, &key, "https://another.internal"),
        "an assertion for one backend must not verify for another"
    );
}
