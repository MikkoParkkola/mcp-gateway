// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7804: the per-caller catalogue reads resolve a credential for the
//! backend they are about to fetch from, not for whatever the registry holds
//! under that name when the lookup runs. A reload that swaps the backend in
//! between must not hand the replacement's minted credential to a fetch that
//! goes out through the original.

use std::sync::Arc;
use std::time::Duration;

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    CallerProof, IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

/// Mints `Bearer minted-for-<subject>` bound to `<subject>@<audience>`.
struct Mint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Mint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{subject_key}"),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{subject_key}@{}", backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

fn alpha() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_string(),
    }
}

fn backend(config: BackendConfig) -> Arc<Backend> {
    Arc::new(Backend::new(
        "ledger",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn minting() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: false,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    }
}

/// A catalogue read for the captured backend mints exactly what that backend's
/// own configuration asks for. The captured backend propagates nothing; the
/// replacement a reload registered under the same name mints a per-user
/// credential. Mutant: resolving by name hands the replacement's credential to
/// a fetch that goes out through the captured backend. The control reads the
/// replacement itself and does get the minted credential.
#[tokio::test]
async fn a_catalogue_read_mints_what_the_captured_backend_asks_for() {
    let registry = Arc::new(BackendRegistry::new());
    let captured = backend(BackendConfig::default());
    assert!(registry.register(Arc::clone(&captured)), "registration");
    let meta = MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(Mint));
    let identity = alpha();
    let caller = CallerProof::Verified(&identity);

    let replacement = backend(minting());
    assert!(registry.remove("ledger"), "ledger was registered");
    assert!(registry.register(Arc::clone(&replacement)), "reload");

    let control = meta.catalogue_credential_for(&replacement, caller).await;
    assert!(
        control.is_some_and(|(headers, binding)| !headers.is_empty() && binding.is_some()),
        "control: the replacement mints a per-user credential"
    );
    let served = meta.catalogue_credential_for(&captured, caller).await;
    assert_eq!(
        served,
        Some((Vec::new(), None)),
        "the captured backend propagates nothing: the reload must not mint for it"
    );
}
