// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `AccountStrategyRegistry::revalidate` against a REAL managed lease: a
//! descriptor re-installed under another minter refuses the credential minted
//! before the swap, whichever kind replaced which.

use super::*;
use crate::identity_propagation::{
    AccountCredential, AccountStrategyRegistry, IdentityPropagation, InstalledAccount, Minter,
    PropagatedCredential,
};
use crate::personal_accounts::config::DescriptorMode;

/// An external strategy with an open published lifetime.
struct External;

#[async_trait::async_trait]
impl IdentityPropagation for External {
    async fn propagate(
        &self,
        _identity: &VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> std::result::Result<PropagatedCredential, PropagationError> {
        Ok(PropagatedCredential {
            headers: vec![("Authorization".to_owned(), "Bearer external".to_owned())],
            expires_at: i64::MAX,
            subject_key: "alice".to_owned(),
            audience: RESOURCE.to_owned(),
            scopes: Vec::new(),
            cache_binding: "external-binding".to_owned(),
        })
    }
}

fn installed(minter: Minter) -> InstalledAccount {
    InstalledAccount {
        descriptor_id: DESCRIPTOR_ID.into(),
        provider: "google".into(),
        audience: RESOURCE.into(),
        required: false,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
        minter,
    }
}

async fn prepared(
    registry: &AccountStrategyRegistry,
    alice: &VerifiedIdentity,
) -> Arc<crate::identity_propagation::PreparedAccountCredential> {
    let resolved = registry
        .resolve(DESCRIPTOR_ID, "oauth:google", CallerProof::Verified(alice))
        .await
        .expect("alice's grant mints");
    match resolved {
        AccountCredential::Prepared(prepared) => prepared,
        AccountCredential::Legacy => panic!("a personal_managed descriptor is never legacy"),
    }
}

async fn replaced(
    registry: &AccountStrategyRegistry,
    prepared: &crate::identity_propagation::PreparedAccountCredential,
    alice: &VerifiedIdentity,
    why: &str,
) {
    let refused = registry
        .revalidate(prepared, CallerProof::Verified(alice))
        .await
        .expect_err(why);
    assert!(
        refused.to_string().contains("strategy was replaced"),
        "{why}: {refused}"
    );
}

/// Mutants: the managed arm accepting any vault, or the kind-mismatch arm
/// accepting, lets a credential minted under one minter be dispatched under
/// another.
#[test]
fn a_reinstalled_minter_of_either_kind_refuses_the_earlier_credential() {
    let tmp = tempfile::TempDir::new().expect("root");
    let alice = identity();
    seed(
        tmp.path(),
        &[(
            key_for(Principal::Verified(&alice)),
            unexpired_grant(ALICE_TOKEN),
        )],
    );

    block_on(async {
        let handle = CustodyHandle::start(
            store_config(tmp.path()),
            CountingProvider {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            SilentObserver,
            4,
        )
        .expect("custody starts against a seeded store");
        let custody: Arc<dyn AccountCustody> = Arc::new(handle);
        let vault = |custody: &Arc<dyn AccountCustody>| {
            Arc::new(VaultStrategy::new(
                Arc::clone(custody),
                descriptor(),
                seeded_revision(),
                false,
            ))
        };
        let released = vault(&custody);
        let registry = AccountStrategyRegistry::default();
        registry.declare(DESCRIPTOR_ID, "google", DescriptorMode::PersonalManaged);
        let install = |minter| registry.install(installed(minter), DescriptorMode::PersonalManaged);

        install(Minter::Managed(Arc::clone(&released)));
        let managed = prepared(&registry, &alice).await;
        registry
            .revalidate(&managed, CallerProof::Verified(&alice))
            .await
            .expect("control: the vault that minted rechecks its own credential");

        install(Minter::Managed(vault(&custody)));
        replaced(&registry, &managed, &alice, "another vault instance").await;

        // The same allocation installed as the other kind: only the kind
        // differs, so the pointer alone cannot refuse it.
        install(Minter::External(Arc::clone(&released) as _));
        replaced(&registry, &managed, &alice, "managed to external").await;

        install(Minter::External(Arc::new(External)));
        let external = prepared(&registry, &alice).await;
        registry
            .revalidate(&external, CallerProof::Verified(&alice))
            .await
            .expect("control: an external mint rechecks under its own install");
        install(Minter::Managed(Arc::clone(&released)));
        replaced(&registry, &external, &alice, "external to managed").await;

        // Positive control: the original install revalidates again.
        registry
            .revalidate(&managed, CallerProof::Verified(&alice))
            .await
            .expect("control: the unmoved world revalidates");
    });
}
