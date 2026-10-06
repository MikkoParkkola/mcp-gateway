// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7804: the identity row the direct route writes names the principal the
//! CAPTURED backend resolves the credential for. An account-bound backend turns
//! the sole operator into a principal; the replacement a reload registered
//! under the same name is not account-bound and has none. A subject taken by
//! name would record the replacement's answer against the captured backend's
//! request: a wrong actor in the audit trail.

use std::sync::Arc;
use std::time::Duration;

use super::direct_caller::{Caller, Route};
use super::direct_preflight::{Preflight, propagate_identity};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::auth::{AuthenticatedClient, anonymous_client, principal_of};
use crate::gateway::router::tests::direct_route_state_with_identity;
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_propagation::{InstalledAccount, Minter};
use crate::personal_accounts::config::DescriptorMode;
use crate::personal_accounts::identity::AccountDescriptor;
use crate::personal_accounts::{
    AccountCustody, CredentialLease, CustodyError, RejectionOutcome, ReleasedCredentials,
    VaultStrategy,
};
use crate::protocol::RequestId;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const ACCOUNT: &str = "acct";

/// Custody nothing here reaches: the principal is read from the vault's
/// sole-operator setting, never from a stored grant.
struct Unreached;

#[async_trait::async_trait]
impl AccountCustody for Unreached {
    async fn resolve(
        &self,
        _account: &crate::personal_accounts::AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        Err(CustodyError::Busy)
    }

    async fn refresh_if_expired(
        &self,
        _account: &crate::personal_accounts::AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        Err(CustodyError::Busy)
    }

    async fn release(&self, _lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        Err(CustodyError::Busy)
    }

    async fn refresh_after_rejection(
        &self,
        _lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        Err(CustodyError::Busy)
    }
}

fn backend(config: BackendConfig) -> Arc<Backend> {
    Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// A sole-operator managed vault for [`ACCOUNT`].
fn operator_vault() -> Arc<VaultStrategy> {
    Arc::new(VaultStrategy::new(
        Arc::new(Unreached),
        AccountDescriptor {
            descriptor_id: ACCOUNT.to_string(),
            provider: "google".to_string(),
            resource: "https://resource.invalid/".to_string(),
            issuer: "https://accounts.google.invalid".to_string(),
        },
        "0".repeat(64),
        true,
    ))
}

/// A state whose only backend is `captured`, with the vault installed for its
/// account and `logger` as the route's transparency log.
async fn state_with(
    captured: &Arc<Backend>,
    logger: Arc<TransparencyLogger>,
) -> Arc<crate::gateway::router::AppState> {
    let (mut state, _store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(
        state_mut.backends.register(Arc::clone(captured)),
        "registration"
    );
    let meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.account_strategies().install(
        InstalledAccount {
            descriptor_id: ACCOUNT.to_string(),
            provider: "google".to_string(),
            audience: "https://resource.invalid/".to_string(),
            required: false,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
            minter: Minter::Managed(operator_vault()),
        },
        DescriptorMode::PersonalManaged,
    );
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(logger);
    state
}

/// A caller that presented a validated credential and no end-user identity:
/// the sole operator, where a vault says so.
fn credentialed_caller() -> Caller {
    Caller {
        client: Some(AuthenticatedClient {
            name: "key".to_string(),
            principal: principal_of("a-validated-secret"),
            authenticated: true,
            ..anonymous_client()
        }),
        cert_identity: None,
        oauth_agent_identity: None,
        proven: None,
        slot: None,
        verified_identity: None,
        inbound_headers: axum::http::HeaderMap::new(),
        grant_subject: None,
        spend_key: String::new(),
    }
}

fn guarded() -> Preflight {
    Preflight {
        retry: crate::protocol::mrtr::RetryFields::default(),
        chain_nonce: None,
        signing_scope: crate::gateway::meta_mcp::signing::SigningScope::InvokeOnly,
        signs: false,
        signing_nonce: None,
        challenge: None,
        isolation_guarded: true,
    }
}

#[tokio::test]
async fn the_mint_audit_subject_is_the_captured_backends_principal() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let logger = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: file.path().to_string_lossy().to_string(),
            key_id: "mik-7804".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("transparency logger opens"),
    );
    let captured = backend(BackendConfig {
        account: Some(ACCOUNT.to_string()),
        ..BackendConfig::default()
    });
    let state = state_with(&captured, logger).await;

    // A reload replaces the account-bound backend with an unbound one.
    assert!(state.backends.remove("alpha"), "alpha was registered");
    assert!(
        state.backends.register(backend(BackendConfig::default())),
        "the reload registers the replacement"
    );

    let caller = credentialed_caller();
    let expected = state.meta_mcp.audit_subject_for(&captured, caller.proof());
    assert_ne!(
        expected,
        crate::identity_propagation::audit_subject(None),
        "premise: the account-bound backend turns the sole operator into a principal"
    );

    let route = Route {
        backend: captured,
        session_id: None,
    };
    // The account-bound backend has no compiled propagation: refused, and the
    // refusal is audited under the subject of the principal it resolves for.
    let refused = propagate_identity(
        &state,
        "alpha",
        &caller,
        &route,
        &guarded(),
        &RequestId::Number(1),
    )
    .await;
    assert!(refused.is_err(), "an unbound account backend is refused");

    let rows = std::fs::read_to_string(file.path()).expect("the audit log is readable");
    assert!(
        rows.contains("idp_refuse"),
        "no refusal row written: {rows}"
    );
    assert!(
        rows.contains(&expected),
        "the refusal was audited under another backend's subject: {rows}"
    );
}
