// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `rt-i3` T1/T2 — [`sole_operator_asserted`](super::super::account_bindings::sole_operator_asserted)
//! observed through the REAL dispatch path, not the predicate in isolation.
//!
//! Both tests drive the production sequence a capability dispatch actually
//! runs: `install_account_strategies` (the one install, real for both
//! listeners) followed by `AccountStrategyRegistry::resolve` against a real,
//! empty custody — a descriptor that is declared but never connected. Custody
//! is real rather than scripted because the fact under test is WHICH refusal
//! text a caller reaches, and `PropagationError::AccountNotConnected`'s own
//! text ("no connected account (fail-closed)") is production's, not this
//! fixture's.
//!
//! T1 (stdio): auth is off and `single_user` is not declared, and the caller
//! presents nothing but the stdio transport itself. A stdio gateway is
//! spawned BY its one operator (`CallerProvenance::LocalTransport`), so it
//! must be served as the sole operator regardless of `auth.enabled` — RED
//! shares one formula between both listeners, gated on `auth.enabled`, so
//! this fails until stdio gets its own predicate.
//!
//! T2 (http): auth is on with two API keys — never a sole-operator shape,
//! in RED or after the fix. A no-regression guard: this must keep failing
//! the same way, over http, once T1 is fixed.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::config::{ApiKeyConfig, AuthConfig, Config, api_key_digest_spec};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::gateway::server::STDIO_CREDENTIAL_PRINCIPAL;
use crate::gateway::server::account_bindings::{ServeMode, install_account_strategies};
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::personal_accounts::config::{
    AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
};
use crate::personal_accounts::{
    AccountCustody, AccountKey, CredentialLease, CredentialReleaseObserver, CustodyHandle,
    GrantRecord, PersonalAccountStore, ProviderRefreshError, RefreshProvider, ReleasedCredentials,
    StoreConfig, TokenRefresh,
};

const DESCRIPTOR_ID: &str = "acct";
const PROVIDER: &str = "wire-fixture";
const STORE_KEY: [u8; 32] = [0x42; 32];

/// With no grant seeded, custody must refuse before it would ever ask a
/// provider to refresh one — so this provider is never called.
struct UnreachableProvider;

impl RefreshProvider for UnreachableProvider {
    fn refresh(
        &self,
        _account: &AccountKey,
        _current: &GrantRecord,
    ) -> impl std::future::Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        // Never reached: with no grant seeded, custody refuses before asking.
        std::future::ready(Err(ProviderRefreshError::Unavailable))
    }
}

/// Nothing in this fixture mints, so nothing ever releases.
struct UnreachableObserver;

impl CredentialReleaseObserver for UnreachableObserver {
    fn on_release(
        &self,
        _account: &AccountKey,
        _lease: &CredentialLease,
        _credentials: &ReleasedCredentials,
    ) {
        unreachable!("no mint succeeds in this fixture; nothing ever releases")
    }
}

/// Real custody over a freshly initialized, empty store: `DESCRIPTOR_ID` is
/// declared by the fixture configuration but never connected, so a resolve
/// against it reaches production's own absence refusal.
fn empty_custody(root: &std::path::Path) -> Arc<dyn AccountCustody> {
    let root = root.canonicalize().expect("fixture tempdir exists");
    let config = StoreConfig {
        instance_id: "stdio-sole-operator-tests".to_string(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([("current".to_string(), STORE_KEY.to_vec())]),
        max_entries: 16,
        max_authority_bytes: 65_536,
    };
    let store = PersonalAccountStore::initialize(config.clone()).expect("store initializes");
    drop(store);
    let handle = CustodyHandle::start(config, UnreachableProvider, UnreachableObserver, 1)
        .expect("custody starts over the empty store");
    Arc::new(handle) as Arc<dyn AccountCustody>
}

/// One structurally complete `personal_managed` descriptor. Synthetic
/// `.invalid` hosts; nothing here is opened over the network.
fn descriptor() -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: PROVIDER.to_string(),
        resource: Some("https://wire.example.invalid/".to_string()),
        issuer: Some("https://accounts.wire-fixture.invalid".to_string()),
        authorization_endpoint: Some("https://accounts.wire-fixture.invalid/authorize".to_string()),
        token_endpoint: Some("https://accounts.wire-fixture.invalid/token".to_string()),
        revocation_endpoint: None,
        client_id: Some("synthetic-client".to_string()),
        client_secret_ref: Some("env:FIXTURE_STDIO_SOLE_OPERATOR_SECRET".to_string()),
        redirect_uri: Some("https://gateway.example.invalid/oauth/callback".to_string()),
        scopes: Some(vec!["https://wire.example.invalid/read".to_string()]),
        send_resource_parameter: Some(false),
        external_strategy: None,
        authorize_extra: None,
    }
}

fn accounts_config() -> AccountsConfig {
    AccountsConfig {
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "stdio-sole-operator-tests".to_string(),
        store_dir: std::path::PathBuf::from("/synthetic/fixture/accounts/records"),
        authority_dir: std::path::PathBuf::from("/synthetic/fixture/accounts/authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: Some(BTreeMap::from([(DESCRIPTOR_ID.to_string(), descriptor())])),
        limits: AccountsLimits::default(),
        adapters: Vec::new(),
        hosted: None,
    }
}

/// A named, digest-backed API key — never a plaintext one.
fn api_key(name: &str, secret: &[u8]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret)),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// The production sequence: real install, then a real resolve against the
/// one declared, never-connected descriptor. Returns the refusal text.
async fn resolve_under(mode: ServeMode, auth: AuthConfig, caller: CallerProof<'_>) -> String {
    let root = tempfile::TempDir::new().expect("fixture tempdir");
    let custody = empty_custody(root.path());
    let config = Config {
        auth,
        accounts: Some(accounts_config()),
        ..Config::default()
    };
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    install_account_strategies(&config, Some(&custody), &gateway_key, &meta, mode)
        .expect("install must accept this fixture configuration");
    let auth_key = format!("oauth:{PROVIDER}");
    match meta
        .account_strategies()
        .resolve(DESCRIPTOR_ID, &auth_key, caller)
        .await
    {
        Ok(_) => panic!("no grant is seeded; resolve must refuse"),
        Err(error) => error.to_string(),
    }
}

#[tokio::test]
async fn stdio_caller_with_auth_off_is_the_sole_operator() {
    let auth = AuthConfig {
        enabled: false,
        bearer_token: None,
        api_keys: Vec::new(),
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
    };
    let caller = CallerProof::new(
        None,
        CallerProvenance::classify(Some(STDIO_CREDENTIAL_PRINCIPAL)),
    );
    let error = resolve_under(ServeMode::Stdio, auth, caller).await;
    assert!(
        error.contains("no connected account (fail-closed)"),
        "stdio with auth off must be served as the sole operator, \
         reaching custody's own absence refusal rather than a missing-identity one; got: {error}"
    );
    assert!(
        !error.contains("carries no verified end-user identity"),
        "a stdio caller structurally cannot present a verified identity and must never be \
         asked for one; got: {error}"
    );
}

#[tokio::test]
async fn http_multiple_api_keys_never_asserts_sole_operator() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            api_key("keyA", b"scoped-key-a"),
            api_key("keyB", b"scoped-key-b"),
        ],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: true,
    };
    let caller = CallerProof::new(None, CallerProvenance::classify(Some("validated-api-key")));
    let error = resolve_under(ServeMode::Http, auth, caller).await;
    assert!(
        error.contains("carries no verified end-user identity"),
        "two configured API keys must never share stored OAuth grants under one sole-operator \
         principal, over http or over stdio; got: {error}"
    );
    assert!(
        !error.contains("no connected account (fail-closed)"),
        "a multi-key gateway must refuse before ever attempting a mint; got: {error}"
    );
}
