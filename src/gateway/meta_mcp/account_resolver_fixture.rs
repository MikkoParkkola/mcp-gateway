// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture for the managed-account consumer tests: a REAL isolated store, the
//! REAL `AccountService`/`CustodyHandle`, the REAL shared compile/install
//! helpers, the REAL dispatch entry (`MetaMcp::code_mode_execute` ->
//! `invoke_tool` -> `resolve_caller_credential` -> `Backend::request_with_headers`),
//! and exactly one faked seam — the `RefreshProvider` round trip.
//!
//! THE PRODUCTION APIS, NOT INVENTED ONES. A backend binding is compiled by
//! `config::account_bindings::compile(&Config)` and applied with
//! `BoundAccountBackend::effective(&BackendConfig)`; the strategy is installed
//! by `gateway::server::account_bindings::install_account_strategies`. Those are
//! the same two calls the real `Gateway` makes. Nothing here compiles a managed
//! propagation config of its own and nothing constructs a `VaultStrategy` in a
//! positive fixture.
//!
//! WHY DISPATCH AND NOT THE PUBLIC RESOLVER. `gateway_invoke` calls
//! `resolve_caller_credential` DIRECTLY; the public wrapper is a SECOND entry to
//! the same helper. Every case here drives `code_mode_execute` and asserts on
//! what reached the transport.
//!
//! WHAT IS REAL. `PersonalAccountStore::initialize` writes a real sealed store
//! into a `TempDir`; `CustodyHandle::start` opens it and claims its two
//! exclusive locks; `refresh_if_expired` and `release` are the production ones,
//! so the five-field key, the version CAS, the lease recheck and the release
//! observer all run unmodified.
//!
//! WHAT IS FAKED, AND WHY ONLY THIS. `GatewayRefreshProvider` needs a network
//! issuer. Custody is generic over `P: RefreshProvider`, so a deterministic
//! `ScriptedProvider` is installed at that generic parameter — the same seam
//! `worker_tests.rs` and `service_tests.rs` use. It returns a rotated token and
//! nothing else.
//!
//! LIMITS, STATED PLAINLY. The `VerifiedIdentity` values below are fixture
//! identities handed to the dispatch entry directly: this module proves the
//! shared compile/install path and real dispatch, NOT public gateway startup and
//! NOT the OIDC wire that would produce such an identity. The `accounts` store
//! settings in the `Config` are synthetic and are never opened by anything here
//! — compile and install read the `descriptors` map only, and custody is the
//! separately started real fixture custody handed in as `Option<&Arc<dyn
//! AccountCustody>>`. No claim is made that the gateway opened that store.
//!
//! NO SLEEPS, NO NETWORK, NO ENV READS. Expiry is `expires_at` in the seeded
//! record (`0` = already expired, `u64::MAX` = not expiring). The revocation
//! race uses the explicit barrier in `account_resolver_gate.rs`. The descriptor
//! `client_secret_ref` stays an unresolved `env:` reference. Every token and key
//! value here is synthetic.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::account_bindings::compile;
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::oauth::GatewayKeyPair;
use crate::gateway::server::account_bindings::install_account_strategies;
use crate::identity_propagation::{IdentityPropagationConfig, PropagationStrategyKind};
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::CustodyHandle;
use crate::personal_accounts::config::{
    AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
};
use crate::personal_accounts::identity::AccountDescriptor as AccountKeyDescriptor;
use crate::personal_accounts::{
    AccountCustody, AccountKey, GrantRecord, PersonalAccountStore, StoreConfig,
};
use crate::personal_accounts::{
    CredentialLease, CredentialReleaseObserver, ProviderRefreshError, RefreshProvider,
    ReleasedCredentials, TokenRefresh,
};

/// Store sealing key. Synthetic, fixed, and never a deployment value.
const STORE_KEY: [u8; 32] = [0x71; 32];

pub(super) const INBOUND_ISSUER: &str = "https://identity.example";
pub(super) const OAUTH_ISSUER: &str = "https://accounts.google.invalid";

/// The two descriptor ids. Both are provider `google`.
pub(super) const WORK: &str = "work-gmail";
pub(super) const PERSONAL: &str = "personal-gmail";

/// ONE resource for BOTH descriptors, on purpose. With distinct resources a
/// separation assertion can pass because the RESOURCE differed; here the
/// descriptor id is the only field that differs between the two accounts, and
/// the subject is the only field that differs between the two principals.
pub(super) const SHARED_RESOURCE: &str = "https://www.googleapis.invalid/drive/v3";

/// Synthetic seeded tokens. Distinct per (principal, descriptor) so a crossed
/// credential is visible in the assertion rather than inferred.
pub(super) const ALICE_WORK_TOKEN: &str = "synthetic-alice-work-access-3f81a2";
pub(super) const BOB_WORK_TOKEN: &str = "synthetic-bob-work-access-7c24de";
pub(super) const ALICE_PERSONAL_TOKEN: &str = "synthetic-alice-personal-access-b19042";
pub(super) const ROTATED_TOKEN: &str = "synthetic-alice-work-rotated-e5c730";

/// A static Authorization header, carried ONLY by the non-managed backend in
/// the mixed case. A managed backend never carries one: `compile` refuses
/// `account` beside a static Authorization, so a fixture that set one would be
/// testing a configuration that cannot exist. The no-fallback proof for managed
/// backends is ZERO backend calls on refusal.
pub(super) const STATIC_FALLBACK: &str = "Bearer synthetic-shared-gateway-static-token";

/// The grant authority every seeded record carries. These three values, plus the
/// token revision, are what `vault::cache_binding` publishes beside the account
/// digest, so the fixture must state them to format an expected pool key.
pub(super) const GENERATION: &str = "abcdef0123456789abcdef0123456789";
pub(super) const AUTHORIZATION_EPOCH: u64 = 1;
/// The revision a seeded grant starts at; a refresh commits revision 2.
pub(super) const SEEDED_REVISION: u64 = 1;
pub(super) const REFRESHED_REVISION: u64 = 2;

/// Display fields are IDENTICAL for every principal. `email`/`name` are mutable
/// labels and must not enter the account key; making them equal means a binding
/// that read one would hand both principals the same account, and the token
/// assertions below would fail. The SUBJECT is the separation source.
const DISPLAY_EMAIL: &str = "shared-display@display.invalid";
const DISPLAY_NAME: &str = "Shared Display Name";

/// 64 zeros, matching the descriptor-revision width the store commits.
pub(super) fn descriptor_revision() -> String {
    "0".repeat(64)
}

/// A fixture identity. Supplied to the dispatch entry directly: this is a
/// FIXTURE principal, not a token this module verified.
pub(super) fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: DISPLAY_EMAIL.to_string(),
        name: Some(DISPLAY_NAME.to_string()),
        groups: vec!["everyone".to_string()],
        issuer: INBOUND_ISSUER.to_string(),
    }
}

/// A structurally complete `personal_managed` descriptor, with the same field
/// set the existing config tests use. Values are synthetic `.invalid` hosts and
/// the client secret stays an unresolved `env:` reference.
pub(super) fn descriptor(id: &str) -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_string(),
        resource: Some(SHARED_RESOURCE.to_string()),
        issuer: Some(OAUTH_ISSUER.to_string()),
        authorization_endpoint: Some(format!("{OAUTH_ISSUER}/o/oauth2/v2/auth")),
        token_endpoint: Some(format!("{OAUTH_ISSUER}/token")),
        revocation_endpoint: None,
        client_id: Some(format!("synthetic-google-client-{id}")),
        client_secret_ref: Some("env:FIXTURE_ACCOUNT_CLIENT_SECRET".to_string()),
        redirect_uri: Some("https://gateway.example.invalid/oauth/callback".to_string()),
        scopes: Some(vec![
            "https://www.googleapis.com/auth/drive.readonly".to_string(),
        ]),
        send_resource_parameter: Some(false),
        external_strategy: None,
    }
}

/// The account-key descriptor `compile` derives from the configured one. Built
/// here only to SEED the store and to format the expected pool binding; the
/// consumer under test derives its own from the installed strategy.
pub(super) fn key_descriptor(id: &str) -> AccountKeyDescriptor {
    AccountKeyDescriptor {
        descriptor_id: id.to_string(),
        provider: "google".to_string(),
        resource: SHARED_RESOURCE.to_string(),
        issuer: OAUTH_ISSUER.to_string(),
    }
}

/// The five-field key exactly as `identity::account_key` builds it.
pub(super) fn account_key(subject: &str, id: &str) -> AccountKey {
    crate::personal_accounts::identity::account_key(Some(&identity(subject)), &key_descriptor(id))
        .expect("fixture principal and descriptor must bind")
}

/// The AUTHORITY-BEARING binding `vault::cache_binding` produces:
/// `acct:v1:{digest}:{gen_len}:{generation}:{epoch}:{token_revision}:{rev_len}:{descriptor_revision}`.
///
/// Formatting it is a fixture prerequisite for seeding the per-user pool slot
/// the real dispatch will select — it is not a second encoder and not a store.
/// The digest comes from the production `AccountKey::digest`, and no token value
/// enters the string. `propagate`/`refresh` are never called to manufacture it.
pub(super) fn expected_identity_key(subject: &str, id: &str, token_revision: u64) -> String {
    let digest = account_key(subject, id)
        .digest()
        .expect("fixture account key is well formed");
    let revision = descriptor_revision();
    format!(
        "acct:v1:{digest}:{}:{GENERATION}:{AUTHORIZATION_EPOCH}:{token_revision}:{}:{revision}",
        GENERATION.len(),
        revision.len(),
    )
}

/// A connected grant at [`SEEDED_REVISION`]. `expires_at: u64::MAX` means no
/// refresh is due; a caller wanting the refresh path passes `0`.
pub(super) fn grant(access_token: &str, expires_at: u64) -> GrantRecord {
    GrantRecord {
        generation: GENERATION.to_string(),
        token_revision: SEEDED_REVISION,
        authorization_epoch: AUTHORIZATION_EPOCH,
        descriptor_revision: descriptor_revision(),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: access_token.to_string(),
        refresh_token: Some(format!("{access_token}-refresh")),
        token_type: "Bearer".into(),
        expires_at,
        provider_account_id: Some("synthetic-provider-account-4410".into()),
        client_id: "synthetic-google-client".into(),
    }
}

fn store_config(root: &std::path::Path) -> StoreConfig {
    let root = root.canonicalize().expect("fixture root exists");
    StoreConfig {
        instance_id: "gateway-consumer-tests".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([("current".into(), STORE_KEY.to_vec())]),
        max_entries: 10_000,
        max_authority_bytes: 16_777_216,
    }
}

// ── The one faked seam ────────────────────────────────────────────────────────

/// Deterministic refresh: returns one scripted rotation and counts its calls.
/// No timing, no network, no retry policy — the production
/// `AccountService::refresh_if_expired` owns all of that and is not replaced.
pub(super) struct ScriptedProvider {
    rotated: String,
    calls: Arc<AtomicUsize>,
}

impl RefreshProvider for ScriptedProvider {
    fn refresh(
        &self,
        _account: &AccountKey,
        current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let rotated = TokenRefresh {
            access_token: self.rotated.clone(),
            refresh_token: None,
            // Never broader than what was granted: the service refuses
            // broadening, and this fixture must not smuggle scope past it.
            scopes: Some(current.scopes.clone()),
            token_type: "Bearer".into(),
            expires_at: u64::MAX,
        };
        async move { Ok(rotated) }
    }
}

/// Records every release that passed the real lease recheck, by account key
/// digest. Never records a token: the assertion is that a release HAPPENED,
/// and a fixture holding credential bytes would be the leak it tests for.
#[derive(Default)]
pub(super) struct RecordingObserver {
    released: Mutex<Vec<String>>,
}

impl CredentialReleaseObserver for RecordingObserver {
    fn on_release(
        &self,
        account: &AccountKey,
        _lease: &CredentialLease,
        _credentials: &ReleasedCredentials,
    ) {
        self.released
            .lock()
            .push(account.digest().expect("released key is well formed"));
    }
}

impl CredentialReleaseObserver for Arc<RecordingObserver> {
    fn on_release(
        &self,
        account: &AccountKey,
        lease: &CredentialLease,
        credentials: &ReleasedCredentials,
    ) {
        (**self).on_release(account, lease, credentials);
    }
}

// ── Real custody ──────────────────────────────────────────────────────────────

/// Everything a test holds onto: the real custody handle, the provider call
/// counter, and the release record.
pub(super) struct Custody {
    pub(super) handle: Arc<CustodyHandle<ScriptedProvider, Arc<RecordingObserver>>>,
    refresh_calls: Arc<AtomicUsize>,
    observer: Arc<RecordingObserver>,
    /// Kept alive: dropping it removes the store directory under the locks.
    _root: tempfile::TempDir,
}

impl Custody {
    /// How many releases passed the real recheck.
    pub(super) fn releases(&self) -> usize {
        self.observer.released.lock().len()
    }

    pub(super) fn refreshes(&self) -> usize {
        self.refresh_calls.load(Ordering::SeqCst)
    }

    /// The production custody, type-erased exactly as the real gateway caller
    /// erases its own `GatewayCustody` before installing. The SAME handle — no
    /// second store, service or authorization path.
    pub(super) fn installed(&self) -> Arc<dyn AccountCustody> {
        Arc::clone(&self.handle) as Arc<dyn AccountCustody>
    }
}

/// Seed a real store with the given grants, then open real custody over it.
pub(super) fn custody_with(seed: &[(AccountKey, GrantRecord)]) -> Custody {
    custody_with_rotation(seed, ROTATED_TOKEN)
}

/// As [`custody_with`], with the scripted rotation chosen.
pub(super) fn custody_with_rotation(seed: &[(AccountKey, GrantRecord)], rotated: &str) -> Custody {
    let root = tempfile::TempDir::new().expect("fixture tempdir");
    let config = store_config(root.path());

    // Real store, written and closed before custody claims it — the same order
    // `worker_tests.rs` seeds in, so custody opens a store it did not create.
    let store = PersonalAccountStore::initialize(config.clone()).expect("store initialize");
    for (account, record) in seed {
        store.commit_grant(account, record).expect("seed grant");
    }
    drop(store);

    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let observer = Arc::new(RecordingObserver::default());
    let handle = CustodyHandle::start(
        config,
        ScriptedProvider {
            rotated: rotated.to_string(),
            calls: Arc::clone(&refresh_calls),
        },
        Arc::clone(&observer),
        4,
    )
    .expect("custody must start over the seeded store");

    Custody {
        handle: Arc::new(handle),
        refresh_calls,
        observer,
        _root: root,
    }
}

// ── Dispatch capture ──────────────────────────────────────────────────────────

/// One observed backend call.
#[derive(Clone, Debug)]
pub(super) struct Dispatch {
    pub(super) headers: Vec<(String, String)>,
    pub(super) identity_key: Option<String>,
}

impl Dispatch {
    pub(super) fn authorization(&self) -> Option<String> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
    }
}

/// Every dispatch this gateway made, in order. A refusal is proved by
/// `count() == 0` — an OBSERVED absence of backend calls, not an unread buffer.
#[derive(Default)]
pub(super) struct Dispatches {
    calls: Mutex<Vec<Dispatch>>,
}

impl Dispatches {
    pub(super) fn count(&self) -> usize {
        self.calls.lock().len()
    }

    pub(super) fn calls(&self) -> Vec<Dispatch> {
        self.calls.lock().clone()
    }

    /// The single dispatch expected by a positive case; panics loudly if the
    /// count is anything else, so "reached transport" is never assumed.
    pub(super) fn only(&self) -> Dispatch {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "expected exactly one backend call");
        calls.into_iter().next().expect("checked above")
    }
}

struct CapturingTransport {
    dispatches: Arc<Dispatches>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for CapturingTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        // Recorded too: a dispatch that carried NO per-request headers is still
        // a backend call, and a refusal must not produce one by either door.
        self.dispatches.calls.lock().push(Dispatch {
            headers: Vec::new(),
            identity_key: None,
        });
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}]}),
        ))
    }

    async fn request_with_headers(
        &self,
        _method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.dispatches.calls.lock().push(Dispatch {
            headers: extra_headers.to_vec(),
            identity_key: identity_key.map(str::to_string),
        });
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}]}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

#[path = "account_resolver_gateway.rs"]
mod gateway;
pub(super) use gateway::{Bind, Descriptors, execute, external_cfg, gateway, slots};
