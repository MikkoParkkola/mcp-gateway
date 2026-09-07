// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Account-service acceptance harness, and the two synchronous lease cases.
//!
//! The fixtures live here because every case file below needs them. Each
//! submodule owns one behaviour of the service and nothing else; splitting them
//! keeps every file inside the size cap and keeps a failure's name honest about
//! what broke.

use std::collections::{BTreeMap, HashMap};
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::personal_accounts::StoreConfig;
use crate::personal_accounts::consent::{GuardedCommit, GuardedCommitError};

use super::{
    AccountError, AccountKey, AccountLookup, AccountService, AccountServiceError,
    ConsentExpectation, CredentialLease, CredentialReleaseObserver, GrantRecord, GrantVersion,
    PersonalAccountStore, ProviderRefreshError, RefreshProvider, ReleasedCredentials, TokenRefresh,
};

const KEY: [u8; 32] = [0x51; 32];

/// Bounds a failure only. Every wait in this suite is released by a causal
/// event; the timeout exists so a missing event fails the case instead of
/// hanging the suite.
const DEADLOCK: Duration = Duration::from_secs(5);

fn alice() -> AccountKey {
    AccountKey {
        principal_authority: "https://identity.example".into(),
        principal_subject: "alice".into(),
        backend_id: "google-workspace".into(),
        resource: "https://www.googleapis.com/drive/v3".into(),
        oauth_issuer: "https://accounts.google.com".into(),
    }
}

fn bob() -> AccountKey {
    AccountKey {
        principal_subject: "bob".into(),
        ..alice()
    }
}

/// Alice's subject at a different principal authority. The four constructors
/// below each move exactly one non-subject field, so a partition keyed on
/// anything less than the whole tuple fails on one of them.
fn alice_other_authority() -> AccountKey {
    AccountKey {
        principal_authority: "https://other-identity.example".into(),
        ..alice()
    }
}

fn alice_other_backend() -> AccountKey {
    AccountKey {
        backend_id: "microsoft-graph".into(),
        ..alice()
    }
}

fn alice_other_resource() -> AccountKey {
    AccountKey {
        resource: "https://www.googleapis.com/calendar/v3".into(),
        ..alice()
    }
}

fn alice_other_issuer() -> AccountKey {
    AccountKey {
        oauth_issuer: "https://login.microsoftonline.com/common/v2.0".into(),
        ..alice()
    }
}

/// Every account key that differs from alice in exactly one field, named for
/// the field it moves. A case iterating this cannot forget one.
fn one_field_apart() -> [(&'static str, AccountKey); 5] {
    [
        ("principal_authority", alice_other_authority()),
        ("principal_subject", bob()),
        ("backend_id", alice_other_backend()),
        ("resource", alice_other_resource()),
        ("oauth_issuer", alice_other_issuer()),
    ]
}

/// A distinct generation per one-field-apart account, so a record written or
/// read under the wrong account key is visible as such.
const VARIANT_GENERATION: [&str; 5] = [
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
    "44444444444444444444444444444444",
    "55555555555555555555555555555555",
];

/// The one-field-apart accounts, each holding its own distinct grant.
fn one_field_apart_grants() -> Vec<(AccountKey, GrantRecord)> {
    one_field_apart()
        .into_iter()
        .zip(VARIANT_GENERATION)
        .map(|((_, account), generation)| (account, grant_gen(generation)))
        .collect()
}

/// An account the store has never held, for the cases that must show a lease is
/// refused rather than answered from absence.
fn mallory() -> AccountKey {
    AccountKey {
        principal_subject: "mallory".into(),
        ..alice()
    }
}

fn grant() -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: "synthetic-alice-access-private-material-9f3a71".into(),
        refresh_token: Some("synthetic-alice-refresh-private-material-8c9d21".into()),
        token_type: "Bearer".into(),
        expires_at: 0,
        provider_account_id: Some("synthetic-alice-provider-account-private-1a92".into()),
        client_id: "synthetic-google-client".into(),
    }
}

/// The same grant with an expiry no clock reaches, so "expired" is never an
/// accident of when the suite runs.
fn unexpired_grant() -> GrantRecord {
    GrantRecord {
        expires_at: u64::MAX,
        ..grant()
    }
}

fn bob_grant() -> GrantRecord {
    GrantRecord {
        generation: "0123456789abcdef0123456789abcdef".into(),
        access_token: "synthetic-bob-access-private-material-4e2b18".into(),
        refresh_token: Some("synthetic-bob-refresh-private-material-7a1c44".into()),
        provider_account_id: Some("synthetic-bob-provider-account-private-3c07".into()),
        ..grant()
    }
}

fn grant_gen(generation: &str) -> GrantRecord {
    GrantRecord {
        generation: generation.into(),
        access_token: format!("synthetic-access-{generation}"),
        refresh_token: Some(format!("synthetic-refresh-{generation}")),
        ..grant()
    }
}

fn metadata_scope() -> String {
    "https://www.googleapis.com/auth/drive.metadata.readonly".into()
}

fn full_drive_scope() -> String {
    "https://www.googleapis.com/auth/drive".into()
}

fn config(root: &std::path::Path) -> StoreConfig {
    let root = root
        .canonicalize()
        .expect("fixture root is an existing directory");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([("current".into(), KEY.to_vec())]),
        max_entries: 10_000,
        max_authority_bytes: 16_777_216,
    }
}

fn expected_lease(account: AccountKey, record: &GrantRecord) -> CredentialLease {
    CredentialLease {
        account,
        generation: record.generation.clone(),
        authorization_epoch: record.authorization_epoch,
        scopes: record.scopes.clone(),
        descriptor_revision: record.descriptor_revision.clone(),
        token_revision: record.token_revision,
    }
}

fn expected_credentials(record: &GrantRecord) -> ReleasedCredentials {
    ReleasedCredentials {
        access_token: record.access_token.clone(),
        token_type: record.token_type.clone(),
    }
}

fn expected_version(record: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

/// The scaffold's refusal is not an answer. Every case routes its results
/// through this, so a service that merely refuses can never look like a pass.
#[track_caller]
fn refuse_scaffold<T>(
    result: Result<T, AccountServiceError>,
    what: &str,
) -> Result<T, AccountServiceError> {
    match result {
        Err(AccountServiceError::RuntimeNotImplemented) => {
            panic!("{what}: RuntimeNotImplemented is the refusing scaffold, not a domain outcome")
        }
        other => other,
    }
}

#[track_caller]
fn domain_err<T>(result: Result<T, AccountServiceError>, what: &str) -> AccountServiceError {
    refuse_scaffold(result, what).err().expect(what)
}

/// The same rule one layer down, for the guarded store entrypoint.
#[track_caller]
fn refuse_guarded_scaffold(
    result: Result<GuardedCommit, GuardedCommitError>,
    what: &str,
) -> Result<GuardedCommit, GuardedCommitError> {
    match result {
        Err(GuardedCommitError::RuntimeNotImplemented) => {
            panic!("{what}: the guarded store entrypoint is a scaffold, not a domain outcome")
        }
        other => other,
    }
}

fn lookup_kind(lookup: &AccountLookup) -> &'static str {
    match lookup {
        AccountLookup::Absent => "absent",
        AccountLookup::Connected(_) => "connected",
        AccountLookup::Revoked(_) => "revoked",
        AccountLookup::ReconnectRequired(_) => "reconnect-required",
    }
}

#[track_caller]
fn expect_connected(lookup: AccountLookup) -> GrantRecord {
    match lookup {
        AccountLookup::Connected(record) => record,
        other => panic!("expected connected, got {}", lookup_kind(&other)),
    }
}

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(fut)
}

async fn reached<F: Future>(fut: F, boundary: &'static str) -> F::Output {
    tokio::time::timeout(DEADLOCK, fut)
        .await
        .unwrap_or_else(|_| panic!("{boundary} not reached within deadlock bound"))
}

/// Signals the first time the wrapped future is polled to Pending.
///
/// A spawned task that has not been polled has not entered the code under test,
/// so an assertion made before that point measures the scheduler rather than
/// the service.
struct FirstPending<F> {
    inner: Pin<Box<F>>,
    signal: Option<oneshot::Sender<()>>,
}

impl<F: Future> Future for FirstPending<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let polled = this.inner.as_mut().poll(cx);
        if polled.is_pending() {
            if let Some(signal) = this.signal.take() {
                let _ = signal.send(());
            }
        }
        polled
    }
}

fn first_pending<F: Future>(inner: F) -> (FirstPending<F>, oneshot::Receiver<()>) {
    let (signal, observed) = oneshot::channel();
    (
        FirstPending {
            inner: Box::pin(inner),
            signal: Some(signal),
        },
        observed,
    )
}

fn seed(accounts: &[(&AccountKey, GrantRecord)]) -> (tempfile::TempDir, PersonalAccountStore) {
    let tmp = tempfile::TempDir::new().expect("personal account fixture root");
    let store = PersonalAccountStore::initialize(config(tmp.path())).expect("initialize store");
    for (account, record) in accounts {
        store
            .commit_grant(account, record)
            .expect("seed connected grant");
    }
    (tmp, store)
}

/// The sealed record files under a fixture root, sorted. The authority manifest
/// and the lock file live elsewhere, so anything returned here is a candidate.
fn record_files(tmp: &tempfile::TempDir) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(config(tmp.path()).store_dir)
        .expect("record directory")
        .map(|entry| entry.expect("record directory entry").path())
        .filter(|path| path.extension().is_some_and(|suffix| suffix == "json"))
        .collect();
    paths.sort();
    paths
}

fn counting_observer() -> (CountingObserver, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        CountingObserver {
            calls: Arc::clone(&calls),
        },
        calls,
    )
}

fn rotation(access: &'static str, scopes: Option<Vec<String>>) -> TokenRefresh {
    TokenRefresh {
        access_token: access.into(),
        refresh_token: Some(format!("{access}-refresh")),
        scopes,
        token_type: "Bearer".into(),
        expires_at: u64::MAX,
    }
}

struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

impl RefreshProvider for CountingProvider {
    fn refresh(
        &self,
        _account: &AccountKey,
        _current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        future::ready(Err(ProviderRefreshError::Unavailable))
    }
}

struct CountingObserver {
    calls: Arc<AtomicUsize>,
}

impl CredentialReleaseObserver for CountingObserver {
    fn on_release(
        &self,
        _account: &AccountKey,
        _lease: &CredentialLease,
        _credentials: &ReleasedCredentials,
    ) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

struct AccountScript {
    calls: Arc<AtomicUsize>,
    result: Result<TokenRefresh, ProviderRefreshError>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

/// Scripts keyed by the COMPLETE account key digest, never by subject. A
/// harness keyed on one field cannot observe a service that partitions on one
/// field: both would agree, and both would be wrong.
struct ScriptedProvider {
    scripts: Mutex<HashMap<String, AccountScript>>,
}

impl ScriptedProvider {
    fn new() -> Self {
        Self {
            scripts: Mutex::new(HashMap::new()),
        }
    }

    fn script_key(account: &AccountKey) -> String {
        account
            .digest()
            .expect("fixture account key is well formed")
    }

    fn ready(
        &self,
        account: &AccountKey,
        result: Result<TokenRefresh, ProviderRefreshError>,
    ) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        self.scripts.lock().expect("script lock").insert(
            Self::script_key(account),
            AccountScript {
                calls: Arc::clone(&calls),
                result,
                entered: None,
                release: None,
            },
        );
        calls
    }

    fn hold(
        &self,
        account: &AccountKey,
        result: Result<TokenRefresh, ProviderRefreshError>,
    ) -> (Arc<AtomicUsize>, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        self.scripts.lock().expect("script lock").insert(
            Self::script_key(account),
            AccountScript {
                calls: Arc::clone(&calls),
                result,
                entered: Some(entered_tx),
                release: Some(release_rx),
            },
        );
        (calls, entered_rx, release_tx)
    }
}

impl RefreshProvider for ScriptedProvider {
    fn refresh(
        &self,
        account: &AccountKey,
        _current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        let mut scripts = self.scripts.lock().expect("script lock");
        let script = scripts
            .get_mut(&Self::script_key(account))
            .expect("provider has an independent script per complete account key");
        script.calls.fetch_add(1, Ordering::SeqCst);
        let entered = script.entered.take();
        let release = script.release.take();
        let result = script.result.clone();
        drop(scripts);
        async move {
            if let Some(tx) = entered {
                let _ = tx.send(());
            }
            if let Some(rx) = release {
                let _ = rx.await;
            }
            result
        }
    }
}

struct Fixture {
    tmp: tempfile::TempDir,
    service: AccountService<CountingProvider, CountingObserver>,
    provider_calls: Arc<AtomicUsize>,
    observer_calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn connected_alice() -> Self {
        Self::seeded(&[(&alice(), grant())])
    }

    fn seeded(accounts: &[(&AccountKey, GrantRecord)]) -> Self {
        let (tmp, store) = seed(accounts);
        Self::wrap(tmp, store)
    }

    fn wrap(tmp: tempfile::TempDir, store: PersonalAccountStore) -> Self {
        let provider_calls = Arc::new(AtomicUsize::new(0));
        let observer_calls = Arc::new(AtomicUsize::new(0));
        let service = AccountService::new(
            store,
            CountingProvider {
                calls: Arc::clone(&provider_calls),
            },
            CountingObserver {
                calls: Arc::clone(&observer_calls),
            },
        );
        Self {
            tmp,
            service,
            provider_calls,
            observer_calls,
        }
    }

    #[track_caller]
    fn assert_quiet(&self, what: &str) {
        assert_eq!(
            self.provider_calls.load(Ordering::SeqCst),
            0,
            "{what}: the provider must not be contacted"
        );
        assert_eq!(
            self.observer_calls.load(Ordering::SeqCst),
            0,
            "{what}: no credential may be published"
        );
    }
}

#[test]
fn connected_resolve_binds_exact_lease_and_release_notifies_once() {
    let fx = Fixture::connected_alice();
    let record = grant();
    let lease = fx
        .service
        .resolve(&alice())
        .expect("connected principal resolves");
    assert_eq!(lease, expected_lease(alice(), &record));

    let credentials = fx
        .service
        .release(&lease)
        .expect("connected lease releases");
    assert_eq!(credentials, expected_credentials(&record));
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        fx.service.resolve(&bob()),
        Err(AccountServiceError::ConnectOffer)
    );
    assert_eq!(fx.provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn invalidate_revokes_durably_and_retires_prior_lease() {
    let fx = Fixture::connected_alice();
    let record = grant();
    let lease = fx
        .service
        .resolve(&alice())
        .expect("lease acquired before invalidate");
    fx.service
        .release(&lease)
        .expect("release succeeds before invalidate");
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);

    fx.service
        .invalidate(&alice())
        .expect("invalidate durably revokes");
    assert_eq!(
        fx.service.release(&lease),
        Err(AccountServiceError::LeaseRetired)
    );
    assert_eq!(
        fx.service.resolve(&alice()),
        Err(AccountServiceError::Revoked)
    );
    assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fx.provider_calls.load(Ordering::SeqCst), 0);

    let Fixture {
        tmp,
        service,
        observer_calls,
        provider_calls,
    } = fx;
    drop(service);
    let store = PersonalAccountStore::open(config(tmp.path())).expect("reopen after drop");
    assert_eq!(
        store.lookup(&alice()).expect("revoked lookup"),
        AccountLookup::Revoked(expected_version(&record))
    );
    assert_eq!(observer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
}

#[path = "service_refresh_tests.rs"]
mod service_refresh_tests;

#[path = "service_singleflight_tests.rs"]
mod service_singleflight_tests;

#[path = "service_provider_tests.rs"]
mod service_provider_tests;

#[path = "service_release_tests.rs"]
mod service_release_tests;

#[path = "service_consent_tests.rs"]
mod service_consent_tests;
