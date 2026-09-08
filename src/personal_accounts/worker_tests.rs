// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reuses the grant fixture shape and the single-flight mechanics of the
//! approved service tests. The frozen `service_tests.rs` is not modified and
//! nothing is removed from it.
//!
//! Every wait here is released by an event: a provider entry, a first Pending
//! poll, or a stalled REAL store operation. Timeouts bound failures only. No
//! sleeps.
//!
//! Off-the-event-loop claims are pinned by `super::store_probe`, which records
//! and stalls INSIDE the store operation itself. A wrapper that never reaches
//! the store records nothing here, so an empty closure cannot manufacture an
//! event.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::oneshot;

use super::*;
use crate::personal_accounts::service::{ProviderRefreshError, TokenRefresh};
use crate::personal_accounts::store_probe::{self, StoreOp};
// `AccountServiceError`, `ConsentExpectation` and `GrantRecord` arrive through
// the parent glob above, which is where `worker.rs` already imports them.
use crate::personal_accounts::{AccountLookup, PersonalAccountStore};

const KEY: [u8; 32] = [0x51; 32];
const DEADLOCK: Duration = Duration::from_secs(5);

/// Serialises the worker tests against each other.
///
/// Store-directory scoping keeps OTHER modules' stores out of a recording, and
/// every test here builds its own `TempDir`. This lock keeps THIS module
/// single-file-at-a-time, so a non-recording worker test cannot be swallowed by
/// a recording one's stall.
///
/// Deliberately a different lock from `store_probe`'s own serialisation, and
/// always taken FIRST: a test takes this, then `watch` takes the probe lock.
/// One direction only, so the pair cannot deadlock.
static WORKER_TESTS: Mutex<()> = Mutex::new(());

/// Held for the whole test, taken before any runtime or fixture exists.
fn worker_test_lock() -> MutexGuard<'static, ()> {
    WORKER_TESTS.lock().unwrap_or_else(PoisonError::into_inner)
}

#[track_caller]
fn refuse_scaffold<T>(result: Result<T, CustodyError>, what: &str) -> Result<T, CustodyError> {
    match result {
        Err(CustodyError::RuntimeNotImplemented) => {
            panic!("{what}: RuntimeNotImplemented is the scaffold, not a domain outcome")
        }
        other => other,
    }
}

#[track_caller]
fn domain_err<T>(result: Result<T, CustodyError>, what: &str) -> CustodyError {
    refuse_scaffold(result, what).err().expect(what)
}

fn alice() -> AccountKey {
    AccountKey {
        principal_authority: "https://identity.example".into(),
        principal_subject: "alice".into(),
        backend_id: "google-workspace-personal".into(),
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

fn digest(account: &AccountKey) -> String {
    account
        .digest()
        .expect("fixture account key is well formed")
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

fn unexpired() -> GrantRecord {
    GrantRecord {
        expires_at: u64::MAX,
        ..grant()
    }
}

fn config(root: &std::path::Path) -> StoreConfig {
    let root = root.canonicalize().expect("fixture root exists");
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

fn seed(root: &std::path::Path, accounts: &[(&AccountKey, GrantRecord)]) {
    let store = PersonalAccountStore::initialize(config(root)).expect("initialize");
    for (account, record) in accounts {
        store.commit_grant(account, record).expect("seed grant");
    }
    drop(store);
}

#[track_caller]
fn expect_connected(lookup: AccountLookup) -> GrantRecord {
    match lookup {
        AccountLookup::Connected(record) => record,
        other => panic!("expected a connected account, got {other:?}"),
    }
}

/// Signals the first time the wrapped future is polled to Pending.
///
/// The approved single-flight test's mechanic: a task that has not been polled
/// has not reached the code under test, so an assertion made before that point
/// measures the scheduler rather than the service.
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

/// Shared provider state the test keeps a handle to. The `CustodyHandle` owns
/// the `RefreshProvider`; the test owns this.
#[derive(Default)]
struct ProviderState {
    calls: Mutex<Vec<String>>,
    gates: Mutex<HashMap<String, (oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

impl ProviderState {
    /// Hold this account's provider call until released.
    fn hold(&self, account: &AccountKey) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.gates
            .lock()
            .expect("gate lock")
            .insert(digest(account), (entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    fn call_count(&self, account: &AccountKey) -> usize {
        let key = digest(account);
        self.calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|call| **call == key)
            .count()
    }
}

struct GatedProvider {
    state: Arc<ProviderState>,
}

impl RefreshProvider for GatedProvider {
    fn refresh(
        &self,
        account: &AccountKey,
        current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        let key = digest(account);
        self.state.calls.lock().expect("calls").push(key.clone());
        // Taken by value, so the entry signal fires from inside the future.
        let gate = self.state.gates.lock().expect("gate lock").remove(&key);
        let rotated = TokenRefresh {
            access_token: format!("synthetic-rotated-{}", &key[..8]),
            refresh_token: None,
            scopes: Some(current.scopes.clone()),
            token_type: "Bearer".into(),
            expires_at: u64::MAX,
        };
        async move {
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.await;
            }
            Ok(rotated)
        }
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

struct Fixture {
    handle: Arc<CustodyHandle<GatedProvider, CountingObserver>>,
    provider: Arc<ProviderState>,
    observer_calls: Arc<AtomicUsize>,
}

fn start(root: &std::path::Path, capacity: usize) -> Fixture {
    let provider = Arc::new(ProviderState::default());
    let observer_calls = Arc::new(AtomicUsize::new(0));
    let handle = CustodyHandle::start(
        config(root),
        GatedProvider {
            state: Arc::clone(&provider),
        },
        CountingObserver {
            calls: Arc::clone(&observer_calls),
        },
        capacity,
    )
    .expect("custody starts against a seeded store");
    Fixture {
        handle: Arc::new(handle),
        provider,
        observer_calls,
    }
}

fn current_thread<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(fut)
}

fn multi_thread<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("multi-thread runtime")
        .block_on(fut)
}

#[test]
fn a_command_returns_the_real_store_answer() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let lease = refuse_scaffold(fx.handle.resolve(&alice()).await, "positive resolve")
            .expect("a connected account resolves through the handle");
        // The REAL durable answer: every field comes from the seeded record.
        let record = unexpired();
        assert_eq!(lease.account, alice());
        assert_eq!(lease.generation, record.generation);
        assert_eq!(lease.token_revision, record.token_revision);
        assert_eq!(lease.authorization_epoch, record.authorization_epoch);
        assert_eq!(lease.scopes, record.scopes);
        assert_eq!(
            fx.provider.call_count(&alice()),
            0,
            "an unexpired grant needs no provider round trip"
        );

        let credentials = refuse_scaffold(fx.handle.release(&lease).await, "positive release")
            .expect("the lease releases");
        assert_eq!(credentials.access_token, record.access_token);
        assert_eq!(fx.observer_calls.load(Ordering::SeqCst), 1);
        refuse_scaffold(fx.handle.shutdown().await, "shutdown").expect("shutdown completes");
    });
}

/// Shutdown drains in-flight work, refuses new work while draining, and only
/// then releases the store.
///
/// The reopen happens WHILE the handle is still alive. A no-op shutdown cannot
/// pass this: without an actual release, the second `open` fails on the file
/// locks the handle is still holding.
#[test]
fn shutdown_drains_in_flight_work_refuses_new_work_and_frees_the_locks_while_alive() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let (alice_entered, alice_release) = fx.provider.hold(&alice());

        let in_flight = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
        };
        // The refresh is genuinely inside its provider call before shutdown.
        tokio::time::timeout(DEADLOCK, alice_entered)
            .await
            .expect("the provider was entered within the deadlock bound")
            .expect("entry signal");

        // Shutdown must be PROVEN in progress before "new work is refused"
        // means anything: spawning it only guarantees it exists, and a correct
        // implementation may not have been polled yet when the next line runs.
        // A stub that returns Ready never pends, so its signal sender drops and
        // the receive below fails with the explicit message.
        let (shutdown_fut, shutdown_pending) = first_pending({
            let handle = Arc::clone(&fx.handle);
            async move { handle.shutdown().await }
        });
        let shutting_down = tokio::spawn(shutdown_fut);
        tokio::time::timeout(DEADLOCK, shutdown_pending)
            .await
            .expect("shutdown was polled within the deadlock bound")
            .expect(
                "shutdown returned Ready without ever pending: it cannot have drained the \
                 in-flight command that is still held",
            );

        // New work is refused while draining, not queued behind it.
        assert_eq!(
            domain_err(
                fx.handle.resolve(&alice()).await,
                "work submitted during drain"
            ),
            CustodyError::ShuttingDown,
            "shutdown must refuse new work immediately, not accept it"
        );
        // Necessary condition, checked without waiting: in-flight work is still
        // held, so a shutdown that drains cannot have finished.
        assert!(
            !shutting_down.is_finished(),
            "shutdown completed while an in-flight command was still held: it did not drain"
        );

        alice_release
            .send(())
            .expect("the held provider is still waiting");
        let lease = refuse_scaffold(
            in_flight.await.expect("in-flight task"),
            "in-flight refresh during shutdown",
        )
        .expect("a command accepted before shutdown must still complete");
        assert!(lease.token_revision > grant().token_revision);
        refuse_scaffold(
            shutting_down.await.expect("shutdown task"),
            "shutdown after drain",
        )
        .expect("shutdown completes once in-flight work drains");

        // THE PROOF, while the handle is still alive: both file locks are free.
        let reopened = PersonalAccountStore::open(config(tmp.path()))
            .expect("shutdown released both file locks");
        let durable = expect_connected(reopened.lookup(&alice()).expect("readback"));
        assert!(
            durable.token_revision > grant().token_revision,
            "the drained refresh is durable and readable through a fresh store"
        );
        assert_eq!(durable.token_revision, lease.token_revision);
        drop(reopened);

        assert_eq!(
            domain_err(fx.handle.resolve(&alice()).await, "post-shutdown command"),
            CustodyError::ShuttingDown,
            "work after shutdown is refused, never silently queued"
        );
        refuse_scaffold(fx.handle.shutdown().await, "second shutdown")
            .expect("shutdown is idempotent");
    });
}

#[test]
fn a_failed_start_reaches_the_real_lock_boundary_and_yields_no_handle() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    // A live store owns both exclusive locks for its lifetime.
    let holder = PersonalAccountStore::open(config(tmp.path())).expect("first owner");
    let started = CustodyHandle::start(
        config(tmp.path()),
        GatedProvider {
            state: Arc::new(ProviderState::default()),
        },
        CountingObserver {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        4,
    );
    match started {
        Err(CustodyStartError::Store(AccountError::StorageUnavailable)) => {}
        Err(CustodyStartError::RuntimeNotImplemented) => {
            panic!("start must reach the real lock boundary, not refuse as a scaffold")
        }
        Err(other) => panic!("expected the lock boundary, got {other:?}"),
        Ok(_) => panic!("a second owner must not start while the locks are held"),
    }
    drop(holder);

    // The control: once the first owner releases, start succeeds. Without it a
    // start that always fails would pass the case above.
    let fx = start(tmp.path(), 4);
    drop(fx);
}

/// A CURRENT-THREAD runtime is the falsifier: if a synchronous store phase runs
/// on it, nothing else can be polled while that phase is parked.
///
/// The entry wait is `.await`ed, not blocked on. Blocking here would stop the
/// very task trying to enter, and no correct implementation could ever pass.
#[test]
fn store_phases_run_off_the_calling_runtime_thread() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    current_thread(async {
        let fx = start(tmp.path(), 4);
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        // Stalls inside the REAL lookup, past the authority guard. A wrapper
        // that never calls the store never reaches it.
        let mut park = recording.park(StoreOp::Lookup);
        let caller_thread = format!("{:?}", std::thread::current().id());

        let heartbeat = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let heartbeat = Arc::clone(&heartbeat);
            tokio::spawn(async move {
                loop {
                    heartbeat.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            })
        };
        let resolving = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.resolve(&alice()).await })
        };

        // Awaiting lets this single-threaded runtime poll the resolving task.
        park.wait_entered().await;
        let before = heartbeat.load(Ordering::SeqCst);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(
            heartbeat.load(Ordering::SeqCst) > before,
            "the event loop stalled while a real store lookup was held: it ran on the calling runtime"
        );
        park.release();
        refuse_scaffold(resolving.await.expect("resolve task"), "parked resolve")
            .expect("the resolve completes once released");
        ticker.abort();

        assert!(
            recording.ops().contains(&StoreOp::Lookup),
            "resolve must reach the real store lookup; nothing else counts as having resolved"
        );
        assert!(
            !recording.threads().contains(&caller_thread),
            "a real store operation ran on the runtime thread that called it"
        );
        drop(recording);
    });
}

/// Refresh has store work on BOTH sides of the provider call, and both must be
/// off the event loop.
///
/// The operations recorded are the REAL ones: a `Lookup` to read the grant the
/// provider is asked about, and a `RefreshTokens` compare-and-swap to commit
/// the rotation. Neither can be manufactured by a wrapper, and their ORDER is
/// asserted, so an implementation that read after committing fails.
#[test]
fn refresh_runs_its_pre_and_post_provider_store_phases_off_the_caller_thread() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        let caller_thread = format!("{:?}", std::thread::current().id());

        let lease = refuse_scaffold(fx.handle.refresh_if_expired(&alice()).await, "refresh")
            .expect("an expired grant refreshes through the handle");
        assert!(lease.token_revision > grant().token_revision);

        let ops = recording.ops();
        let pre = ops.iter().position(|op| *op == StoreOp::Lookup);
        let post = ops.iter().position(|op| *op == StoreOp::RefreshTokens);
        assert!(
            pre.is_some(),
            "the read before the provider call must reach the real store lookup"
        );
        assert!(
            post.is_some(),
            "the compare-and-swap after the provider call must reach the real store"
        );
        assert!(
            pre < post,
            "the pre-provider read must precede the post-provider commit: {ops:?}"
        );
        for entry in recording.entries() {
            assert_ne!(
                entry.thread, caller_thread,
                "{:?} ran on the calling runtime thread instead of a blocking thread",
                entry.op
            );
        }
        drop(recording);

        // The operations did real work: the rotation is durable and readable.
        refuse_scaffold(fx.handle.shutdown().await, "shutdown").expect("shutdown");
        let reopened = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        let durable = expect_connected(reopened.lookup(&alice()).expect("readback"));
        assert_eq!(durable.token_revision, lease.token_revision);
        assert_eq!(fx.provider.call_count(&alice()), 1);
    });
}

#[test]
fn one_held_provider_does_not_block_a_different_account() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant()), (&bob(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let (alice_entered, alice_release) = fx.provider.hold(&alice());

        let held = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
        };
        tokio::time::timeout(DEADLOCK, alice_entered)
            .await
            .expect("alice provider entered within the deadlock bound")
            .expect("entry signal");

        let bob_lease = refuse_scaffold(
            tokio::time::timeout(DEADLOCK, fx.handle.refresh_if_expired(&bob()))
                .await
                .expect("bob must not wait behind alice's held provider"),
            "independent account refresh",
        )
        .expect("a different account completes while one provider is held");
        assert_eq!(bob_lease.account, bob());
        assert_eq!(fx.provider.call_count(&alice()), 1);

        alice_release
            .send(())
            .expect("alice provider still waiting");
        refuse_scaffold(held.await.expect("alice task"), "held alice refresh")
            .expect("alice completes once released");
    });
}

#[test]
fn the_in_flight_bound_refuses_rather_than_queueing_without_limit() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 1);
        assert_eq!(
            fx.handle.capacity(),
            1,
            "capacity is a constructor argument; the approved schema has no worker-queue field"
        );
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        let mut park = recording.park(StoreOp::Lookup);

        let occupying = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.resolve(&alice()).await })
        };
        // The bound is only occupied once the phase is actually entered.
        park.wait_entered().await;

        assert_eq!(
            domain_err(fx.handle.resolve(&alice()).await, "over the bound"),
            CustodyError::Busy,
            "over the in-flight bound the answer is a typed refusal, never an unbounded queue"
        );
        park.release();
        refuse_scaffold(
            occupying.await.expect("occupying task"),
            "occupying command",
        )
        .expect("the in-flight command still completes");

        // The control: with the bound free again the same call succeeds, so the
        // refusal was capacity and not a permanent failure.
        refuse_scaffold(fx.handle.resolve(&alice()).await, "after the bound frees")
            .expect("capacity refusals are transient");
        drop(recording);
    });
}

/// The two delegating wrappers the handle exposes and nothing else drove:
/// `invalidate` and `commit_grant_if`.
///
/// This is service delegation, not a consent journey: the handle must forward
/// to the one `AccountService` and reach the REAL store, and its outcomes must
/// be the service's own. Three things are pinned together because they are one
/// causal chain — a stale expectation is fenced and writes nothing, a revoke is
/// durable, and a lease taken before the revoke stops releasing afterwards.
#[test]
fn invalidate_and_conditional_commit_delegate_to_the_real_store_off_the_caller_thread() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let recording = store_probe::watch(&config(tmp.path()).store_dir);
        let caller_thread = format!("{:?}", std::thread::current().id());
        let seeded = unexpired();

        // A lease taken while the account is still connected.
        let lease = refuse_scaffold(fx.handle.resolve(&alice()).await, "lease before revoke")
            .expect("a connected account resolves");
        assert_eq!(lease.generation, seeded.generation);

        // STALE conditional commit: the captured expectation says Absent, the
        // store holds a connected grant. Fenced, and nothing written.
        //
        // The delta is taken around THIS CALL ALONE. A stub that always answers
        // StaleConsentFenced without touching the store adds no acquisition and
        // fails here; `ops.contains` could not tell it apart, because `resolve`
        // above already recorded both a Lookup and an acquisition.
        let replacement = GrantRecord {
            generation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            access_token: "synthetic-replacement-access-private-material-77d0".into(),
            ..grant()
        };
        let acquisitions = |recording: &store_probe::Recording| {
            recording
                .ops()
                .iter()
                .filter(|op| **op == StoreOp::AuthorityAcquired)
                .count()
        };
        let before = acquisitions(&recording);
        assert_eq!(
            domain_err(
                fx.handle
                    .commit_grant_if(&alice(), &ConsentExpectation::Absent, &replacement)
                    .await,
                "stale conditional commit",
            ),
            CustodyError::Account(AccountServiceError::StaleConsentFenced),
            "a stale expectation is fenced, and the wrapper reports the service's own outcome"
        );
        assert_eq!(
            acquisitions(&recording) - before,
            1,
            "the fenced conditional commit must take exactly one real authority guard: \
             one store operation, one acquisition, compared and refused under it"
        );

        // Readback through the handle, not the raw store: a synchronous
        // `store().lookup()` here would run a REAL store operation on the
        // runtime thread and fail this test's own off-thread assertion.
        let after_fence = refuse_scaffold(
            fx.handle.resolve(&alice()).await,
            "readback after the fenced commit",
        )
        .expect("the account is still connected after a fenced commit");
        assert_eq!(
            after_fence.generation, seeded.generation,
            "a fenced conditional commit must write nothing at all"
        );

        // Durable revoke through the wrapper.
        refuse_scaffold(fx.handle.invalidate(&alice()).await, "invalidate")
            .expect("invalidate revokes through the handle");

        // The lease taken before the revoke no longer releases.
        assert_eq!(
            domain_err(fx.handle.release(&lease).await, "release after revoke"),
            CustodyError::Account(AccountServiceError::LeaseRetired),
            "a lease issued before a revoke must stop releasing after it"
        );
        assert_eq!(
            fx.observer_calls.load(Ordering::SeqCst),
            0,
            "no credential may be published for a revoked account"
        );

        // `invalidate` reached the real revoke; the fenced commit was already
        // pinned by its own acquisition delta above.
        let ops = recording.ops();
        assert!(
            ops.contains(&StoreOp::Revoke),
            "invalidate must reach the real store revoke: {ops:?}"
        );
        assert!(
            ops.contains(&StoreOp::Lookup),
            "resolve and release must reach the real store lookup: {ops:?}"
        );
        // Every recorded operation, all of them driven through the handle.
        for entry in recording.entries() {
            assert_ne!(
                entry.thread, caller_thread,
                "{:?} ran on the calling runtime thread instead of a blocking thread",
                entry.op
            );
        }
        drop(recording);

        // Durable across a reopen: the revoke survived, the fenced grant never landed.
        refuse_scaffold(fx.handle.shutdown().await, "shutdown").expect("shutdown");
        let reopened = PersonalAccountStore::open(config(tmp.path())).expect("reopen");
        assert!(
            matches!(
                reopened.lookup(&alice()).expect("readback"),
                AccountLookup::Revoked(_)
            ),
            "the revoke is durable, and the fenced replacement never became the account"
        );
    });
}

/// Two concurrent refreshes for ONE account share one provider round trip.
///
/// Overlap is proven, not assumed: the first is inside its provider call, and
/// the second has been polled to Pending. Only then is the one-call assertion
/// meaningful.
#[test]
fn single_flight_survives_the_handle_for_one_account() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 4);
        let (alice_entered, alice_release) = fx.provider.hold(&alice());

        let first = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
        };
        tokio::time::timeout(DEADLOCK, alice_entered)
            .await
            .expect("the first refresh entered the provider")
            .expect("entry signal");

        let (second_fut, second_pending) = first_pending({
            let handle = Arc::clone(&fx.handle);
            async move { handle.refresh_if_expired(&alice()).await }
        });
        let second = tokio::spawn(second_fut);
        // The waiter is genuinely parked inside the service, not merely spawned.
        tokio::time::timeout(DEADLOCK, second_pending)
            .await
            .expect("the second refresh was polled to Pending")
            .expect("pending signal");

        assert_eq!(
            fx.provider.call_count(&alice()),
            1,
            "two overlapping refreshes for one account must share one round trip"
        );

        alice_release
            .send(())
            .expect("the held provider is still waiting");
        let a = refuse_scaffold(first.await.expect("first"), "first refresh").expect("first lease");
        let b =
            refuse_scaffold(second.await.expect("second"), "second refresh").expect("second lease");
        assert_eq!(a, b, "both waiters receive the same rotated lease");
        assert_eq!(
            fx.provider.call_count(&alice()),
            1,
            "the wrapper must not add a second single-flight, nor defeat the existing one"
        );
    });
}
