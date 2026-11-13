// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Keeps the synchronous store off the event loop. Refusing scaffold.
//!
//! RECONCILED: an earlier note claimed the store "cannot be spawn_blocking-ed
//! per call because it holds locks". That was wrong. An `Arc<AccountService>`
//! hands the SAME service to a blocking thread; no file descriptor is
//! duplicated and no second store exists. The real constraints are narrower,
//! and all of them are what the tests pin:
//!
//! 1. every synchronous store operation runs off the event loop -- including
//!    the ones refresh performs BEFORE and AFTER its provider call;
//! 2. the authority guard is never held across an await (it is taken and
//!    released inside one store call, so this holds as long as no caller wraps
//!    a guard in a future);
//! 3. one account whose provider is slow must not stall a different account;
//! 4. shutdown drains in-flight work, refuses new work, and only then releases
//!    the store -- so both file locks are free while the handle still exists.
//!
//! ONE PIPELINE. This wrapper owns no store logic, no cache and no second
//! single-flight: `AccountService` remains the only path to the store, and
//! per-key single-flight stays where it already is.
//!
//! CAPACITY IS A CONSTRUCTOR ARGUMENT, not a config field. The approved
//! configuration table has no worker-queue knob, and inventing one would be a
//! schema change nobody approved.
//!
//! HOW THE TESTS OBSERVE IT. There is deliberately NO witness in this module.
//! A witness here would record what this wrapper says it is about to do, and an
//! empty closure on a blocking thread would satisfy it while the real store
//! call happened on the event loop. Observation lives inside the store instead
//! -- `super::store_probe`, called past the authority guard and immediately
//! before each real `storage::` call. A wrapper that skips the store records
//! nothing, and one that performs store I/O on the runtime records the
//! runtime's own thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::revoke::RevocationMaterial;
use super::service::{
    AccountService, AccountServiceError, CredentialLease, CredentialReleaseObserver,
    RefreshProvider, RejectionOutcome, ReleasedCredentials,
};
use super::{AccountError, AccountKey, PersonalAccountStore, StoreConfig};
#[cfg(test)]
use super::{GrantRecord, service::ConsentExpectation};

/// Default in-flight bound when a caller does not choose one.
pub(crate) const DEFAULT_CAPACITY: usize = 32;

/// Refusals at the custody boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CustodyError {
    #[error("custody handle runtime is not implemented")]
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
    )]
    RuntimeNotImplemented,
    /// The in-flight bound is reached. A retryable refusal, not a failure.
    #[error("custody is at its in-flight bound")]
    Busy,
    /// Shutdown has begun; new work is refused rather than queued.
    #[error("custody is shutting down")]
    ShuttingDown,
    /// A release could not start a thread and the store is held until the
    /// process exits.
    #[error("the custody store could not be released and is held until exit")]
    ReleaseStuck,
    #[error(transparent)]
    Account(#[from] AccountServiceError),
}

/// Why a handle could not start. Distinguished from a runtime refusal because a
/// store that cannot claim its locks must not look half-available.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CustodyStartError {
    #[error("custody start is not implemented")]
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
    )]
    RuntimeNotImplemented,
    #[error(transparent)]
    Store(#[from] AccountError),
}

/// The one entrypoint callers use. Wraps exactly one `AccountService`.
///
/// `service` is behind an `Option` so `shutdown` can RELEASE it — dropping the
/// last `Arc` drops the store, which is what frees both file locks while this
/// handle is still alive. A `std::sync::Mutex` guards it: every access is a
/// clone or a take, no await is ever held under it.
pub(crate) struct CustodyHandle<P, O> {
    slot: std::sync::Mutex<Slot<P, O>>,
    /// Becomes true when the service itself is dropped, wherever that happens.
    done: tokio::sync::watch::Receiver<bool>,
    permits: Arc<Semaphore>,
    shutting_down: AtomicBool,
    /// Set by the first report, so a release problem is logged once. Shared
    /// with the release thread, which reports a panic.
    reported: Arc<AtomicBool>,
    /// Test seam: the next release thread fails to start.
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
    capacity: usize,
}

/// What the handle holds, all behind one mutex: one transition at a time.
enum Slot<P, O> {
    /// Serving, or refusing but not yet released.
    Open(Arc<Held<P, O>>),
    /// A release thread owns the handle's reference.
    Releasing,
    /// A thread could not be started and the reference was leaked to process
    /// exit: never waited on, never reported released.
    Stuck,
}

/// The service plus the signal that it is gone. `done` is the LAST field, so it
/// drops after the service (store, provider, observer): completion means the
/// store really dropped, on whichever thread held the final reference.
struct Held<P, O> {
    service: AccountService<P, O>,
    _done: DoneGuard,
}

impl<P, O> std::ops::Deref for Held<P, O> {
    type Target = AccountService<P, O>;

    fn deref(&self) -> &Self::Target {
        &self.service
    }
}

impl<P, O> Slot<P, O> {
    /// Take the reference out of an `Open` slot (leaving `Releasing`); any other
    /// state is left as it is.
    fn take_open(&mut self) -> Option<Arc<Held<P, O>>> {
        match std::mem::replace(self, Slot::Releasing) {
            Slot::Open(held) => Some(held),
            other => {
                *self = other;
                None
            }
        }
    }
}

/// Log a release problem once per handle, whichever call meets it first. Error
/// level: a store whose locks are not released is a lost-lock risk. No line
/// names an account or a secret.
fn report_once(reported: &AtomicBool, what: &str) {
    if !reported.swap(true, Ordering::SeqCst) {
        tracing::error!("account custody: {what}");
    }
}

/// Sends `true` when dropped, also while a panic unwinds.
struct DoneGuard(tokio::sync::watch::Sender<bool>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

/// One admitted call: the service to run it against, and the permit that keeps
/// it inside the in-flight bound until it finishes.
struct Admission<P, O> {
    service: Arc<Held<P, O>>,
    permit: OwnedSemaphorePermit,
}

impl<P: RefreshProvider + 'static, O: CredentialReleaseObserver + 'static> CustodyHandle<P, O> {
    /// Open the store, build the one service, and become ready -- or fail.
    ///
    /// The store is opened HERE so a lock that cannot be claimed is a start
    /// failure at the real boundary, not a refusal discovered on first use.
    pub(crate) fn start(
        config: StoreConfig,
        provider: P,
        observer: O,
        capacity: usize,
    ) -> Result<Self, CustodyStartError> {
        // The store is claimed HERE. A directory whose locks another process
        // holds fails now, with no handle produced, rather than surfacing as a
        // refusal on first use.
        let store = PersonalAccountStore::open(config)?;
        let capacity = capacity.max(1);
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        let held = Held {
            service: AccountService::new(store, provider, observer),
            _done: DoneGuard(done_tx),
        };
        Ok(Self {
            slot: std::sync::Mutex::new(Slot::Open(Arc::new(held))),
            done: done_rx,
            permits: Arc::new(Semaphore::new(capacity)),
            shutting_down: AtomicBool::new(false),
            reported: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_spawn: AtomicBool::new(false),
            capacity,
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Admit one call, or say exactly why not.
    ///
    /// `try_acquire` and not `acquire`: over the bound the answer is a typed
    /// refusal the caller can act on, never an unbounded queue and never a
    /// silent stall.
    fn admit(&self) -> Result<Admission<P, O>, CustodyError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(CustodyError::ShuttingDown);
        }
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| CustodyError::Busy)?;
        let service = match &*self.lock_slot() {
            Slot::Open(held) => Arc::clone(held),
            Slot::Releasing | Slot::Stuck => return Err(CustodyError::ShuttingDown),
        };
        Ok(Admission { service, permit })
    }

    /// Run one synchronous store operation off the calling runtime thread.
    ///
    /// `spawn_blocking` hands the SAME `Arc<AccountService>` to a blocking
    /// thread. No descriptor is duplicated, no second store exists, and the
    /// event loop is free while the filesystem work happens. The permit rides
    /// into the closure so the bound is held for the whole operation, not just
    /// until dispatch.
    async fn offload<T, F>(&self, work: F) -> Result<T, CustodyError>
    where
        T: Send + 'static,
        F: FnOnce(&AccountService<P, O>) -> Result<T, AccountServiceError> + Send + 'static,
    {
        let Admission { service, permit } = self.admit()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&service)
        })
        .await
        // A panic in the store is a bug, not a domain outcome. Re-raising is
        // the honest answer; inventing a store error here would hide it.
        .expect("custody blocking worker")
        .map_err(CustodyError::from)
    }

    pub(crate) async fn resolve(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        let account = account.clone();
        self.offload(move |service| service.resolve(&account)).await
    }

    /// Single-flight, provider round trip and compare-and-swap all stay in
    /// `AccountService`. This only decides WHERE that future runs.
    ///
    /// The whole `refresh_if_expired` future is driven on the blocking thread,
    /// so the store work on BOTH sides of the provider call is off the event
    /// loop, the per-key flight lock still serialises one account, and a slow
    /// provider stalls only its own thread — a different account is admitted
    /// and dispatched independently.
    pub(crate) async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        let Admission { service, permit } = self.admit()?;
        let account = account.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.block_on(service.refresh_if_expired(&account))
        })
        .await
        .expect("custody blocking worker")
        .map_err(CustodyError::from)
    }

    /// A11-c: a 401 against `lease`. Admitted and run on a blocking worker
    /// exactly like [`Self::refresh_if_expired`], because it can hold the same
    /// flight lock across the same provider round trip.
    pub(crate) async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        let Admission { service, permit } = self.admit()?;
        let lease = lease.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.block_on(service.refresh_after_rejection(&lease))
        })
        .await
        .expect("custody blocking worker")
        .map_err(CustodyError::from)
    }

    pub(crate) async fn release(
        &self,
        lease: &CredentialLease,
    ) -> Result<ReleasedCredentials, CustodyError> {
        let lease = lease.clone();
        self.offload(move |service| service.release(&lease)).await
    }

    pub(crate) async fn invalidate(
        &self,
        account: &AccountKey,
    ) -> Result<Option<RevocationMaterial>, CustodyError> {
        let account = account.clone();
        self.offload(move |service| service.invalidate(&account))
            .await
    }

    /// The provider the service refreshes against. Not admitted: it touches
    /// no store, so it holds no permit, but it still refuses after shutdown.
    pub(crate) fn provider(&self) -> Result<P, CustodyError>
    where
        P: Clone,
    {
        match &*self.lock_slot() {
            Slot::Open(held) => Ok(held.provider().clone()),
            Slot::Releasing | Slot::Stuck => Err(CustodyError::ShuttingDown),
        }
    }

    /// The slot, whether or not a panic poisoned its mutex: every access is a
    /// clone or a take and no await is held under it.
    fn lock_slot(&self) -> std::sync::MutexGuard<'_, Slot<P, O>> {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test-only, like [`AccountService::commit_grant_if`] it forwards to.
    #[cfg(test)]
    pub(crate) async fn commit_grant_if(
        &self,
        account: &AccountKey,
        expected: &ConsentExpectation,
        record: &GrantRecord,
    ) -> Result<(), CustodyError> {
        let account = account.clone();
        let expected = expected.clone();
        let record = record.clone();
        self.offload(move |service| service.commit_grant_if(&account, &expected, &record))
            .await
    }

    /// Stop accepting, let in-flight work finish, then release the store so
    /// both file locks are freed.
    ///
    /// Takes `&self`, not `self`: "a command after shutdown is refused" and
    /// "the locks are free while the handle is still alive" are both contracts
    /// that a consuming signature makes unexpressible. Idempotent.
    pub(crate) async fn shutdown(&self) -> Result<(), CustodyError> {
        // No deadline: in-flight work completes and Ok means the store is
        // dropped and both file locks are free. A store a thread could not be
        // started for is reported as an error, never as released.
        match self.release_by(None).await? {
            ShutdownEnd::Released => Ok(()),
            ShutdownEnd::ReleasePending | ShutdownEnd::InFlightPending | ShutdownEnd::Stuck => {
                Err(CustodyError::ReleaseStuck)
            }
        }
    }

    /// Start the release of `held` on a detached thread. The reference travels
    /// in a shared cell, so a spawn that fails (its closure is dropped) leaves
    /// the reference in the cell for the caller to recover and leak instead of
    /// dropping it inline. A release thread that panics still signals done (the
    /// guard is the service's last field) and reports once.
    fn spawn_release(&self, held: Arc<Held<P, O>>) -> Result<(), Arc<Held<P, O>>> {
        let cell = Arc::new(std::sync::Mutex::new(Some(held)));
        let recover = |cell: &std::sync::Mutex<Option<Arc<Held<P, O>>>>| {
            cell.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        };
        #[cfg(test)]
        if self.fail_next_spawn.swap(false, Ordering::SeqCst) {
            return Err(recover(&cell).expect("the reference is still in the cell"));
        }
        let (thread_cell, reported) = (Arc::clone(&cell), Arc::clone(&self.reported));
        let spawned = std::thread::Builder::new()
            .name("shutdown: custody release".to_owned())
            .spawn(move || {
                let held = thread_cell
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(held)))
                    .is_err()
                {
                    report_once(&reported, "the store release panicked");
                }
            });
        match spawned {
            Ok(_) => Ok(()),
            Err(_) => Err(recover(&cell).expect("the reference is still in the cell")),
        }
    }

    /// Wait for the service to be gone: `true` when it is, `false` at `deadline`.
    async fn await_done(&self, deadline: Option<tokio::time::Instant>) -> bool {
        let mut done = self.done.clone();
        let waiting = done.wait_for(|gone| *gone);
        match deadline {
            Some(at) => matches!(tokio::time::timeout_at(at, waiting).await, Ok(Ok(_))),
            None => waiting.await.is_ok(),
        }
    }

    /// The one release path. `deadline` `None` is the unbounded `shutdown()`.
    async fn release_by(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<ShutdownEnd, CustodyError> {
        // Refuse first, drain second: the other order would let a call slip in
        // behind the drain and outlive the store it needs.
        self.shutting_down.store(true, Ordering::Release);
        // A later call inspects the slot BEFORE draining permits, so it is never
        // told "in flight" about a release that is already running or stuck.
        if let Some(end) = self.settled_end(deadline).await {
            return end;
        }
        // Holding every permit means no operation is in flight. In-flight work
        // is awaited, not cancelled, up to the deadline.
        let capacity = u32::try_from(self.capacity).unwrap_or(u32::MAX);
        let draining = Arc::clone(&self.permits).acquire_many_owned(capacity);
        let drained = match deadline {
            Some(at) => {
                let Ok(permits) = tokio::time::timeout_at(at, draining).await else {
                    // A detach may have started (or failed to start) the
                    // release while this call drained: report that, not "in flight".
                    if let Some(end) = self.settled_end(deadline).await {
                        return end;
                    }
                    report_once(
                        &self.reported,
                        "in-flight work still running at the stop deadline; the store was not released",
                    );
                    return Ok(ShutdownEnd::InFlightPending);
                };
                permits
            }
            None => draining.await,
        };
        // Take the reference and publish the new state in one critical section.
        let started = {
            let mut slot = self.lock_slot();
            match slot.take_open() {
                // Taken by a concurrent call while this one drained: a stuck
                // store is never waited on, a running release is.
                None if matches!(*slot, Slot::Stuck) => Some(false),
                None => None,
                Some(held) => match self.spawn_release(held) {
                    Ok(()) => Some(true),
                    Err(held) if deadline.is_none() => {
                        // Standalone shutdown: the gateway may stay alive, so do
                        // not hold the locks to exit; drop on the blocking pool.
                        drop(slot);
                        drop(tokio::task::spawn_blocking(move || drop(held)));
                        Some(true)
                    }
                    Err(held) => {
                        // The stop and detach paths: never drop it inline.
                        std::mem::forget(held);
                        *slot = Slot::Stuck;
                        Some(false)
                    }
                },
            }
        };
        drop(drained);
        match started {
            Some(true) | None => Ok(self.release_end(deadline).await),
            Some(false) => {
                report_once(
                    &self.reported,
                    "the store release could not start a thread; the store is held until exit",
                );
                Self::stuck_end(deadline)
            }
        }
    }

    /// How a call ends when the release is already running or stuck; `None`
    /// while the slot is still `Open`. The slot lock is released before any wait.
    async fn settled_end(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> Option<Result<ShutdownEnd, CustodyError>> {
        let stuck = match &*self.lock_slot() {
            Slot::Open(_) => return None,
            Slot::Releasing => false,
            Slot::Stuck => true,
        };
        Some(if stuck {
            Self::stuck_end(deadline)
        } else {
            Ok(self.release_end(deadline).await)
        })
    }

    /// How a call ends when the release thread is (or was) running.
    async fn release_end(&self, deadline: Option<tokio::time::Instant>) -> ShutdownEnd {
        if self.await_done(deadline).await {
            ShutdownEnd::Released
        } else {
            report_once(
                &self.reported,
                "store release still running at the stop deadline; it finishes off the stop path",
            );
            ShutdownEnd::ReleasePending
        }
    }

    /// How a call ends on a stuck store: bounded callers are told, unbounded
    /// ones get an error at once instead of waiting for a signal that never comes.
    fn stuck_end(deadline: Option<tokio::time::Instant>) -> Result<ShutdownEnd, CustodyError> {
        if deadline.is_some() {
            Ok(ShutdownEnd::Stuck)
        } else {
            Err(CustodyError::ReleaseStuck)
        }
    }

    /// Like [`Self::shutdown`] but bounded: the call ends at `deadline` whatever
    /// the release is doing; a release still running then continues off the stop
    /// path (reported once). `Released` means the store is dropped and both file
    /// locks are free.
    pub(crate) async fn shutdown_by(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<ShutdownEnd, CustodyError> {
        self.release_by(Some(deadline)).await
    }

    /// Hand any remaining service to a detached release thread and return at
    /// once: the end of a stop that cut or skipped the custody step, so the last
    /// drop is never on the thread that drops the gateway. Idempotent.
    pub(crate) fn detach_release(&self) {
        self.shutting_down.store(true, Ordering::Release);
        let mut slot = self.lock_slot();
        if let Some(held) = slot.take_open()
            && let Err(held) = self.spawn_release(held)
        {
            std::mem::forget(held);
            *slot = Slot::Stuck;
            report_once(
                &self.reported,
                "the store release could not start a thread; the store is held until exit",
            );
        }
    }

    /// A guard for a serve's whole body: dropped by any exit (an early error
    /// return, a cancelled future, the normal end after the stop's own detach),
    /// it hands the store to a release thread, so the gateway's drop never
    /// releases it on that thread. Idempotent with [`Self::detach_release`].
    pub(crate) fn detach_on_drop(self: &Arc<Self>) -> DetachOnDrop<P, O> {
        DetachOnDrop(Arc::clone(self))
    }

    /// Test seam: the next release thread fails to start.
    #[cfg(test)]
    pub(crate) fn fail_next_release_spawn(&self) {
        self.fail_next_spawn.store(true, Ordering::SeqCst);
    }
}

/// See [`CustodyHandle::detach_on_drop`].
pub(crate) struct DetachOnDrop<P: RefreshProvider + 'static, O: CredentialReleaseObserver + 'static>(
    Arc<CustodyHandle<P, O>>,
);

impl<P: RefreshProvider + 'static, O: CredentialReleaseObserver + 'static> Drop
    for DetachOnDrop<P, O>
{
    fn drop(&mut self) {
        self.0.detach_release();
    }
}

/// How a bounded custody shutdown ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ShutdownEnd {
    /// The store is dropped and both file locks are free.
    Released,
    /// The deadline passed while the release was still running off the stop path.
    ReleasePending,
    /// In-flight work still held a permit at the deadline; the store was not taken.
    InFlightPending,
    /// A spawn failed and the store is held until the process exits.
    Stuck,
}

#[path = "worker_journeys.rs"]
mod journeys;
pub(crate) use journeys::{AccountHandles, JourneyService, JourneyStarted};
/// For a test double of [`JourneyService`] (A11 offer cell). Test-only.
#[cfg(test)]
pub(crate) use journeys::{JourneyCreated, JourneyResult};
#[path = "worker_callback.rs"]
mod callback;
pub(crate) use callback::{CallbackOutcome, CallbackRequest};

#[cfg(test)]
#[path = "worker_tests.rs"]
mod worker_tests;
