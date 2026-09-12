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

use super::service::{
    AccountService, AccountServiceError, ConsentExpectation, CredentialLease,
    CredentialReleaseObserver, RefreshProvider, ReleasedCredentials,
};
use super::{AccountError, AccountKey, GrantRecord, PersonalAccountStore, StoreConfig};

/// Default in-flight bound when a caller does not choose one.
pub(crate) const DEFAULT_CAPACITY: usize = 32;

/// Refusals at the custody boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CustodyError {
    #[error("custody handle runtime is not implemented")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    RuntimeNotImplemented,
    /// The in-flight bound is reached. A retryable refusal, not a failure.
    #[error("custody is at its in-flight bound")]
    Busy,
    /// Shutdown has begun; new work is refused rather than queued.
    #[error("custody is shutting down")]
    ShuttingDown,
    #[error(transparent)]
    Account(#[from] AccountServiceError),
}

/// Why a handle could not start. Distinguished from a runtime refusal because a
/// store that cannot claim its locks must not look half-available.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CustodyStartError {
    #[error("custody start is not implemented")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
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
    service: std::sync::Mutex<Option<Arc<AccountService<P, O>>>>,
    permits: Arc<Semaphore>,
    shutting_down: AtomicBool,
    capacity: usize,
}

/// One admitted call: the service to run it against, and the permit that keeps
/// it inside the in-flight bound until it finishes.
struct Admission<P, O> {
    service: Arc<AccountService<P, O>>,
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
        Ok(Self {
            service: std::sync::Mutex::new(Some(Arc::new(AccountService::new(
                store, provider, observer,
            )))),
            permits: Arc::new(Semaphore::new(capacity)),
            shutting_down: AtomicBool::new(false),
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
        let service = self
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone)
            .ok_or(CustodyError::ShuttingDown)?;
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

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
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

    pub(crate) async fn release(
        &self,
        lease: &CredentialLease,
    ) -> Result<ReleasedCredentials, CustodyError> {
        let lease = lease.clone();
        self.offload(move |service| service.release(&lease)).await
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    pub(crate) async fn invalidate(&self, account: &AccountKey) -> Result<(), CustodyError> {
        let account = account.clone();
        self.offload(move |service| service.invalidate(&account))
            .await
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
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
        // Refuse first, drain second. The other order would let a call slip in
        // behind the drain and outlive the store it needs.
        self.shutting_down.store(true, Ordering::Release);
        let capacity = u32::try_from(self.capacity).unwrap_or(u32::MAX);
        // Holding every permit means no operation is in flight. In-flight work
        // is awaited, not cancelled: a command admitted before shutdown still
        // completes.
        let drained = Arc::clone(&self.permits).acquire_many_owned(capacity).await;
        let taken = self
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // The last `Arc` goes here, so the store — and both of its exclusive
        // file locks — is released while this handle is still alive.
        drop(taken);
        drop(drained);
        Ok(())
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod worker_tests;
