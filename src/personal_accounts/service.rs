// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-process account service: leases, single-flight refresh, release recheck.
//!
//! Three rules the whole module follows.
//!
//! A LEASE IS A CLAIM, NEVER AN AUTHORITY. Every release re-reads the store and
//! compares the whole lease against what is authoritative now. Nothing is
//! published on the strength of what the caller is holding.
//!
//! AN ACCOUNT IS THE WHOLE FIVE-FIELD KEY. Single-flight, provider round trips
//! and durable writes all partition on `AccountKey::digest`, so two accounts
//! that share a subject and differ in backend, resource, authority or issuer
//! never serialise behind, or write over, one another.
//!
//! THE STORE'S OWN LOCK IS NEVER HELD ACROSS AN AWAIT. Rotations serialise on a
//! per-key async lock; each store call takes the authority lock, finishes and
//! returns. A provider that never answers stalls one account, not the store.
//!
//! Conditional consent (`commit_grant_if`) cannot be built from
//! `PersonalAccountStore::commit_grant`. That API is unconditional, and
//! `lookup` drops the authority lock before returning, so the pair leaves a
//! window a competing grant or revoke is lost in. It routes through
//! `PersonalAccountStore::commit_grant_if_unchanged`, whose single-acquisition
//! contract the `consent` module states and its witness observes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::consent::{GuardedCommit, GuardedCommitError};
use super::{
    AccountError, AccountKey, AccountLookup, FenceOutcome, GrantRecord, GrantVersion,
    PersonalAccountStore, RefreshOutcome,
};

/// Provider-side token rotation result. Omitted refresh token or scope must be
/// preserved by the service, not dropped.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TokenRefresh {
    pub(crate) access_token: String,
    /// `None` means the provider omitted the field (RFC 6749 §5.1/§6).
    pub(crate) refresh_token: Option<String>,
    /// `None` means the provider omitted `scope`.
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) token_type: String,
    pub(crate) expires_at: u64,
}

impl std::fmt::Debug for TokenRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRefresh").finish_non_exhaustive()
    }
}

/// Refresh-provider failure. `InvalidGrant` must become reconnect-required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderRefreshError {
    InvalidGrant,
    Unavailable,
}

/// Counting, holdable refresh seam. One round trip per in-flight account key.
pub(crate) trait RefreshProvider: Send + Sync {
    fn refresh(
        &self,
        account: &AccountKey,
        current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send;
}

/// Stable authorization binding plus the volatile token-revision guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialLease {
    pub(crate) account: AccountKey,
    pub(crate) generation: String,
    pub(crate) authorization_epoch: u64,
    pub(crate) scopes: Vec<String>,
    pub(crate) descriptor_revision: String,
    pub(crate) token_revision: u64,
}

/// Transport credentials, produced only after a successful release recheck.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ReleasedCredentials {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
}

impl std::fmt::Debug for ReleasedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedCredentials")
            .finish_non_exhaustive()
    }
}

/// Observes a credential that has passed the lease-boundary recheck.
///
/// This is the dispatch seam for account-service tests. It is not HTTP, cache
/// invalidation, or connection retirement.
pub(crate) trait CredentialReleaseObserver: Send + Sync {
    fn on_release(
        &self,
        account: &AccountKey,
        lease: &CredentialLease,
        credentials: &ReleasedCredentials,
    );
}

/// Non-secret prior state a consent journey captured before talking to a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConsentExpectation {
    Absent,
    Connected(GrantVersion),
    Revoked(GrantVersion),
    ReconnectRequired(GrantVersion),
}

impl ConsentExpectation {
    /// Snapshot lookup without retaining credential bytes.
    pub(crate) fn captured(lookup: &AccountLookup) -> Self {
        match lookup {
            AccountLookup::Absent => Self::Absent,
            AccountLookup::Connected(record) => Self::Connected(GrantVersion {
                generation: record.generation.clone(),
                token_revision: record.token_revision,
                authorization_epoch: record.authorization_epoch,
                descriptor_revision: record.descriptor_revision.clone(),
            }),
            AccountLookup::Revoked(version) => Self::Revoked(version.clone()),
            AccountLookup::ReconnectRequired(version) => Self::ReconnectRequired(version.clone()),
        }
    }
}

/// Typed refusals at the account-service boundary.
///
/// `RuntimeNotImplemented` is the scaffold. Domain cases must not match it.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccountServiceError {
    #[error("account service runtime is not implemented")]
    RuntimeNotImplemented,
    #[error("account is not connected")]
    ConnectOffer,
    #[error("account grant is revoked")]
    Revoked,
    #[error("account must reconnect")]
    ReconnectRequired,
    #[error("refresh would broaden granted scopes")]
    ScopeBroadeningRefused,
    #[error("credential lease is no longer valid")]
    LeaseRetired,
    #[error("stale consent was fenced by a later grant or revoke")]
    StaleConsentFenced,
    #[error("refresh provider is unavailable")]
    ProviderUnavailable,
    #[error("personal account store refused the operation")]
    Store(#[from] AccountError),
}

/// The non-secret binding a lease publishes. Built from the durable record, so
/// a lease can never claim a field the store did not commit.
fn lease_of(account: &AccountKey, record: &GrantRecord) -> CredentialLease {
    CredentialLease {
        account: account.clone(),
        generation: record.generation.clone(),
        authorization_epoch: record.authorization_epoch,
        scopes: record.scopes.clone(),
        descriptor_revision: record.descriptor_revision.clone(),
        token_revision: record.token_revision,
    }
}

fn version_of(record: &GrantRecord) -> GrantVersion {
    GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    }
}

/// A clock that cannot read backwards into "still valid": an unreadable clock
/// means refresh, never serve.
fn expired(record: &GrantRecord) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| since.as_secs());
    record.expires_at <= now
}

/// In-process layer between the durable store and crate-internal callers.
pub(crate) struct AccountService<P, O> {
    store: PersonalAccountStore,
    provider: P,
    observer: O,
    /// One rotation at a time per COMPLETE account key.
    ///
    /// An async lock, because it is the one thing held across the provider
    /// round trip. The store's authority lock is not: every store call below
    /// takes it, finishes and returns before anything is awaited.
    ///
    /// ponytail: entries are never reclaimed, so this is bounded by the number
    /// of distinct accounts a process refreshes. Prune on last release if a
    /// long-lived process ever makes that a real number.
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<P: RefreshProvider, O: CredentialReleaseObserver> AccountService<P, O> {
    pub(crate) fn new(store: PersonalAccountStore, provider: P, observer: O) -> Self {
        Self {
            store,
            provider,
            observer,
            flights: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn store(&self) -> &PersonalAccountStore {
        &self.store
    }

    /// Account key → lease, or a typed refusal. Storage failure is never absence.
    pub(crate) fn resolve(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, AccountServiceError> {
        let record = self.connected(account)?;
        Ok(lease_of(account, &record))
    }

    /// Single-flight per account key. Applies through the store's version CAS.
    pub(crate) async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, AccountServiceError> {
        let flight = self.flight(account)?;
        let _rotating = flight.lock().await;

        // Read again inside the flight: a waiter normally finds the leader's
        // rotation already durable and unexpired, which is why one round trip
        // serves both and neither serves a token the other replaced.
        let current = self.connected(account)?;
        if !expired(&current) {
            return Ok(lease_of(account, &current));
        }
        let expected = version_of(&current);
        match self.provider.refresh(account, &current).await {
            Ok(rotated) => self.apply(account, &current, &expected, rotated),
            // Transient. Nothing durable moves, so the account stays connected
            // and the next attempt costs the user nothing.
            Err(ProviderRefreshError::Unavailable) => Err(AccountServiceError::ProviderUnavailable),
            Err(ProviderRefreshError::InvalidGrant) => {
                self.fence_after_invalid_grant(account, &expected)
            }
        }
    }

    /// Recheck the whole lease against current authority, then publish once.
    pub(crate) fn release(
        &self,
        lease: &CredentialLease,
    ) -> Result<ReleasedCredentials, AccountServiceError> {
        let current = match self.store.lookup(&lease.account)? {
            AccountLookup::Connected(record) => record,
            AccountLookup::ReconnectRequired(_) => {
                return Err(AccountServiceError::ReconnectRequired);
            }
            // Holding a lease is not an invitation to connect one, so absence
            // is a retired lease here and never a connect offer.
            AccountLookup::Revoked(_) | AccountLookup::Absent => {
                return Err(AccountServiceError::LeaseRetired);
            }
        };
        // The WHOLE lease, not the token revision alone: a superseded
        // generation, authorization or descriptor is just as retired.
        if lease_of(&lease.account, &current) != *lease {
            return Err(AccountServiceError::LeaseRetired);
        }
        let credentials = ReleasedCredentials {
            access_token: current.access_token.clone(),
            token_type: current.token_type.clone(),
        };
        // Exactly once, and only past the recheck above.
        self.observer
            .on_release(&lease.account, lease, &credentials);
        Ok(credentials)
    }

    /// Durably revoke, then bar new leases and release eligibility.
    pub(crate) fn invalidate(&self, account: &AccountKey) -> Result<(), AccountServiceError> {
        self.store.revoke(account)?;
        Ok(())
    }

    /// Commit a grant only if `expected` still holds under the authority lock.
    ///
    /// One store call, on purpose. Reading the state here and committing after
    /// would be the TOCTOU the guarded entrypoint exists to remove.
    pub(crate) fn commit_grant_if(
        &self,
        account: &AccountKey,
        expected: &ConsentExpectation,
        record: &GrantRecord,
    ) -> Result<(), AccountServiceError> {
        match self
            .store
            .commit_grant_if_unchanged(account, expected, record)
        {
            Ok(GuardedCommit::Committed) => Ok(()),
            Ok(GuardedCommit::Fenced) => Err(AccountServiceError::StaleConsentFenced),
            Err(GuardedCommitError::Store(error)) => Err(AccountServiceError::Store(error)),
            Err(GuardedCommitError::RuntimeNotImplemented) => {
                Err(AccountServiceError::RuntimeNotImplemented)
            }
        }
    }

    /// The current grant, or the typed reason there is none. A storage failure
    /// propagates as itself: it is never reported as absence.
    fn connected(&self, account: &AccountKey) -> Result<GrantRecord, AccountServiceError> {
        match self.store.lookup(account)? {
            AccountLookup::Connected(record) => Ok(record),
            AccountLookup::Absent => Err(AccountServiceError::ConnectOffer),
            AccountLookup::Revoked(_) => Err(AccountServiceError::Revoked),
            AccountLookup::ReconnectRequired(_) => Err(AccountServiceError::ReconnectRequired),
        }
    }

    /// The rotation lock for one complete account key.
    fn flight(
        &self,
        account: &AccountKey,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, AccountServiceError> {
        let digest = account.digest()?;
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(Arc::clone(flights.entry(digest).or_default()))
    }

    /// Turn a provider rotation into a durable replacement, or refuse it.
    fn apply(
        &self,
        account: &AccountKey,
        current: &GrantRecord,
        expected: &GrantVersion,
        rotated: TokenRefresh,
    ) -> Result<CredentialLease, AccountServiceError> {
        // An omitted scope list means "unchanged", never "none".
        let mut scopes = rotated.scopes.unwrap_or_else(|| current.scopes.clone());
        scopes.sort();
        scopes.dedup();
        if scopes.iter().any(|scope| !current.scopes.contains(scope)) {
            // A refresh may narrow what the user granted. It may never widen
            // it: that is a new consent, and the user has not given it.
            return Err(AccountServiceError::ScopeBroadeningRefused);
        }
        // Narrower is a DIFFERENT authorization, so the epoch moves and every
        // lease issued under the old one is retired by that alone.
        let narrowed = scopes.len() < current.scopes.len();
        let authorization_epoch = if narrowed {
            current
                .authorization_epoch
                .checked_add(1)
                .ok_or(AccountError::StorageUnavailable)?
        } else {
            current.authorization_epoch
        };
        let next = GrantRecord {
            token_revision: current
                .token_revision
                .checked_add(1)
                .ok_or(AccountError::StorageUnavailable)?,
            authorization_epoch,
            scopes,
            access_token: rotated.access_token,
            // An omitted refresh token means "keep using the one you have".
            refresh_token: rotated
                .refresh_token
                .or_else(|| current.refresh_token.clone()),
            token_type: rotated.token_type,
            expires_at: rotated.expires_at,
            ..current.clone()
        };
        match self.store.refresh_tokens(account, expected, &next)? {
            RefreshOutcome::Committed => Ok(lease_of(account, &next)),
            // The grant moved while the provider was answering. Theirs is the
            // live one; this rotation has nothing left to apply to, and must
            // not be written over it.
            RefreshOutcome::Rejected => Err(self.superseded(account)),
        }
    }

    /// The provider rejected the grant this refresh was rotating.
    ///
    /// The account must be fenced durably BEFORE the refusal is reported, or a
    /// user told to reconnect keeps resolving and releasing as connected. The
    /// fence is a compare-and-swap on the whole expected version, so a grant
    /// re-authorized while the provider was answering is never tombstoned.
    fn fence_after_invalid_grant(
        &self,
        account: &AccountKey,
        expected: &GrantVersion,
    ) -> Result<CredentialLease, AccountServiceError> {
        match self.store.fence_expected_version(account, expected)? {
            FenceOutcome::Fenced => Err(AccountServiceError::ReconnectRequired),
            // The rejected generation is no longer the live one, so the
            // rejection has nothing to apply to and nothing was written.
            FenceOutcome::Superseded => Err(self.superseded(account)),
        }
    }

    /// Why a rotation lost, in the caller's vocabulary. The compare-and-swap
    /// already refused; this only decides which refusal to report.
    fn superseded(&self, account: &AccountKey) -> AccountServiceError {
        match self.store.lookup(account) {
            Ok(AccountLookup::Revoked(_)) => AccountServiceError::Revoked,
            Ok(AccountLookup::ReconnectRequired(_)) => AccountServiceError::ReconnectRequired,
            Ok(AccountLookup::Connected(_) | AccountLookup::Absent) => {
                AccountServiceError::LeaseRetired
            }
            Err(error) => AccountServiceError::Store(error),
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod service_tests;
