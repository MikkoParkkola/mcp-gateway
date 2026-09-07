// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Principal-bound downstream account custody.
//!
//! Private encrypted custody, with explicit offline initialization and no
//! fallback to legacy operator tokens. Filesystem operations are synchronous;
//! async callers must execute custody work on a blocking worker.

mod consent;
mod service;
mod storage;

// Test-only fault control for the durable-commit boundaries. The commit path
// calls `faults::reached` at each of them; see that module for the contract.
#[cfg(test)]
mod faults;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// An exact verified principal/backend/resource/issuer binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountKey {
    pub(crate) principal_authority: String,
    pub(crate) principal_subject: String,
    pub(crate) backend_id: String,
    pub(crate) resource: String,
    pub(crate) oauth_issuer: String,
}

impl AccountKey {
    /// Validate and hash the versioned length-prefixed account tuple.
    pub(crate) fn digest(&self) -> Result<String, AccountError> {
        let fields = self.fields()?;
        let encoded = storage::encode_fields(b"mcp-gateway/account-key/v1", &fields)?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }

    fn fields(&self) -> Result<[&str; 5], AccountError> {
        let fields = [
            self.principal_authority.as_str(),
            self.principal_subject.as_str(),
            self.backend_id.as_str(),
            self.resource.as_str(),
            self.oauth_issuer.as_str(),
        ];
        if fields
            .iter()
            .any(|value| value.is_empty() || value.len() > 4096)
        {
            return Err(AccountError::InvalidAccountKey);
        }
        Ok(fields)
    }
}

/// Secret-free errors at the private account boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccountError {
    #[error("account key is invalid")]
    InvalidAccountKey,
    #[error("personal account storage is unavailable")]
    StorageUnavailable,
    #[error("personal account credential authentication failed")]
    NotAuthentic,
    #[error("personal account storage configuration is invalid")]
    InvalidConfiguration,
    #[error("personal account storage is at capacity")]
    CapacityExhausted,
    /// A proposed replacement contradicts the expectation the caller supplied
    /// with it — a different generation or descriptor, or a revision that moves
    /// backwards. Deliberately NOT `RefreshOutcome::Rejected`: losing a race is
    /// worth retrying and this never is, so conflating them invites a caller to
    /// retry forever.
    #[error("proposed grant version is inconsistent with the expected version")]
    InvalidGrantVersion,
}

/// Outcome of a compare-and-swap token replacement. A stale expectation is an
/// ordinary refusal, not a failure: the caller lost a race it was meant to lose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RefreshOutcome {
    Committed,
    Rejected,
}

/// Outcome of an expected-version fence. A superseded grant is an ordinary
/// refusal, not a failure: the account was re-authorized while the provider was
/// answering, and fencing it then would disconnect a user who has just consented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FenceOutcome {
    Fenced,
    Superseded,
}

/// Already-resolved private store configuration; environment lookup stays outside.
#[derive(Clone)]
pub(crate) struct StoreConfig {
    pub(crate) instance_id: String,
    pub(crate) store_dir: PathBuf,
    pub(crate) authority_dir: PathBuf,
    pub(crate) current_key_id: String,
    pub(crate) keys: BTreeMap<String, Vec<u8>>,
    pub(crate) max_entries: usize,
    pub(crate) max_authority_bytes: usize,
}

/// Encrypted record payload; Debug intentionally omits credentials and identity.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantRecord {
    pub(crate) generation: String,
    pub(crate) token_revision: u64,
    pub(crate) authorization_epoch: u64,
    pub(crate) descriptor_revision: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) access_token: String,
    pub(crate) refresh_token: Option<String>,
    pub(crate) token_type: String,
    pub(crate) expires_at: u64,
    pub(crate) provider_account_id: Option<String>,
    pub(crate) client_id: String,
}

impl std::fmt::Debug for GrantRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantRecord").finish_non_exhaustive()
    }
}

/// Non-secret version captured by a connected or tombstoned grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GrantVersion {
    pub(crate) generation: String,
    pub(crate) token_revision: u64,
    pub(crate) authorization_epoch: u64,
    pub(crate) descriptor_revision: String,
}

/// Distinct lookup states; only genuine absence can offer initial connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AccountLookup {
    Absent,
    Connected(GrantRecord),
    Revoked(GrantVersion),
    ReconnectRequired(GrantVersion),
}

/// Lifetime-owned durable personal store.
pub(crate) struct PersonalAccountStore {
    config: StoreConfig,
    // `None` means poisoned: a failure after the manifest rename left this copy
    // unable to vouch for itself, so it refuses instead of serving a state the
    // durable authority may already have superseded. A restart re-reads it.
    authority: parking_lot::Mutex<Option<Authority>>,
    // Both halves must remain exclusively owned even if another configuration
    // incorrectly pairs one of the directories with a different counterpart.
    _record_lock: crate::fs_lock::ExclusiveFileLock,
    _authority_lock: crate::fs_lock::ExclusiveFileLock,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    instance_id: String,
    store_epoch: String,
    commit_revision: u64,
    entries: BTreeMap<String, AuthorityEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    generation: String,
    token_revision: u64,
    authorization_epoch: u64,
    descriptor_revision: String,
    record_basename: Option<String>,
    record_sha256: Option<String>,
    state: GrantState,
    legacy_migration: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantState {
    Connected,
    Revoked,
    ReconnectRequired,
}

/// The authority guard, and the only thing any operation may hold it as.
///
/// Under `cfg(test)` it carries the witness session for the acquisition it
/// represents and closes that session when the guard drops. Outside tests it is
/// the `parking_lot` guard and nothing else — one field, no `Drop`.
struct AuthorityGuard<'store> {
    guard: parking_lot::MutexGuard<'store, Option<Authority>>,
    #[cfg(test)]
    ticket: consent::witness::Ticket,
}

impl std::ops::Deref for AuthorityGuard<'_> {
    type Target = Option<Authority>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl std::ops::DerefMut for AuthorityGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[cfg(test)]
impl Drop for AuthorityGuard<'_> {
    fn drop(&mut self) {
        // Logged before the mutex itself is released, which is what makes
        // "released, then the competitor acquired" a causal order rather than
        // two timestamps that happen to be in that sequence.
        self.ticket.released();
    }
}

impl PersonalAccountStore {
    /// Explicit offline initialization; existing state must never be replaced.
    pub(crate) fn initialize(config: StoreConfig) -> Result<Self, AccountError> {
        storage::initialize(config)
    }

    /// Open an existing authority; absence is an error, not initialization.
    pub(crate) fn open(config: StoreConfig) -> Result<Self, AccountError> {
        storage::open(config)
    }

    /// THE acquisition point for the authority mutex. Every operation below
    /// goes through it, and nothing acquires `self.authority` directly.
    ///
    /// Two reasons it is a function rather than five `lock()` calls. It is the
    /// one place a guarded conditional commit can be REQUIRED to reuse, and
    /// under `cfg(test)` it is where an acquisition becomes observable — the
    /// attempt before the block, the acquisition, the park while held, and the
    /// release. A test therefore counts what the store did, never what an
    /// implementation says it did.
    fn lock_authority(&self) -> AuthorityGuard<'_> {
        #[cfg(test)]
        let ticket = consent::witness::attempting(consent::witness::identify(self));
        let guard = self.authority.lock();
        #[cfg(test)]
        ticket.acquired();
        // Held. An armed park stalls the lock itself, so a competing writer
        // released against it blocks on a real mutex.
        #[cfg(test)]
        consent::witness::park_after_acquire(consent::witness::identify(self));
        AuthorityGuard {
            guard,
            #[cfg(test)]
            ticket,
        }
    }

    /// Resolve one exact account. The full five-field tuple is validated before
    /// the authority is consulted, so a malformed identity is never reported as
    /// connectable absence.
    pub(crate) fn lookup(&self, account: &AccountKey) -> Result<AccountLookup, AccountError> {
        let digest = account.digest()?;
        let authority = self.lock_authority();
        let authority = authority.as_ref().ok_or(AccountError::StorageUnavailable)?;
        storage::lookup(&self.config, authority, &digest, account)
    }

    /// Commit a new grant generation for an account.
    pub(crate) fn commit_grant(
        &self,
        account: &AccountKey,
        record: &GrantRecord,
    ) -> Result<(), AccountError> {
        let mut authority = self.lock_authority();
        storage::commit::commit_grant(&self.config, &mut authority, account, record)
    }

    /// Replace tokens only if the expected version still holds.
    pub(crate) fn refresh_tokens(
        &self,
        account: &AccountKey,
        expected: &GrantVersion,
        record: &GrantRecord,
    ) -> Result<RefreshOutcome, AccountError> {
        let mut authority = self.lock_authority();
        storage::commit::refresh_tokens(&self.config, &mut authority, account, expected, record)
    }

    /// Durably tombstone the current generation before reporting success.
    pub(crate) fn revoke(&self, account: &AccountKey) -> Result<(), AccountError> {
        let mut authority = self.lock_authority();
        storage::commit::revoke(&self.config, &mut authority, account)
    }

    /// Fence the grant a provider rejected, and only while it is still the
    /// live one. Distinct from `mark_reconnect_required`, which fences on a
    /// DESCRIPTOR move and deliberately does nothing when the descriptor is
    /// unchanged; this one compares the whole expected version instead, under
    /// the same single acquisition that publishes the fence.
    pub(crate) fn fence_expected_version(
        &self,
        account: &AccountKey,
        expected: &GrantVersion,
    ) -> Result<FenceOutcome, AccountError> {
        let mut authority = self.lock_authority();
        storage::commit::fence_expected_version(&self.config, &mut authority, account, expected)
    }

    /// Fence a grant whose descriptor revision moved.
    pub(crate) fn mark_reconnect_required(
        &self,
        account: &AccountKey,
        descriptor_revision: &str,
    ) -> Result<(), AccountError> {
        let mut authority = self.lock_authority();
        storage::commit::mark_reconnect_required(
            &self.config,
            &mut authority,
            account,
            descriptor_revision,
        )
    }
}

#[cfg(test)]
mod tests;
