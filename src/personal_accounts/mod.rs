// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Principal-bound downstream account custody.
//!
//! Private encrypted custody, with explicit offline initialization and no
//! fallback to legacy operator tokens. Filesystem operations are synchronous;
//! async callers must execute custody work on a blocking worker.

pub(crate) mod config;
mod consent;
// Visible to the crate for the descriptor contract only: `account_key` and the
// `AccountDescriptor` it binds. The store, the service and the worker stay
// private, so a consumer cannot reach past custody to the records themselves.
pub(crate) mod identity;
mod provider;
mod service;
mod storage;
mod vault;
mod worker;

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

/// Test-only observation of REAL store operations.
///
/// WHY IT LIVES HERE AND NOT IN A WRAPPER. A witness placed in a caller records
/// what the caller says it is about to do. `phase(kind, id, || ())` on a
/// blocking thread, with the actual store call made somewhere else entirely,
/// satisfies such a witness completely — it authenticates the wrapper, not the
/// store. So the observation point is inside the store operation itself, past
/// the authority guard and immediately before the real `storage::` call. A
/// caller that skips the store reaches nothing here, and a caller that performs
/// synchronous store I/O on the event loop records the runtime's own thread.
///
/// SCOPED BY STORE DIRECTORY. Every test builds its own `TempDir`, so a
/// recording watches one path and unrelated parallel store tests are invisible.
/// Account digests are not enough: fixtures across tests share one account key.
///
/// NO GUARD IS HELD ACROSS AN AWAIT. Everything here is synchronous; a parked
/// operation blocks its own thread and nothing else.
#[cfg(test)]
pub(crate) mod store_probe {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use tokio::sync::oneshot;

    /// Bounds a failure only. Progress is always made by a real event.
    const DEADLOCK: Duration = Duration::from_secs(5);

    /// The real operations, named where they actually happen.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum StoreOp {
        /// The single authority acquisition every operation passes through.
        AuthorityAcquired,
        Lookup,
        CommitGrant,
        RefreshTokens,
        Revoke,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct Entry {
        pub(crate) op: StoreOp,
        pub(crate) thread: String,
    }

    static SERIAL: Mutex<()> = Mutex::new(());
    static STATE: Mutex<Option<State>> = Mutex::new(None);

    struct State {
        store_dir: PathBuf,
        entered: Vec<Entry>,
        park: Option<(StoreOp, oneshot::Sender<()>, Receiver<()>)>,
    }

    fn state() -> MutexGuard<'static, Option<State>> {
        STATE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Called from inside a real store operation. Records the thread that is
    /// actually executing it, and stalls there if a test armed this operation.
    pub(crate) fn entered(op: StoreOp, store_dir: &Path) {
        let parked = {
            let mut slot = state();
            match slot.as_mut() {
                Some(state) if state.store_dir == store_dir => {
                    state.entered.push(Entry {
                        op,
                        thread: format!("{:?}", std::thread::current().id()),
                    });
                    match &state.park {
                        Some((armed, _, _)) if *armed == op => state.park.take(),
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        if let Some((_, entered, release)) = parked {
            // Announce to an awaiting test, then block THIS thread only.
            let _ = entered.send(());
            let _ = release.recv_timeout(DEADLOCK);
        }
    }

    /// Watch one store directory. Also serialises the observing tests.
    pub(crate) fn watch(store_dir: &Path) -> Recording {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        *state() = Some(State {
            store_dir: store_dir.to_path_buf(),
            entered: Vec::new(),
            park: None,
        });
        Recording { _serial: serial }
    }

    pub(crate) struct Recording {
        _serial: MutexGuard<'static, ()>,
    }

    impl Recording {
        pub(crate) fn entries(&self) -> Vec<Entry> {
            state()
                .as_ref()
                .map(|s| s.entered.clone())
                .unwrap_or_default()
        }

        pub(crate) fn ops(&self) -> Vec<StoreOp> {
            self.entries().into_iter().map(|entry| entry.op).collect()
        }

        /// Every thread a real store operation ran on.
        pub(crate) fn threads(&self) -> Vec<String> {
            let mut threads: Vec<String> = self
                .entries()
                .into_iter()
                .map(|entry| entry.thread)
                .collect();
            threads.sort();
            threads.dedup();
            threads
        }

        /// Stall the next occurrence of `op` inside the store operation itself.
        pub(crate) fn park(&self, op: StoreOp) -> Park {
            let (entered_tx, entered_rx) = oneshot::channel();
            let (release_tx, release_rx) = channel();
            if let Some(state) = state().as_mut() {
                state.park = Some((op, entered_tx, release_rx));
            }
            Park {
                entered: Some(entered_rx),
                release: release_tx,
            }
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            *state() = None;
        }
    }

    pub(crate) struct Park {
        entered: Option<oneshot::Receiver<()>>,
        release: Sender<()>,
    }

    impl Park {
        /// Await the store operation actually reaching the stall.
        ///
        /// ASYNC on purpose: blocking here on a current-thread runtime would
        /// stop the very task trying to enter, and no implementation could pass.
        pub(crate) async fn wait_entered(&mut self) {
            let entered = self.entered.take().expect("wait_entered is called once");
            tokio::time::timeout(DEADLOCK, entered)
                .await
                .expect("a real store operation reached the stall within the deadlock bound")
                .expect("the parked store operation kept its entry signal");
        }

        pub(crate) fn release(self) {
            let _ = self.release.send(());
        }
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
        // Held, and inside the real acquisition: every store operation passes
        // here, including the guarded conditional commit in `consent`.
        #[cfg(test)]
        store_probe::entered(
            store_probe::StoreOp::AuthorityAcquired,
            &self.config.store_dir,
        );
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
        #[cfg(test)]
        store_probe::entered(store_probe::StoreOp::Lookup, &self.config.store_dir);
        storage::lookup(&self.config, authority, &digest, account)
    }

    /// Commit a new grant generation for an account.
    pub(crate) fn commit_grant(
        &self,
        account: &AccountKey,
        record: &GrantRecord,
    ) -> Result<(), AccountError> {
        let mut authority = self.lock_authority();
        #[cfg(test)]
        store_probe::entered(store_probe::StoreOp::CommitGrant, &self.config.store_dir);
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
        #[cfg(test)]
        store_probe::entered(store_probe::StoreOp::RefreshTokens, &self.config.store_dir);
        storage::commit::refresh_tokens(&self.config, &mut authority, account, expected, record)
    }

    /// Durably tombstone the current generation before reporting success.
    pub(crate) fn revoke(&self, account: &AccountKey) -> Result<(), AccountError> {
        let mut authority = self.lock_authority();
        #[cfg(test)]
        store_probe::entered(store_probe::StoreOp::Revoke, &self.config.store_dir);
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

// ── Gateway-facing custody bootstrap ─────────────────────────────────────────
//
// The live path. `start_custody` builds the real refresh provider, awaits its
// EAGER bootstrap, and only then opens the store and claims its two exclusive
// locks. A gateway that reaches Serving therefore holds a provider whose issuer
// metadata is already validated and pinned; there is no later discovery for a
// refresh to perform, and no half-started custody to observe.
//
// ORDER IS THE CONTRACT. Provider first, store second. A store opened before a
// descriptor was rejected would hold both file locks for a deployment that is
// about to refuse startup, and the operator's next attempt would fail on the
// locks rather than on the configuration that is actually wrong.
//
// Names are fully qualified through `service::` on purpose: `worker.rs` already
// imports the same six, and an import here would be one more chance to collide.

/// The non-secret lease a managed credential was released under.
///
/// Exported unconditionally because the REST account registry RETAINS it beside
/// the prepared credential: its recheck before the inner cache and before egress
/// is `VaultStrategy::recheck`, the real custody release, which needs the lease
/// this dispatch's credential came from. A lease is a binding, never authority.
pub(crate) use service::CredentialLease;
#[cfg(test)]
pub(crate) use service::{
    CredentialReleaseObserver, ProviderRefreshError, RefreshProvider, ReleasedCredentials,
    TokenRefresh,
};
#[cfg(test)]
pub(crate) use worker::CustodyHandle;
pub(crate) use worker::{CustodyError, CustodyStartError};

/// The managed-account dispatch strategy and the object-safe custody it runs
/// against. The gateway installs one `VaultStrategy` per bound backend; both
/// consumers reach it through the existing identity-propagation resolver.
pub(crate) use vault::{AccountCustody, VaultStrategy};

/// The one refresh provider a gateway runs: the real policy over the real
/// transport, the system clock, and the gateway's own environment overlay.
pub(crate) type GatewayRefreshProvider = provider::PersonalOAuthRefresh<
    provider::GatewayProviderHttp,
    provider::SystemClock,
    provider::EnvSecrets,
>;

/// The production transport type, nameable by tests that must hand a
/// configured instance to a real startup. Test-gated: no production caller
/// constructs one anywhere but `start_custody`.
#[cfg(test)]
pub(crate) use provider::GatewayProviderHttp;

/// Non-secret record that a credential passed the release recheck.
///
/// Names the backend and the resource and nothing else: no principal subject,
/// no authority, no token. WHERE this ultimately belongs (a metric, the
/// transparency log, neither) is an open runtime decision, named in the handoff
/// rather than settled here.
pub(crate) struct AccountReleaseAudit;

impl service::CredentialReleaseObserver for AccountReleaseAudit {
    fn on_release(
        &self,
        account: &AccountKey,
        lease: &service::CredentialLease,
        _credentials: &service::ReleasedCredentials,
    ) {
        // ci-allow-secret-log: token_revision is a nonsecret u64 monotonic revision counter copied from GrantRecord.token_revision and advanced with checked_add(1); it carries no token bytes.
        tracing::debug!(
            backend = %account.backend_id,
            resource = %account.resource,
            token_revision = lease.token_revision,
            "personal account credential released"
        );
    }
}

/// The one custody type a gateway holds.
pub(crate) type GatewayCustody = worker::CustodyHandle<GatewayRefreshProvider, AccountReleaseAudit>;

/// Why managed custody could not be brought up.
///
/// Three failures a caller must not confuse: a deployment that is
/// misconfigured, a descriptor whose issuer metadata was not acceptable, and a
/// store another owner already holds.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CustodyBootstrapError {
    #[error(transparent)]
    Config(#[from] config::AccountsConfigError),
    #[error(transparent)]
    Provider(#[from] provider::ProviderBuildError),
    #[error(transparent)]
    Start(#[from] CustodyStartError),
}

/// Bring managed custody up: real provider, then exactly one custody handle.
///
/// Reached only after the Gateway has resolved a real `accounts` block, so a
/// misconfigured deployment still fails as a configuration error first.
///
/// `descriptors` are the configured ones as written, keyed by logical account
/// id. An empty map is ordinary: a store-only deployment brings custody up with
/// no HTTP and no secret read.
///
/// The store open is synchronous filesystem work that takes two exclusive file
/// locks, so it runs on a blocking thread rather than on the event loop — the
/// same rule every other store call in this module already follows.
pub(crate) async fn start_custody(
    store: StoreConfig,
    descriptors: BTreeMap<String, config::AccountDescriptor>,
    env: std::sync::Arc<crate::config::LiveEnv>,
) -> Result<GatewayCustody, CustodyBootstrapError> {
    // The production transport, built here and nowhere else.
    start_custody_with_http(
        provider::GatewayProviderHttp::new()?,
        store,
        descriptors,
        env,
    )
    .await
}

/// [`start_custody`] with the transport supplied rather than built.
///
/// SAME type, SAME order, SAME body: this is the function `start_custody` now
/// is, with one argument lifted. It exists so a test can drive the REAL startup
/// against a real loopback endpoint, and deliberately not as a provider seam —
/// there is no trait here, no factory and no way to pass anything that is not
/// the production client.
pub(crate) async fn start_custody_with_http(
    http: provider::GatewayProviderHttp,
    store: StoreConfig,
    descriptors: BTreeMap<String, config::AccountDescriptor>,
    env: std::sync::Arc<crate::config::LiveEnv>,
) -> Result<GatewayCustody, CustodyBootstrapError> {
    // Awaited HERE, before the store is touched: every managed descriptor's
    // issuer metadata is fetched, validated and pinned, or nothing starts.
    let refresh = provider::PersonalOAuthRefresh::bootstrap(
        descriptors,
        http,
        provider::SystemClock,
        provider::EnvSecrets::new(env),
    )
    .await?;
    let handle = tokio::task::spawn_blocking(move || {
        worker::CustodyHandle::start(
            store,
            refresh,
            AccountReleaseAudit,
            worker::DEFAULT_CAPACITY,
        )
    })
    .await
    // A panic opening the store is a bug, not a domain outcome; re-raising is
    // the honest answer, and matches how the worker treats its own blocking
    // failures.
    .expect("custody start blocking worker")?;
    Ok(handle)
}

// ── Offline store initialization ─────────────────────────────────────────────
//
// The ONLY public surface of this module besides the `AccountsConfig` DTO.
// Everything else — the store, the service, the worker, `StoreConfig` and the
// raw key bytes it carries — stays crate-private, so `accounts init-store`
// cannot reach past custody to the records themselves.

/// What an offline initialization created, for an operator to read back.
///
/// Paths and non-secret names only: no key material, no key bytes, and no
/// account identity. `secret_refs_read` names the environment variables the
/// resolution looked up, which is what makes "which key did it read" answerable
/// without printing what it read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedStore {
    /// `accounts.instance_id` the fresh authority was sealed for.
    pub instance_id: String,
    /// The configured record root.
    pub store_dir: PathBuf,
    /// The configured authority root.
    pub authority_dir: PathBuf,
    /// Environment variable NAMES read while resolving keys, sorted.
    pub secret_refs_read: Vec<String>,
}

/// Why offline initialization was refused. Carries no key material.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OfflineInitError {
    /// The configuration declares no `accounts` block at all. Initializing a
    /// store the deployment never asked for would create custody state nothing
    /// opens, so absence is refused rather than defaulted.
    #[error("configuration declares no accounts block; there is no store to initialize")]
    NotConfigured,
    /// The `accounts` block is invalid, or a declared key reference did not
    /// resolve against the config's own env-file overlay.
    #[error("accounts configuration refused: {0}")]
    Configuration(String),
    /// The existing storage initializer refused: a configured root already
    /// holds records or a manifest, a root is not a private directory, or
    /// another owner holds the store locks. Existing state is never replaced,
    /// and nothing is migrated into a store this command creates.
    #[error("accounts store initialization refused: {0}")]
    Refused(String),
}

/// Create a fresh empty account authority for an already-loaded configuration.
///
/// OFFLINE AND EXPLICIT. This is the only path that may create a store, and it
/// is never reached by daemon startup: `serve` opens an existing authority or
/// fails. Nothing here launches a gateway, starts the custody worker, builds an
/// HTTP client or reaches the network, and no token is read, written or
/// migrated — a store this creates has zero records by construction.
///
/// The existing initializer stays authoritative for everything it already
/// owns: it validates and locks both roots, requires them empty, generates the
/// random store epoch and seals the encrypted authority. No crypto, no path
/// rule and no emptiness rule is reimplemented here; this resolves the
/// configuration through the existing `config::resolve` and hands the resolved
/// `StoreConfig` straight to it.
///
/// `overlay` is the environment the config was evaluated against — an env file
/// loads into an overlay and is never exported, so the caller must pass the
/// overlay its `env_files` produced rather than the process environment.
///
/// The store handle is dropped before returning, releasing both exclusive
/// locks: this command initializes and exits, it does not hold custody open.
///
/// # Errors
///
/// [`OfflineInitError::NotConfigured`] when `accounts` is absent,
/// [`OfflineInitError::Configuration`] when the block or a key reference is
/// invalid, and [`OfflineInitError::Refused`] when the configured roots already
/// hold state or are otherwise unusable as a private store.
pub fn initialize_store_offline(
    gateway_config: &crate::config::Config,
    overlay: &crate::config::EnvOverlay,
) -> Result<InitializedStore, OfflineInitError> {
    let resolved = config::resolve(gateway_config.accounts.as_ref(), overlay)
        .map_err(|error| OfflineInitError::Configuration(error.to_string()))?
        .ok_or(OfflineInitError::NotConfigured)?;

    // Read back before the resolved config is moved into the initializer. Names
    // and paths only; `StoreConfig::keys` never leaves this function.
    let report = InitializedStore {
        instance_id: resolved.store.instance_id.clone(),
        store_dir: resolved.store.store_dir.clone(),
        authority_dir: resolved.store.authority_dir.clone(),
        secret_refs_read: resolved.secret_refs_read.clone(),
    };

    let store = PersonalAccountStore::initialize(resolved.store)
        .map_err(|error| OfflineInitError::Refused(error.to_string()))?;
    // Explicit, not incidental: the locks are released here, and no worker,
    // provider or gateway ever sees this handle.
    drop(store);

    Ok(report)
}

#[cfg(test)]
mod tests;
