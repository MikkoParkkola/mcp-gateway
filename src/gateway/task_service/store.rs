// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ordered file store: one durable JSON record per task, one process-wide owner.
//!
//! Reads are served from the committed in-memory image, so a caller-supplied task
//! identifier is only ever a map key. A filename is derived exclusively from an
//! identifier the shared task model has already validated as `task-<uuid v4>`.
//!
//! Every mutation runs to completion on a blocking thread while holding the
//! ordering lock, so dropping the caller's future cannot leave the directory
//! ahead of the committed image. Losing the *answer* to a cancelled call is
//! acceptable; losing the publish or the poison that follows a write is not.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::record::{
    AdmissionRecord, CommittedTask, MAX_UPSTREAM_HANDLE_BYTES, PreparedTask, Record,
    UPSTREAM_VERSION, UpstreamRecord, widest_handle_reservation,
};
use crate::fs_lock::ExclusiveFileLock;
#[cfg(test)]
use chrono::{DateTime, Utc};
#[cfg(test)]
use disk::acquire_lease;
#[cfg(test)]
pub(super) use disk::after_load;
#[cfg(test)]
pub(super) use disk::read_bounded;
use disk::{Fault, fire, open_blocking, write_record};
#[path = "store_disk.rs"]
mod disk;
#[path = "store_expiry.rs"]
mod expiry;
#[path = "store_input.rs"]
pub(crate) mod input;
#[cfg(test)]
#[path = "store_lease_tests.rs"]
mod lease_tests;
#[cfg(unix)]
#[path = "store_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "store_windows.rs"]
mod platform;
#[path = "store_targets.rs"]
pub(crate) mod targets;
#[cfg(test)]
use crate::protocol::tasks::TaskTransition;
use crate::protocol::tasks::{Task, TaskStatus};

/// The one sidecar a fresh store creates. Deliberately not a `task-*.json` name,
/// so the loader can never mistake custody state for a record.
const LEASE: &str = "store.lease";
const RECORD_MODE: u32 = 0o600;
const STORE_MODE: u32 = 0o700;
/// Attempts to find an unused temporary name before giving up, mirroring the
/// reviewed `oauth::storage::create_secret_tmp` retry bound.
const TEMP_ATTEMPTS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("task store unavailable")]
    Unavailable,
    #[error("unsafe task store")]
    UnsafeStore,
    /// The store directory or lease could not be inspected (not absent, not
    /// unsafe): a failure to look, distinct from `Unavailable`.
    #[error("task store path could not be inspected")]
    Uninspectable,
    #[error("corrupt task record")]
    CorruptRecord,
    #[error("task store is already owned")]
    AlreadyOwned,
    #[error("task not found")]
    NotFound,
    #[error("task revision changed")]
    RevisionConflict,
    #[error("task capacity exceeded")]
    Capacity,
    #[error("task storage operation failed")]
    Storage,
    /// The model refused the offered event, whether as a malformed payload or as
    /// an illegal transition. Nothing was serialized and nothing was written.
    #[error("invalid task transition")]
    InvalidTransition,
    /// The offered record reuses a live task identifier or admission identity.
    /// Writing it would replace a task or leave a store the loader will reject.
    #[error("duplicate task record")]
    Duplicate,
}

/// Bounds on durable task count and encoded record bytes, enforced during
/// store opening and before writes. `Default` supplies the gateway defaults.
#[derive(Clone, Copy)]
pub struct StoreLimits {
    pub(crate) records: usize,
    pub(crate) per_principal: usize,
    pub(crate) record_bytes: usize,
    pub(crate) logical_bytes: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            records: 256,
            per_principal: 32,
            record_bytes: 512 * 1024,
            logical_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommitStage {
    Write,
    Flush,
    FileSync,
    Rename,
    DirectorySync,
    /// Fired between the readable-state insert and the dedupe
    /// publication. Test-only: production installs no hook.
    Published,
    /// Fired between the durable deletion and the dedupe release.
    Deleted,
}

pub(super) type CommitHook = Arc<dyn Fn(CommitStage) -> std::io::Result<()> + Send + Sync>;

/// One committed record and its parsed model. The two are written together and
/// never separately, so `record.model` is always `task.snapshot()`.
struct Entry {
    task: Task,
    record: Record,
}

struct State {
    ready: bool,
    entries: BTreeMap<String, Entry>,
    /// Rows skipped at load whose keys stay taken (MIK-8023), and the file
    /// names of rows whose key could not be read, which seal new keyed
    /// admissions (MIK-8052). Their files stay; both still count against the
    /// store's caps.
    reserved: Vec<(AdmissionRecord, String)>,
    sealed: BTreeSet<String>,
}

/// How many rows the last load skipped, by whether each kept its key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SkippedRecords {
    pub(crate) reserved: usize,
    pub(crate) sealed: usize,
}

struct Shared {
    dir: PathBuf,
    limits: StoreLimits,
    /// Held for the whole of a mutation, on a blocking thread. `close` takes it
    /// too, which is how shutdown joins a writer instead of racing it.
    order: Mutex<()>,
    state: Mutex<State>,
    lease: Mutex<Option<ExclusiveFileLock>>,
    /// The store directory's identity at open, so a re-read can tell a removed
    /// record from a directory that moved away or was replaced (MIK-8052).
    dir_id: Option<platform::DirId>,
    #[cfg(test)]
    seams: input::TestSeams,
    temp: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct TaskStore(Arc<Shared>);

impl TaskStore {
    pub(super) async fn open(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        let dir = path.to_owned();
        let opened = dir.clone();
        let (lease, loaded, dir_id) =
            tokio::task::spawn_blocking(move || open_blocking(&opened, limits))
                .await
                .map_err(|_| StoreError::Storage)??;
        for (class, count) in [
            ("reserved", loaded.reserved.len()),
            ("sealed", loaded.sealed.len()),
        ] {
            #[allow(clippy::cast_precision_loss)]
            telemetry_metrics::gauge!("mcp_task_store_skipped_records", "class" => class)
                .set(count as f64);
        }
        Ok(Self(Arc::new(Shared {
            dir,
            limits,
            order: Mutex::new(()),
            state: Mutex::new(State {
                ready: true,
                entries: loaded.entries,
                reserved: loaded.reserved,
                sealed: loaded.sealed,
            }),
            lease: Mutex::new(Some(lease)),
            dir_id,
            #[cfg(test)]
            seams: input::TestSeams::default(),
            temp: AtomicU64::new(0),
        })))
    }

    pub(super) async fn create(&self, task: PreparedTask) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (record, publication) = (task.record, task.publication);
        tokio::task::spawn_blocking(move || shared.create_blocking(record, publication))
            .await
            .map_err(|_| StoreError::Storage)?
    }

    pub(crate) fn get(&self, owner: &str, id: &str) -> Result<CommittedTask, StoreError> {
        let state = self.0.state();
        if !state.ready {
            return Err(StoreError::Unavailable);
        }
        let entry = owned(&state, owner, id)?;
        Ok(CommittedTask::of(entry.task.clone(), &entry.record))
    }

    #[cfg(test)]
    pub(crate) async fn transition(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.transition_blocking(&owner, &id, revision, event, at)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Durably set the dispatch marker at `expected_revision`. The public
    /// revision, model and TTL are unchanged; a failed write does not claim
    /// dispatch. Terminal records and moved revisions refuse without writing.
    pub(crate) async fn mark_dispatched(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.mark_dispatched_blocking(&owner, &id, expected_revision)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Durably attach `upstream` to a non-terminal row at `expected_revision`.
    ///
    /// The `mark_dispatched` idiom exactly: read-modify-write inside the same
    /// ordering-lock section, refusing a moved revision or a terminal row, and
    /// NOT bumping `revision` — no reader observes the field, so the settle CAS
    /// is untouched. It does raise `version` to [`UPSTREAM_VERSION`], because
    /// the row now holds a field an older loader must not silently drop.
    ///
    /// A row is recoverable only once this write has landed. Until then the
    /// crash window is `unknown`, never `not_executed` and never claimed.
    pub(crate) async fn mark_upstream(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
        upstream: UpstreamRecord,
    ) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.mark_upstream_blocking(&owner, &id, expected_revision, upstream)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// The owner-scoped upstream descriptor of one committed row, with the
    /// revision and status it was read at.
    ///
    /// Owner-scoped through [`owned`], so a foreign caller is told the task is
    /// absent and learns nothing about a handle. A descriptor that does not
    /// belong to the record it was read from is dropped here rather than
    /// returned: a read path may not authorize against an inconsistent target.
    pub(crate) fn upstream_of(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<(Option<UpstreamRecord>, u64, TaskStatus), StoreError> {
        let state = self.0.state();
        if !state.ready {
            return Err(StoreError::Unavailable);
        }
        let entry = owned(&state, owner, id)?;
        let descriptor = entry
            .record
            .upstream
            .clone()
            .filter(|upstream| upstream.consistent_with(&entry.record.admission));
        Ok((descriptor, entry.record.revision, entry.task.status()))
    }

    /// Whether the committed row could still hold the COMPLETE recovery
    /// descriptor for `(backend, tool, arguments)` and the widest handle a peer
    /// may answer with.
    ///
    /// Measured, never estimated: the candidate is the record as it stands with
    /// the descriptor `mark_upstream` would attach, serialized by the same
    /// [`serialize`] the write uses and compared against the same
    /// `record_bytes` bound. JSON escaping is therefore counted by
    /// construction — an argument whose bytes fit but whose ENCODING does not is
    /// refused here — and the handle is reserved at
    /// [`widest_handle_reservation`], so no answer this store would accept can
    /// make a measured-fitting descriptor overflow afterwards. There is no
    /// arithmetic to overflow: nothing is added up, one candidate is encoded.
    ///
    /// Owner-scoped through [`owned`] and read-only: it takes no ordering lock,
    /// writes nothing, and tells a foreign caller only what an absent task
    /// tells it. Conservative at the revision it is asked at — `dispatched` is
    /// still `false`, which encodes one byte WIDER than the `true` the row will
    /// carry when the descriptor is written — and `mark_upstream`'s own check
    /// stays the authority over anything that grows in between.
    pub(crate) fn admits_upstream_descriptor(
        &self,
        owner: &str,
        id: &str,
        backend: &str,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> Result<bool, StoreError> {
        let mut candidate = {
            let state = self.0.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            owned(&state, owner, id)?.record.clone()
        };
        // The record's OWN admitted digest, exactly as `capture_upstream` binds
        // it: measuring against a digest derived a second time would measure a
        // descriptor this record could never be given.
        let operation_digest = candidate.admission.operation_digest.clone();
        candidate.upstream = Some(UpstreamRecord {
            handle: widest_handle_reservation(),
            backend: backend.to_owned(),
            tool: tool.to_owned(),
            arguments: arguments.clone(),
            operation_digest,
        });
        candidate.version = candidate.version.max(UPSTREAM_VERSION);
        Ok(serialize(&candidate)?.len() <= self.0.limits.record_bytes)
    }

    /// Test-only: the durable recovery descriptor of `id`, whatever owner holds
    /// it.
    ///
    /// Owner-agnostic on purpose. A route-level regression knows the task
    /// identifier the client was answered with and nothing else; reproducing
    /// admission's principal hashing to read what dispatch persisted would put
    /// the test's own derivation between it and the record. It is a read of the
    /// committed image and exists only under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn upstream_for_test(&self, id: &str) -> Option<UpstreamRecord> {
        self.0
            .state()
            .entries
            .get(id)
            .and_then(|entry| entry.record.upstream.clone())
    }

    /// The admitted operation digest of one owner-scoped row.
    ///
    /// Read, never recomputed: the dispatch path binds its recovery descriptor
    /// to the digest the record itself was admitted under.
    pub(crate) fn operation_digest_of(&self, owner: &str, id: &str) -> Option<String> {
        let state = self.0.state();
        if !state.ready {
            return None;
        }
        owned(&state, owner, id)
            .ok()
            .map(|entry| entry.record.admission.operation_digest.clone())
    }

    #[cfg(test)]
    pub(super) fn ready(&self) -> bool {
        self.0.state().ready
    }

    #[cfg(test)]
    pub(super) async fn set_hook(&self, hook: Option<CommitHook>) {
        self.0.seams.set_hook(hook);
    }

    /// Stop serving and release custody — after any mutation already in flight
    /// has finished, so a second process cannot open the directory while this
    /// one is still writing to it.
    pub(super) async fn close(self) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || shared.close_blocking())
            .await
            .map_err(|_| StoreError::Storage)
    }

    /// Admit no further mutation, without waiting for one in flight
    /// (MIK-7839.CANCEL.3). Every mutation checks `ready` under the ordering
    /// lock before it writes, so one not yet past that check is refused; one
    /// already past it was admitted earlier and finishes. Takes only the state
    /// lock, never the ordering lock, so a caller in `Drop` never waits on disk.
    pub(crate) fn stop_serving(&self) {
        self.0.state().ready = false;
    }
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn order(&self) -> MutexGuard<'_, ()> {
        self.order.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn create_blocking(
        &self,
        record: Record,
        publication: Option<crate::idempotency::admission::TaskPublication>,
    ) -> Result<CommittedTask, StoreError> {
        let _order = self.order();
        // The model validates the identifier; only then does it become a filename.
        let task =
            Task::from_snapshot(record.model.clone()).map_err(|_| StoreError::CorruptRecord)?;
        let bytes = serialize(&record)?;
        {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            reject_duplicate(&state, task.id(), &record)?;
            admit(&state, self.limits, &record, bytes.len())?;
        }
        // Room for the bounded failure this task may have to settle as, or a
        // too-large outcome would leave it working (MIK-7651).
        if targets::fallback_bytes(&task, &record, self.now())? > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        // Readable FIRST, discoverable second. Reversed, a retry could be told
        // the task exists and then fail to read it.
        let committed = self.publish(task, record);
        let hook = self.hook();
        let hook_result = fire(hook.as_ref(), CommitStage::Published);
        if let Some(publication) = publication {
            publication.publish(committed.task.id());
        }
        hook_result.map_err(|_| StoreError::Storage)?;
        Ok(committed)
    }

    #[cfg(test)]
    fn transition_blocking(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let _order = self.order();
        let (mut task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.revision != revision {
                return Err(StoreError::RevisionConflict);
            }
            (entry.task.clone(), entry.record.clone())
        };
        let change = task
            .transition(event, at)
            .map_err(|_| StoreError::InvalidTransition)?;
        if !change.changed {
            // A late outcome against a settled task is not a failure and is not
            // a write: the first terminal commit stays the committed one.
            return Ok(CommittedTask::of(task, &record));
        }
        // Unreachable in practice; a record that can hold no further revision is
        // out of room rather than broken.
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        record.set_model(&task);
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(self.publish(task, record))
    }

    fn mark_dispatched_blocking(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        let _order = self.order();
        let (task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.revision != expected_revision {
                return Err(StoreError::RevisionConflict);
            }
            if matches!(
                entry.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return Err(StoreError::InvalidTransition);
            }
            (entry.task.clone(), entry.record.clone())
        };
        record.dispatched = true;
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record);
        Ok(())
    }

    fn mark_upstream_blocking(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
        upstream: UpstreamRecord,
    ) -> Result<(), StoreError> {
        // Bounded before anything is read or written: an over-long handle is
        // refused rather than persisted or truncated, and the row stays
        // unrecoverable — which is the honest state for a handle we do not hold.
        if upstream.handle.len() > MAX_UPSTREAM_HANDLE_BYTES {
            return Err(StoreError::Capacity);
        }
        let _order = self.order();
        let (task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.revision != expected_revision {
                return Err(StoreError::RevisionConflict);
            }
            if matches!(
                entry.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return Err(StoreError::InvalidTransition);
            }
            (entry.task.clone(), entry.record.clone())
        };
        // The descriptor must name the operation this record was admitted for.
        if upstream.operation_digest != record.admission.operation_digest {
            return Err(StoreError::InvalidTransition);
        }
        record.upstream = Some(upstream);
        record.version = record.version.max(UPSTREAM_VERSION);
        let bytes = serialize(&record)?;
        // The descriptor counts against the record budget. Refused BEFORE the
        // write, so an oversized recovery descriptor is never silently omitted
        // from a row the reader would then authorize with missing arguments.
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record);
        Ok(())
    }

    fn close_blocking(&self) {
        // Taking the ordering lock IS the join: a mutation in flight finishes,
        // publishes or poisons, and only then does custody go away.
        let _order = self.order();
        let lease = self
            .lease
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let mut state = self.state();
        state.ready = false;
        state.entries.clear();
        drop(state);
        drop(lease);
    }

    /// Make a committed record visible to readers. Called only after the write
    /// is durable, which is what keeps an acknowledgement behind its record.
    fn publish(&self, task: Task, record: Record) -> CommittedTask {
        let committed = CommittedTask::of(task.clone(), &record);
        self.state()
            .entries
            .insert(task.id().to_owned(), Entry { task, record });
        committed
    }

    /// The test-only commit hook. Production installs none and pays nothing.
    #[cfg(test)]
    fn hook(&self) -> Option<CommitHook> {
        self.seams.hook()
    }

    // `&self` is load-bearing: one shape with the cfg(test) twin above.
    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        reason = "keeps one shape with the cfg(test) twin"
    )]
    fn hook(&self) -> Option<CommitHook> {
        None
    }

    fn commit(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let hook = self.hook();
        match write_record(&self.dir, name, bytes, hook.as_ref(), &self.temp) {
            Ok(()) => Ok(()),
            Err(Fault::BeforeRename(error)) => {
                tracing::warn!(%error, record = %name, "task record write failed before publication");
                Err(StoreError::Storage)
            }
            Err(Fault::AfterRename(error)) => {
                tracing::error!(%error, record = %name, "task record durability uncertain; store poisoned");
                self.state().ready = false;
                Err(StoreError::Storage)
            }
        }
    }
}

fn owned<'a>(state: &'a State, owner: &str, id: &str) -> Result<&'a Entry, StoreError> {
    // A foreign owner is indistinguishable from an absent task, on purpose.
    state
        .entries
        .get(id)
        .filter(|entry| entry.record.admission.principal_digest == owner)
        .ok_or(StoreError::NotFound)
}

/// Refuse a record that would replace a live task or duplicate an admission
/// identity. Uniqueness is the loader's invariant, so the writer has to keep it:
/// otherwise a bad caller leaves a directory that refuses to open next time.
/// Recovering a retried task remains the admission owner's job, not this one's.
fn reject_duplicate(state: &State, id: &str, record: &Record) -> Result<(), StoreError> {
    let identity = &record.admission.identity_digest;
    if state.entries.contains_key(id)
        || state
            .entries
            .values()
            .any(|entry| entry.record.admission.identity_digest == *identity)
    {
        return Err(StoreError::Duplicate);
    }
    Ok(())
}

fn admit(
    state: &State,
    limits: StoreLimits,
    record: &Record,
    size: usize,
) -> Result<(), StoreError> {
    let principal = &record.admission.principal_digest;
    let mine = state
        .entries
        .values()
        .map(|entry| &entry.record.admission)
        .chain(state.reserved.iter().map(|(admission, _)| admission))
        .filter(|admission| admission.principal_digest == *principal)
        .count();
    if size > limits.record_bytes || mine >= limits.per_principal {
        return Err(StoreError::Capacity);
    }
    // A skipped row's file is still on disk and still reserves its allowance.
    fits(
        limits,
        state.entries.len() + state.reserved.len() + state.sealed.len(),
    )
}

/// One more record has to fit both the count cap and the logical budget, where
/// every record reserves its maximum allowance until deletion.
fn fits(limits: StoreLimits, held: usize) -> Result<(), StoreError> {
    let reserved = held
        .checked_add(1)
        .and_then(|records| records.checked_mul(limits.record_bytes));
    if held >= limits.records || reserved.is_none_or(|bytes| bytes > limits.logical_bytes) {
        return Err(StoreError::Capacity);
    }
    Ok(())
}

fn serialize(record: &Record) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(record).map_err(|_| StoreError::Storage)
}

fn record_name(id: &str) -> String {
    format!("{id}.json")
}

fn is_record_name(name: &str) -> bool {
    name.starts_with("task-")
        && Path::new(name)
            .extension()
            .is_some_and(|kind| kind == "json")
}
