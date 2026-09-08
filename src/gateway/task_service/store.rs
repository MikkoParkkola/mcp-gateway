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
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};

use super::record::{CommittedTask, PreparedTask, RECORD_VERSION, Record};
use crate::fs_lock::ExclusiveFileLock;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

/// The one sidecar a fresh store creates. Deliberately not a `task-*.json` name,
/// so the loader can never mistake custody state for a record.
const LEASE: &str = "store.lease";
const RECORD_MODE: u32 = 0o600;
const STORE_MODE: u32 = 0o700;
/// Attempts to find an unused temporary name before giving up, mirroring the
/// reviewed `oauth::storage::create_secret_tmp` retry bound.
const TEMP_ATTEMPTS: u64 = 8;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("task store unavailable")]
    Unavailable,
    #[error("unsafe task store")]
    UnsafeStore,
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
}

struct Shared {
    dir: PathBuf,
    limits: StoreLimits,
    /// Held for the whole of a mutation, on a blocking thread. `close` takes it
    /// too, which is how shutdown joins a writer instead of racing it.
    order: Mutex<()>,
    state: Mutex<State>,
    lease: Mutex<Option<ExclusiveFileLock>>,
    hook: Mutex<Option<CommitHook>>,
    temp: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct TaskStore(Arc<Shared>);

impl TaskStore {
    pub(super) async fn open(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        let dir = path.to_owned();
        let opened = dir.clone();
        let (lease, entries) = tokio::task::spawn_blocking(move || open_blocking(&opened, limits))
            .await
            .map_err(|_| StoreError::Storage)??;
        Ok(Self(Arc::new(Shared {
            dir,
            limits,
            order: Mutex::new(()),
            state: Mutex::new(State {
                ready: true,
                entries,
            }),
            lease: Mutex::new(Some(lease)),
            hook: Mutex::new(None),
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
        Ok(CommittedTask {
            task: entry.task.clone(),
            revision: entry.record.revision,
        })
    }

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

    pub(super) fn ready(&self) -> bool {
        self.0.state().ready
    }

    #[cfg(test)]
    pub(super) async fn set_hook(&self, hook: Option<CommitHook>) {
        *self.0.hook.lock().unwrap_or_else(PoisonError::into_inner) = hook;
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
            return Ok(CommittedTask {
                revision: record.revision,
                task,
            });
        }
        // Unreachable in practice; a record that can hold no further revision is
        // out of room rather than broken.
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        record.model = task.snapshot();
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
        let revision = record.revision;
        let committed = task.clone();
        self.state()
            .entries
            .insert(task.id().to_owned(), Entry { task, record });
        CommittedTask {
            task: committed,
            revision,
        }
    }

    /// The test-only commit hook. Production installs none and pays nothing.
    #[cfg(test)]
    fn hook(&self) -> Option<CommitHook> {
        self.hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[cfg(not(test))]
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
        .filter(|entry| entry.record.admission.principal_digest == *principal)
        .count();
    if size > limits.record_bytes || mine >= limits.per_principal {
        return Err(StoreError::Capacity);
    }
    fits(limits, state.entries.len())
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

fn open_blocking(
    dir: &Path,
    limits: StoreLimits,
) -> Result<(ExclusiveFileLock, BTreeMap<String, Entry>), StoreError> {
    prepare_dir(dir)?;
    let lease = acquire_lease(&dir.join(LEASE))?;
    Ok((lease, load(dir, limits)?))
}

fn prepare_dir(dir: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() || !has_mode(&meta, STORE_MODE) {
                tracing::warn!(path = %dir.display(), "task store directory is not a private directory");
                return Err(StoreError::UnsafeStore);
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_dir(dir),
        Err(error) => {
            tracing::warn!(%error, path = %dir.display(), "task store directory unreadable");
            Err(StoreError::Unavailable)
        }
    }
}

fn acquire_lease(lease: &Path) -> Result<ExclusiveFileLock, StoreError> {
    match fs::symlink_metadata(lease) {
        Ok(meta) => {
            if !meta.is_file() || !has_mode(&meta, RECORD_MODE) {
                tracing::warn!(path = %lease.display(), "task store lease is not a private regular file");
                return Err(StoreError::UnsafeStore);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, path = %lease.display(), "task store lease unreadable");
            return Err(StoreError::Unavailable);
        }
    }
    ExclusiveFileLock::try_acquire(lease).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            return StoreError::AlreadyOwned;
        }
        // Includes the platforms with no tested exclusion primitive: they refuse
        // custody outright rather than pretend to hold it.
        tracing::warn!(%error, path = %lease.display(), "task store lease not acquired");
        StoreError::Unavailable
    })
}

/// Read every record. Any unreadable, foreign-moded, non-regular, unsupported,
/// duplicated or over-budget record refuses readiness with the directory left
/// exactly as found. The disk is a trust boundary, so limits apply here too and
/// the cap is enforced on the BYTES ACTUALLY READ rather than on a stat taken
/// beforehand — a length observed before the read is a fact about a moment that
/// has already passed.
fn load(dir: &Path, limits: StoreLimits) -> Result<BTreeMap<String, Entry>, StoreError> {
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut principals: BTreeMap<String, usize> = BTreeMap::new();
    for entry in fs::read_dir(dir).map_err(|_| StoreError::Unavailable)? {
        let entry = entry.map_err(|_| StoreError::Unavailable)?;
        let name = entry.file_name();
        // An orphaned temp file, the lease, and anything else is not a record and
        // never becomes one.
        let Some(name) = name.to_str().filter(|name| is_record_name(name)) else {
            continue;
        };
        let path = entry.path();
        // Open first, then judge the OPEN HANDLE. Checking the path and then
        // opening it are two different files if anything swaps the name in
        // between, and a symlink is refused by the open itself rather than by a
        // check that the open could disagree with.
        let mut file = open_record(&path)?;
        let meta = file.metadata().map_err(|_| StoreError::Unavailable)?;
        if !meta.is_file() || !has_mode(&meta, RECORD_MODE) {
            tracing::warn!(path = %path.display(), "task record is not a private regular file");
            return Err(StoreError::UnsafeStore);
        }
        fits(limits, entries.len())?;
        let bytes = read_bounded(&mut file, limits.record_bytes).map_err(|error| {
            if error == StoreError::Capacity {
                tracing::warn!(path = %path.display(), "task record exceeds the record budget");
            }
            error
        })?;
        let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
            tracing::warn!(%error, path = %path.display(), "task record does not parse");
            StoreError::CorruptRecord
        })?;
        if !(1..=RECORD_VERSION).contains(&record.version) {
            tracing::warn!(path = %path.display(), version = record.version, "unsupported task record version");
            return Err(StoreError::CorruptRecord);
        }
        let task = Task::from_snapshot(record.model.clone()).map_err(|error| {
            tracing::warn!(%error, path = %path.display(), "task record does not restore");
            StoreError::CorruptRecord
        })?;
        // A record living under another task's name would let a rename rebind it.
        if record_name(task.id()) != name
            || !identities.insert(record.admission.identity_digest.clone())
        {
            tracing::warn!(path = %path.display(), "task record identity or name is not its own");
            return Err(StoreError::CorruptRecord);
        }
        let held = principals
            .entry(record.admission.principal_digest.clone())
            .or_default();
        *held += 1;
        if *held > limits.per_principal {
            tracing::warn!(path = %path.display(), "stored tasks exceed the per-principal cap");
            return Err(StoreError::Capacity);
        }
        entries.insert(task.id().to_owned(), Entry { task, record });
    }
    Ok(entries)
}

/// Read at most `cap` bytes, refusing as soon as one more than that arrives.
/// Reading a byte past the cap is what makes "too large" observable without ever
/// allocating the oversized content it is refusing.
/// `pub(super)` only so the bound itself can be asserted directly rather than
/// inferred from a store-level outcome. Still module-private.
pub(super) fn read_bounded(file: &mut fs::File, cap: usize) -> Result<Vec<u8>, StoreError> {
    use std::io::Read as _;

    let ceiling = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(ceiling)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Unavailable)?;
    if bytes.len() > cap {
        return Err(StoreError::Capacity);
    }
    Ok(bytes)
}

/// Open a record without following a symlink, so the thing judged and the thing
/// read are the same file.
#[cfg(unix)]
fn open_record(path: &Path) -> Result<fs::File, StoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
        .map_err(|error| {
            tracing::warn!(%error, path = %path.display(), "task record could not be opened as a private regular file");
            StoreError::UnsafeStore
        })
}

#[cfg(not(unix))]
fn open_record(path: &Path) -> Result<fs::File, StoreError> {
    if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return Err(StoreError::UnsafeStore);
    }
    fs::File::open(path).map_err(|_| StoreError::UnsafeStore)
}

enum Fault {
    BeforeRename(io::Error),
    AfterRename(io::Error),
}

/// Write one record durably: private temp, payload, file sync, rename, directory
/// sync. Failure before the rename is a clean refusal; failure at or after it
/// leaves durability uncertain, which is the caller's cue to poison readiness.
fn write_record(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    hook: Option<&CommitHook>,
    counter: &AtomicU64,
) -> Result<(), Fault> {
    // Nothing is removed before this point: a colliding orphan belongs to some
    // earlier attempt and is stepped over, never deleted.
    let (file, temp) = create_temp(dir, name, counter).map_err(Fault::BeforeRename)?;
    let staged = stage_temp(file, bytes, hook)
        .and_then(|()| fire(hook, CommitStage::Rename))
        .and_then(|()| fs::rename(&temp, dir.join(name)));
    if let Err(error) = staged {
        let _ = fs::remove_file(&temp);
        return Err(Fault::BeforeRename(error));
    }
    fire(hook, CommitStage::DirectorySync)
        .and_then(|()| sync_dir(dir))
        .map_err(Fault::AfterRename)
}

/// Claim a private temporary file, retrying past a name some earlier attempt
/// left behind. Mirrors the reviewed `oauth::storage::create_secret_tmp`: the
/// process id keeps two processes apart, the counter keeps two attempts apart,
/// and a collision costs a nonce rather than another writer's evidence.
fn create_temp(dir: &Path, name: &str, counter: &AtomicU64) -> io::Result<(fs::File, PathBuf)> {
    for _ in 0..TEMP_ATTEMPTS {
        let nonce = counter.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(format!("{name}.tmp.{}.{nonce}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        set_owner_only(&mut options);
        match options.open(&temp) {
            Ok(file) => {
                // `mode` is masked by the process umask; the record is private
                // regardless of how the surrounding process was configured.
                force_owner_only(&file)?;
                return Ok((file, temp));
            }
            // A stale temp holds this name; take the next nonce and leave it be.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unused task record temporary name",
    ))
}

fn stage_temp(mut file: fs::File, bytes: &[u8], hook: Option<&CommitHook>) -> io::Result<()> {
    use std::io::Write as _;

    fire(hook, CommitStage::Write)?;
    file.write_all(bytes)?;
    fire(hook, CommitStage::Flush)?;
    file.sync_all()?;
    fire(hook, CommitStage::FileSync)
}

fn fire(hook: Option<&CommitHook>, stage: CommitStage) -> io::Result<()> {
    hook.map_or(Ok(()), |hook| hook(stage))
}

#[cfg(unix)]
fn has_mode(meta: &fs::Metadata, expected: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o7777 == expected
}

#[cfg(not(unix))]
fn has_mode(_meta: &fs::Metadata, _expected: u32) -> bool {
    true
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(STORE_MODE)
        .create(dir)
        .and_then(|()| fs::set_permissions(dir, fs::Permissions::from_mode(STORE_MODE)))
        .map_err(|error| {
            tracing::warn!(%error, path = %dir.display(), "task store directory not created");
            StoreError::Unavailable
        })
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(dir).map_err(|_| StoreError::Unavailable)
}

#[cfg(unix)]
fn set_owner_only(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(RECORD_MODE);
}

#[cfg(not(unix))]
fn set_owner_only(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn force_owner_only(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(RECORD_MODE))
}

#[cfg(not(unix))]
fn force_owner_only(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

/// Make the rename itself durable. Opening a directory as a file is not portable,
/// and the durability target for this store is Linux and macOS.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// The S1 store surface: restart enumeration and the conditional durable expiry
/// that couples a record's deletion to its dedupe entry.
impl TaskStore {
    /// Every committed record's persisted binding, paired with its task id, for
    /// startup import BEFORE serving. Owned values: the state they are read from
    /// lives behind a mutex.
    pub(super) fn restored_bindings(
        &self,
    ) -> Vec<(crate::idempotency::admission::RestoredBinding, String)> {
        let state = self.0.state();
        state
            .entries
            .iter()
            .map(|(id, entry)| {
                let admission = &entry.record.admission;
                (
                    crate::idempotency::admission::RestoredBinding {
                        identity: admission.identity_digest.clone(),
                        principal_digest: admission.principal_digest.clone(),
                        operation: admission.operation_digest.clone(),
                        representation: admission.representation_digest.clone(),
                        metadata_bytes: admission.metadata_bytes,
                    },
                    id.clone(),
                )
            })
            .collect()
    }

    /// Delete one terminal record and drop its dedupe entry TOGETHER, per §13.3.
    ///
    /// `revision` is the caller's expectation and is checked before anything is
    /// deleted, so a task that moved on is refused rather than removed. Nothing
    /// here resets a TTL or a poll interval: expiry ends a task's life, it does
    /// not extend it.
    pub(super) async fn expire(
        &self,
        id: &str,
        revision: u64,
        admission: &Arc<crate::idempotency::admission::ExecutionAdmission>,
    ) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        let id = id.to_owned();
        let admission = Arc::clone(admission);
        tokio::task::spawn_blocking(move || shared.expire_blocking(&id, revision, &admission))
            .await
            .map_err(|_| StoreError::Storage)?
    }
}

impl Shared {
    /// The expiry transaction. The admission guard is opened AFTER the store's
    /// ordering lock and BEFORE the deletion, and held across the COMPLETE
    /// deletion commit — unlink, directory sync, readable-state removal — and
    /// the dedupe release. `admit_task` takes that same mutex, so no admission
    /// path can observe a half-finished expiry.
    ///
    /// The guard never crosses an `await`: this whole function runs inside one
    /// `spawn_blocking` closure.
    fn expire_blocking(
        &self,
        id: &str,
        revision: u64,
        admission: &Arc<crate::idempotency::admission::ExecutionAdmission>,
    ) -> Result<(), StoreError> {
        let _order = self.order();
        let identity = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = state.entries.get(id).ok_or(StoreError::NotFound)?;
            if entry.record.revision != revision {
                return Err(StoreError::RevisionConflict);
            }
            // Conditional on the record being terminal: a running task is not
            // expiry's to end.
            if !matches!(
                entry.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return Err(StoreError::InvalidTransition);
            }
            entry.record.admission.identity_digest.clone()
        };

        let guard = admission.expiry_guard(&identity);
        match guard.published_task() {
            // The dedupe entry must name THIS task: an identity that owns some
            // other id is not this record's, and deleting it would strand both.
            Some((task_id, _)) if task_id == id => {}
            _ => return Err(StoreError::NotFound),
        }

        // An already-absent record is a deletion to FINISH, not an error: a
        // previous attempt whose directory sync failed left exactly that state,
        // and refusing it would strand the entry and its capacity until restart.
        let path = self.dir.join(record_name(id));
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, task = %id, "task record not deleted");
                return Err(StoreError::Storage);
            }
        }
        let hook = self.hook();
        fire(hook.as_ref(), CommitStage::DirectorySync)
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|error| {
                tracing::warn!(%error, task = %id, "task record deletion not made durable");
                StoreError::Storage
            })?;
        fire(hook.as_ref(), CommitStage::Deleted).map_err(|_| StoreError::Storage)?;

        // Readable view follows the durable one, then the dedupe entry and its
        // capacity go back — all still inside the guard.
        self.state().entries.remove(id);
        guard.release();
        Ok(())
    }
}
