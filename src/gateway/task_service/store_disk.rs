// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's disk layer: directory and lease checks, record loading and
//! the durable write path.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::platform::{
    create_private_dir, has_mode, judge_store_dir, open_new_private, open_record, rename, sync_dir,
    sync_file,
};
use super::{
    CommitHook, CommitStage, Entry, LEASE, RECORD_MODE, STORE_MODE, StoreError, StoreLimits,
    TEMP_ATTEMPTS, fits, is_record_name, record_name,
};
use crate::fs_lock::{DirPin, ExclusiveFileLock};
use crate::gateway::task_service::record::{AdmissionRecord, MAX_LOADABLE_VERSION, Record};
use crate::protocol::tasks::Task;

pub(super) fn open_blocking(
    dir: &Path,
    limits: StoreLimits,
) -> Result<(ExclusiveFileLock, Loaded), StoreError> {
    let pin = prepare_dir(dir)?;
    let lease = acquire_lease(&dir.join(LEASE))?.pinning(pin);
    Ok((lease, load(dir, limits)?))
}

fn prepare_dir(dir: &Path) -> Result<DirPin, StoreError> {
    let shown_path = dir.display();
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() || !has_mode(&meta, STORE_MODE) {
                tracing::warn!(path = %shown_path, "task store directory is not a private directory");
                return Err(StoreError::UnsafeStore);
            }
            judge_store_dir(dir)
        }
        // A fresh directory is judged exactly like an existing one.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_dir(dir).and_then(|()| judge_store_dir(dir))
        }
        Err(error) => {
            tracing::warn!(%error, path = %shown_path, "task store directory unreadable");
            Err(StoreError::Uninspectable)
        }
    }
}

pub(super) fn acquire_lease(lease: &Path) -> Result<ExclusiveFileLock, StoreError> {
    let shown_path = lease.display();
    match fs::symlink_metadata(lease) {
        Ok(meta) => {
            if !meta.is_file() || !has_mode(&meta, RECORD_MODE) {
                tracing::warn!(path = %shown_path, "task store lease is not a private regular file");
                return Err(StoreError::UnsafeStore);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, path = %shown_path, "task store lease unreadable");
            return Err(StoreError::Uninspectable);
        }
    }
    ExclusiveFileLock::try_acquire(lease).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            return StoreError::AlreadyOwned;
        }
        // Windows judges the lease's DACL inside `try_acquire`, the check unix
        // makes above with `has_mode`; a lease that is not private is unsafe.
        #[cfg(windows)]
        if error.kind() == io::ErrorKind::PermissionDenied {
            tracing::warn!(%error, path = %shown_path, "task store lease is not private");
            return StoreError::UnsafeStore;
        }
        // Includes the platforms with no tested exclusion primitive: they refuse
        // custody outright rather than pretend to hold it.
        tracing::warn!(%error, path = %shown_path, "task store lease not acquired");
        StoreError::Unavailable
    })
}

/// What `load` found: the tasks it restored, the rows whose task does not
/// restore but whose admission block still reads, and how many rows nothing
/// could be read from.
pub(super) struct Loaded {
    pub(super) entries: BTreeMap<String, Entry>,
    /// Their keys stay taken: a retry finds the original task id, which reads
    /// as not found, and never starts a second task (MIK-8023).
    pub(super) reserved: Vec<(AdmissionRecord, String)>,
    pub(super) unreadable: usize,
}

/// The parts of a record read before, and independently of, the strict
/// parse, each on its own: one malformed member never hides another. Enough to
/// refuse a newer build's row and to keep a damaged row's key.
#[derive(Default)]
struct Envelope {
    version: Option<u64>,
    admission: Option<AdmissionRecord>,
    task_id: Option<String>,
}

impl Envelope {
    /// Walks the record's top-level members in file order and keeps each one
    /// that reads. A syntax error ends the walk but keeps what came before it:
    /// a record cut off inside `model`, which is written after `admission`,
    /// still yields its version and its key.
    fn read(bytes: &[u8]) -> Self {
        let mut envelope = Self::default();
        let _ = serde::Deserializer::deserialize_map(
            &mut serde_json::Deserializer::from_slice(bytes),
            Members(&mut envelope),
        );
        envelope
    }
}

struct Members<'e>(&'e mut Envelope);

impl<'de> serde::de::Visitor<'de> for Members<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a task record")
    }

    /// A duplicated member is damage too, and no later copy may undo what an
    /// earlier one gave: the key and task id keep the first copy that reads
    /// (any readable binding is the safe side), the version keeps the highest
    /// (a newer build's row must refuse whichever copy says so).
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut members: A) -> Result<(), A::Error> {
        while let Some(key) = members.next_key::<String>()? {
            match key.as_str() {
                "version" => {
                    let version = members.next_value::<serde_json::Value>()?.as_u64();
                    self.0.version = self.0.version.max(version);
                }
                "admission" => {
                    let admission = members.next_value::<serde_json::Value>()?;
                    let admission = AdmissionRecord::deserialize(admission).ok();
                    self.0.admission = self.0.admission.take().or(admission);
                }
                "model" => {
                    let model = members.next_value::<serde_json::Value>()?;
                    let task_id = model
                        .pointer("/task/taskId")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    self.0.task_id = self.0.task_id.take().or(task_id);
                }
                _ => {
                    members.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// Read every record. A row that cannot be read is skipped where it lies,
/// never moved or rewritten, and the rest load (MIK-8023): one damaged row no
/// longer refuses the whole store. A row whose admission block still reads
/// keeps its key reserved. What guards the trust boundary still refuses
/// readiness with the directory left exactly as found: a foreign-moded or
/// non-regular file, an over-budget record or store, a name or identity that is
/// not the row's own, and a version newer than this build reads (a downgrade,
/// not damage). The cap is enforced on the BYTES ACTUALLY READ rather than on a
/// stat taken beforehand — a length observed before the read is a fact about a
/// moment that has already passed.
fn load(dir: &Path, limits: StoreLimits) -> Result<Loaded, StoreError> {
    let mut loaded = Loaded {
        entries: BTreeMap::new(),
        reserved: Vec::new(),
        unreadable: 0,
    };
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
        let shown_path = path.display();
        // Open first, then judge the OPEN HANDLE. Checking the path and then
        // opening it are two different files if anything swaps the name in
        // between, and a symlink is refused by the open itself rather than by a
        // check that the open could disagree with.
        let mut file = open_record(&path)?;
        let meta = file.metadata().map_err(|_| StoreError::Unavailable)?;
        if !meta.is_file() || !has_mode(&meta, RECORD_MODE) {
            tracing::warn!(path = %shown_path, "task record is not a private regular file");
            return Err(StoreError::UnsafeStore);
        }
        // Every candidate row counts, skipped ones included: a directory full
        // of damaged rows is still refused before it is all read.
        fits(
            limits,
            loaded.entries.len() + loaded.reserved.len() + loaded.unreadable,
        )?;
        let bytes = read_bounded(&mut file, limits.record_bytes).inspect_err(|error| {
            if *error == StoreError::Capacity {
                tracing::warn!(path = %shown_path, "task record exceeds the record budget");
            }
        })?;
        let envelope = Envelope::read(&bytes);
        if let Some(version) = envelope.version
            && version > u64::from(MAX_LOADABLE_VERSION)
        {
            tracing::warn!(path = %shown_path, version, "task record was written by a newer gateway");
            return Err(StoreError::CorruptRecord);
        }
        let restored = restore(&bytes, &shown_path);
        let (admission, task_id) = match (&restored, envelope) {
            (Some((record, task)), _) => (record.admission.clone(), task.id().to_owned()),
            (
                None,
                Envelope {
                    admission: Some(admission),
                    task_id,
                    ..
                },
            ) => {
                // The id the row names for itself; the file name when even
                // that is gone, which the name check below then accepts.
                let named = task_id
                    .unwrap_or_else(|| name.strip_suffix(".json").unwrap_or(name).to_owned());
                (admission, named)
            }
            (None, _) => {
                tracing::warn!(
                    path = %shown_path,
                    "task record skipped: nothing in it can be read; its key is not kept; the file stays and counts against the store limit until an operator removes or repairs it"
                );
                loaded.unreadable += 1;
                continue;
            }
        };
        // A record living under another task's name would let a rename rebind it.
        if record_name(&task_id) != name || !identities.insert(admission.identity_digest.clone()) {
            tracing::warn!(path = %shown_path, "task record identity or name is not its own");
            return Err(StoreError::CorruptRecord);
        }
        let held = principals
            .entry(admission.principal_digest.clone())
            .or_default();
        *held += 1;
        if *held > limits.per_principal {
            tracing::warn!(path = %shown_path, "stored tasks exceed the per-principal cap");
            return Err(StoreError::Capacity);
        }
        if let Some((record, task)) = restored {
            // A live row written before this check, or under a larger cap,
            // may have no room for the bounded failure it could settle as;
            // refused like a row over the cap (MIK-7651).
            let needed = super::targets::fallback_bytes(&task, &record, chrono::Utc::now())?;
            if needed > limits.record_bytes {
                tracing::warn!(
                    path = %shown_path,
                    needed,
                    "task record leaves no room for its bounded failure; raise max_record_bytes to at least `needed` or remove the row"
                );
                return Err(StoreError::Capacity);
            }
            loaded.entries.insert(task_id, Entry { task, record });
        } else {
            tracing::warn!(
                path = %shown_path,
                "task record skipped: its task does not restore; its key stays taken; the file stays and counts against the store limits until an operator removes or repairs it"
            );
            loaded.reserved.push((admission, task_id));
        }
    }
    Ok(loaded)
}

/// The record and its task, when both read and the version is one this build
/// loads. Why one does not is logged here, the file named, never its content.
fn restore(bytes: &[u8], shown_path: &std::path::Display<'_>) -> Option<(Record, Task)> {
    // The file named, never the parser's message: it can quote the record.
    let record: Record = serde_json::from_slice(bytes)
        .inspect_err(|_| tracing::warn!(path = %shown_path, "task record does not parse"))
        .ok()?;
    if !(1..=MAX_LOADABLE_VERSION).contains(&record.version) {
        let version = record.version;
        tracing::warn!(path = %shown_path, version, "unsupported task record version");
        return None;
    }
    let task = Task::from_snapshot(record.model.clone())
        .inspect_err(|_| tracing::warn!(path = %shown_path, "task record does not restore"))
        .ok()?;
    Some((record, task))
}

/// Read at most `cap` bytes, refusing as soon as one more than that arrives.
/// Reading a byte past the cap is what makes "too large" observable without ever
/// allocating the oversized content it is refusing.
/// `pub(super)` only so the bound itself can be asserted directly rather than
/// inferred from a store-level outcome. Still module-private.
pub(in crate::gateway::task_service) fn read_bounded(
    file: &mut fs::File,
    cap: usize,
) -> Result<Vec<u8>, StoreError> {
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

pub(super) enum Fault {
    BeforeRename(io::Error),
    AfterRename(io::Error),
}

/// Write one record durably: private temp, payload, file sync, rename, directory
/// sync. Failure before the rename is a clean refusal; failure at or after it
/// leaves durability uncertain, which is the caller's cue to poison readiness.
pub(super) fn write_record(
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
        .and_then(|()| rename(&temp, dir.join(name)));
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
        match open_new_private(&temp) {
            Ok(file) => return Ok((file, temp)),
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
    sync_file(&file)?;
    fire(hook, CommitStage::FileSync)
}

pub(super) fn fire(hook: Option<&CommitHook>, stage: CommitStage) -> io::Result<()> {
    hook.map_or(Ok(()), |hook| hook(stage))
}
