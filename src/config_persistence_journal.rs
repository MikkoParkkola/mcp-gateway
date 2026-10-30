// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The replace journal: what a byte replacement of gateway.yaml needs so that
//! a crash, or a refused reload, never leaves bytes on disk that no reload
//! accepted (ADR-024).
//!
//! A replacement writes, in order: a private copy of the original beside the
//! file, this journal in state `staged`, the new bytes over the file, then,
//! once the reload is accepted, state `all_renamed`. Whoever next takes the
//! config lock (any gateway writer, the CLI, a starting gateway) recovers a
//! journal it finds before reading the file: `staged` puts the original
//! back, `all_renamed` keeps the new bytes. Either way the journal and the
//! copy go, the journal first, so a crash during cleanup is recovered again.
//!
//! Every path is derived from the config itself, never read back from the
//! journal: a journal can only name the file it sits beside.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::atomic::{FileMode, Symlink, write_atomic};
use crate::identity_grants::journal::resolved;

const VERSION: u32 = 1;

/// How far a replacement got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    /// The original is staged; the new bytes may or may not be in place, and
    /// no reload accepted them. Recovery puts the original back.
    Staged,
    /// The new bytes are in place and a reload accepted them. Recovery keeps
    /// them.
    AllRenamed,
}

/// One replacement in flight, as written to disk. `target` and `original`
/// are recorded for a person reading the file; recovery checks `target`
/// against the config it was asked about and never uses either path.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Journal {
    version: u32,
    state: State,
    target: PathBuf,
    original: PathBuf,
    /// The SHA-256 of the staged original, checked before it is written back.
    original_revision: String,
}

/// What recovery did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recovered {
    /// No journal.
    Nothing,
    /// A `staged` journal: the original is back on disk, so a running
    /// gateway owes a reload.
    RolledBack,
    /// An `all_renamed` journal: the new bytes stand; only cleanup ran.
    KeptNew,
}

/// `.<name>.replace-journal` beside the resolved config.
pub(crate) fn journal_path(config: &Path) -> PathBuf {
    beside(&resolved(config), ".replace-journal")
}

/// `.<name>.replace-original` beside the resolved config.
pub(crate) fn original_path(config: &Path) -> PathBuf {
    beside(&resolved(config), ".replace-original")
}

fn beside(target: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(target.file_name().unwrap_or_default());
    name.push(suffix);
    target.with_file_name(name)
}

/// Whether a journal sits beside `config`. Cheap enough for a preflight: a
/// writer that parses the file before locking checks this first, so a
/// stranded half-replaced file never blocks the recovery that fixes it.
pub(crate) fn exists(config: &Path) -> bool {
    std::fs::symlink_metadata(journal_path(config)).is_ok()
}

/// Stage `bytes` (the file's current content) as the private original. A
/// copy left by a crash before its journal existed is debris, removed first;
/// the caller holds the config lock, so no other replacement owns it.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn stage_original(target: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = original_path(target);
    remove_if_present(&path)?;
    let mut file = super::create_new_private(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    sync_dir_of(&path)?;
    Ok(path)
}

/// Publish the journal for a replacement of `target` in state `staged`. It is
/// written whole to a scratch file first and then linked to its name, which
/// refuses an existing journal: a crash never leaves half a journal, and a
/// second replacement never overwrites the first's.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn begin(target: &Path, original_revision: String) -> std::io::Result<()> {
    let journal = Journal {
        version: VERSION,
        state: State::Staged,
        target: resolved(target),
        original: original_path(target),
        original_revision,
    };
    let path = journal_path(target);
    let scratch = beside(&resolved(target), ".replace-journal.new");
    remove_if_present(&scratch)?;
    let mut file = super::create_new_private(&scratch)?;
    file.write_all(&serde_json::to_vec(&journal).map_err(std::io::Error::other)?)?;
    file.sync_all()?;
    drop(file);
    let linked = std::fs::hard_link(&scratch, &path);
    let _ = std::fs::remove_file(&scratch);
    linked?;
    sync_dir_of(&path)
}

/// Mark the journal `all_renamed`: the reload accepted the new bytes. Durable
/// once this returns `Ok`.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "called only by the byte writer, whose first caller lands next"
    )
)]
pub(crate) fn mark_all_renamed(target: &Path) -> std::io::Result<()> {
    let path = journal_path(target);
    let mut journal = read(&path)?;
    journal.state = State::AllRenamed;
    let bytes = serde_json::to_vec(&journal).map_err(std::io::Error::other)?;
    write_atomic(&path, &bytes, FileMode::Private, Symlink::Replace)?;
    sync_dir_of(&path)
}

/// Remove the journal, durably, then the staged original. A crash between
/// the two leaves only debris, which the next recovery or staging removes.
pub(crate) fn finish(target: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if matches!(fault::get(target), Some(fault::Fault::FailJournalRemove)) {
        return Err(std::io::Error::other(
            "injected: the journal cannot be removed",
        ));
    }
    let path = journal_path(target);
    std::fs::remove_file(&path)?;
    sync_dir_of(&path)?;
    remove_if_present(&original_path(target))
}

/// Recover a journal beside `config`, if there is one. The caller holds the
/// config lock.
///
/// The original is verified against its recorded digest before anything is
/// written, and written over the config's own resolved path, owner-only as
/// every gateway.yaml write is. It is read, never moved: a crash in the
/// middle leaves it, and the journal, for the next try. Once the file is
/// right, a failed cleanup is logged, not returned, so the caller still
/// learns that the file changed.
///
/// # Errors
///
/// A journal that cannot be acted on: unreadable, of an unknown version,
/// naming another file, or `staged` with its original gone or not matching
/// its digest. Nothing is changed, and the message says what to do by hand.
pub(crate) fn recover(config: &Path) -> Result<Recovered, String> {
    let target = resolved(config);
    let path = journal_path(&target);
    let original = original_path(&target);
    let manual = || {
        format!(
            "copy the staged original {} over {}, then delete {}",
            original.display(),
            target.display(),
            path.display()
        )
    };
    let journal = match read(&path) {
        Ok(journal) => journal,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A staged copy with no journal is a crash before the journal
            // existed: the file was never replaced.
            let _ = remove_if_present(&original);
            return Ok(Recovered::Nothing);
        }
        Err(e) => {
            return Err(format!(
                "{} cannot be read ({e}); {}",
                path.display(),
                manual()
            ));
        }
    };
    if journal.target != target {
        return Err(format!(
            "{} names {}, not {}; {}",
            path.display(),
            journal.target.display(),
            target.display(),
            manual()
        ));
    }
    let recovered = match journal.state {
        State::Staged => {
            #[cfg(test)]
            if let Some(fault::Fault::Pause(pause)) = fault::get(&target) {
                pause.enter_and_wait();
            }
            let bytes = std::fs::read(&original).map_err(|e| {
                format!("{} cannot be read ({e}); {}", original.display(), manual())
            })?;
            if crate::hashing::sha256_hex(&bytes) != journal.original_revision {
                return Err(format!(
                    "{} does not match the digest its journal {} records, so it was not restored; compare it with {} by hand before restoring anything, then delete the journal",
                    original.display(),
                    path.display(),
                    target.display()
                ));
            }
            write_atomic(&target, &bytes, FileMode::Private, Symlink::Replace)
                .and_then(|()| sync_dir_of(&target))
                .map_err(|e| format!("restoring {} failed: {e}", target.display()))?;
            Recovered::RolledBack
        }
        State::AllRenamed => Recovered::KeptNew,
    };
    if let Err(e) = finish(&target) {
        if recovered == Recovered::RolledBack {
            // A `staged` journal left behind would roll back whatever the
            // next writer saves. Refuse until it is gone: each later lock
            // retries, and restoring the same original again is harmless.
            // The file did change, so a running gateway still owes a reload.
            note_restored(&target);
            return Err(format!(
                "{} was restored, but its journal {} could not be removed ({e}); no config write proceeds until it is: delete the journal",
                target.display(),
                path.display()
            ));
        }
        // An `all_renamed` journal left behind only keeps the current file.
        tracing::warn!(error = %e, journal = %path.display(), "cleaning up a recovered replace journal failed; the next config write retries");
    }
    Ok(recovered)
}

/// Targets whose original was restored by a recovery that then refused the
/// lock (its journal could not be removed). A running gateway takes the mark
/// and owes a reload, so it is reconciled while writes stay refused.
static RESTORED: std::sync::Mutex<Option<std::collections::HashSet<PathBuf>>> =
    std::sync::Mutex::new(None);

fn note_restored(target: &Path) {
    // A poisoned lock still holds the set: losing the mark would lose the
    // owed reload.
    RESTORED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(std::collections::HashSet::new)
        .insert(target.to_path_buf());
}

/// Take the restored mark for `config`, if a refused recovery left one.
pub(crate) fn take_restored(config: &Path) -> bool {
    let target = resolved(config);
    RESTORED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .is_some_and(|set| set.remove(&target))
}

fn read(path: &Path) -> std::io::Result<Journal> {
    let journal: Journal =
        serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)?;
    if journal.version != VERSION {
        return Err(std::io::Error::other(format!(
            "journal version {} is not {VERSION}",
            journal.version
        )));
    }
    Ok(journal)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Flush `path`'s directory, so a create, rename or remove in it is durable;
/// on Windows through the shared helper that opens the directory for it.
fn sync_dir_of(path: &Path) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(windows)]
    {
        crate::private_fs::sync_dir(dir)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(dir)?.sync_all()
    }
}

/// Test-only faults, keyed by the resolved target so parallel tests never see
/// each other's. A global rather than a thread-local: recovery runs on a
/// blocking-pool thread, not the test's.
#[cfg(test)]
pub(crate) mod fault {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Condvar, Mutex};

    #[derive(Clone)]
    pub(crate) enum Fault {
        /// `finish` fails before removing the journal.
        FailJournalRemove,
        /// Recovery of a `staged` journal stops until released.
        Pause(Arc<Pause>),
    }

    /// A gate recovery waits at: the test sees it entered, then releases it.
    #[derive(Default)]
    pub(crate) struct Pause {
        /// (entered, released)
        state: Mutex<(bool, bool)>,
        changed: Condvar,
    }

    impl Pause {
        pub(super) fn enter_and_wait(&self) {
            let mut state = self.state.lock().expect("pause");
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self.changed.wait(state).expect("pause");
            }
        }

        /// Block until recovery has reached the gate, at most 20 s: a test
        /// whose recovery never gets there fails by name instead of leaving
        /// this thread waiting forever.
        pub(crate) fn wait_entered(&self) {
            let (state, timeout) = self
                .changed
                .wait_timeout_while(
                    self.state.lock().expect("pause"),
                    std::time::Duration::from_secs(20),
                    |state| !state.0,
                )
                .expect("pause");
            assert!(
                state.0 && !timeout.timed_out(),
                "recovery never reached the pause within 20 s"
            );
        }

        pub(crate) fn release(&self) {
            self.state.lock().expect("pause").1 = true;
            self.changed.notify_all();
        }
    }

    static FAULTS: Mutex<Option<HashMap<PathBuf, Fault>>> = Mutex::new(None);

    /// Set `fault` for `config` until the returned guard drops. Dropping it,
    /// on a panic too, clears the entry and releases a pause, so a failing
    /// test never leaves recovery parked or its fault visible to another.
    #[must_use]
    pub(crate) fn set(config: &Path, fault: Fault) -> Armed {
        let key = crate::identity_grants::journal::resolved(config);
        FAULTS
            .lock()
            .expect("faults")
            .get_or_insert_with(HashMap::new)
            .insert(key.clone(), fault.clone());
        Armed { key, fault }
    }

    /// An armed fault; see [`set`].
    pub(crate) struct Armed {
        key: PathBuf,
        fault: Fault,
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            if let Ok(mut faults) = FAULTS.lock()
                && let Some(map) = faults.as_mut()
            {
                map.remove(&self.key);
            }
            if let Fault::Pause(pause) = &self.fault {
                pause.release();
            }
        }
    }

    pub(super) fn get(target: &Path) -> Option<Fault> {
        FAULTS
            .lock()
            .expect("faults")
            .as_ref()
            .and_then(|map| map.get(target).cloned())
    }
}
