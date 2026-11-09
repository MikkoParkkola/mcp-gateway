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
use super::sync_dir_of;
use crate::config::UnreadConfig;
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

/// Name suffixes of the journal and the staged original: the one pair both
/// [`journal_path`]/[`original_path`] and their inverse [`config_beside`]
/// read, so a rename cannot leave the inverse matching nothing.
const JOURNAL_SUFFIX: &str = ".replace-journal";
const ORIGINAL_SUFFIX: &str = ".replace-original";

/// `.<name>.replace-journal` beside the resolved config.
pub(crate) fn journal_path(config: &Path) -> PathBuf {
    beside(&resolved(config), JOURNAL_SUFFIX)
}

/// `.<name>.replace-original` beside the resolved config.
pub(crate) fn original_path(config: &Path) -> PathBuf {
    beside(&resolved(config), ORIGINAL_SUFFIX)
}

fn beside(target: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(target.file_name().unwrap_or_default());
    name.push(suffix);
    target.with_file_name(name)
}

/// The config a journal or staged original named `file` would belong to: the
/// inverse of [`journal_path`] and [`original_path`], by name alone, on the
/// name's own bytes, so a name that is not UTF-8 is still recognised.
pub(crate) fn config_beside(file: &Path) -> Option<PathBuf> {
    let name = file.file_name()?;
    let config = [JOURNAL_SUFFIX, ORIGINAL_SUFFIX]
        .iter()
        .find_map(|suffix| name_before(name, suffix))?;
    Some(file.with_file_name(config))
}

/// `name` without its leading `.` and `suffix`; `None` when it lacks either
/// or nothing is left.
#[cfg(unix)]
fn name_before(name: &std::ffi::OsStr, suffix: &str) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStrExt;
    let config = name
        .as_bytes()
        .strip_prefix(b".")?
        .strip_suffix(suffix.as_bytes())?;
    (!config.is_empty()).then(|| std::ffi::OsStr::from_bytes(config).to_os_string())
}

/// [`name_before`] on Windows, on the name's UTF-16 units, unpaired
/// surrogates included.
#[cfg(windows)]
fn name_before(name: &std::ffi::OsStr, suffix: &str) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let units: Vec<u16> = name.encode_wide().collect();
    let suffix: Vec<u16> = suffix.encode_utf16().collect();
    let config = units
        .strip_prefix(&[u16::from(b'.')])?
        .strip_suffix(suffix.as_slice())?;
    (!config.is_empty()).then(|| std::ffi::OsString::from_wide(config))
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
    let mut journal = match read(&path) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Err(std::io::ErrorKind::NotFound.into()),
        Err(UnreadConfig::Refused(why)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                guard_refused(&why),
            ));
        }
        Err(UnreadConfig::Failed(why) | UnreadConfig::NotTheConfig(why)) => {
            return Err(std::io::Error::other(why));
        }
    };
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
        fault::note_fired(target);
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
/// [`NotRecovered::Refused`] when the config guard refuses the journal or the
/// staged original; [`NotRecovered::Failed`] for a journal that cannot be
/// acted on otherwise: unreadable, of an unknown version, naming another file,
/// or `staged` with its original gone or not matching its digest. Then
/// nothing is changed, and the message says what to do by hand. One `Failed`
/// comes after a change: the original was restored but its journal could not
/// be removed, so the file did change and no write proceeds until the journal
/// is gone.
pub(crate) fn recover(config: &Path) -> Result<Recovered, NotRecovered> {
    let target = resolved(config);
    let path = journal_path(&target);
    let original = original_path(&target);
    let Some(journal) = read_checked(&target, &path, &original)? else {
        // A staged copy with no journal is a crash before the journal
        // existed: the file was never replaced.
        let _ = remove_if_present(&original);
        return Ok(Recovered::Nothing);
    };
    let recovered = match journal.state {
        State::Staged => {
            #[cfg(test)]
            if let Some(fault::Fault::Pause(pause)) = fault::get(&target) {
                pause.enter_and_wait();
            }
            let bytes = verified_original(&target, &path, &original, &journal)?.into_bytes();
            write_atomic(&target, &bytes, FileMode::Private, Symlink::Replace)
                .and_then(|()| sync_dir_of(&target))
                .map_err(|e| {
                    NotRecovered::Failed(format!("restoring {} failed: {e}", target.display()))
                })?;
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
            return Err(NotRecovered::Failed(format!(
                "{} was restored, but its journal {} could not be removed ({e}); no config write proceeds until it is: delete the journal",
                target.display(),
                path.display()
            )));
        }
        // An `all_renamed` journal left behind only keeps the current file.
        tracing::warn!(error = %e, journal = %path.display(), "cleaning up a recovered replace journal failed; the next config write retries");
    }
    Ok(recovered)
}

/// The config text [`recover`] would leave at `config`, worked out without
/// changing anything: `staged`, the staged original (read and checked
/// against its digest exactly as [`recover`] checks the bytes it restores);
/// `all_renamed`, the file on disk. `None`: no journal. Errors are
/// [`recover`]'s, each saying what to do by hand.
pub(crate) fn surviving_text(config: &Path) -> Result<Option<String>, NotRecovered> {
    let target = resolved(config);
    let path = journal_path(&target);
    let original = original_path(&target);
    let Some(journal) = read_checked(&target, &path, &original)? else {
        return Ok(None);
    };
    match journal.state {
        State::Staged => verified_original(&target, &path, &original, &journal).map(Some),
        State::AllRenamed => match crate::config::read_config_text(&target) {
            Ok(Some(text)) => Ok(Some(text)),
            Ok(None) => Err(NotRecovered::Failed(format!(
                "{target} is gone but its journal {journal} is all_renamed; nothing was changed. Restore {target} from your own copy, then delete the journal",
                target = target.display(),
                journal = path.display(),
            ))),
            Err(UnreadConfig::Refused(why)) => Err(NotRecovered::Refused(guard_refused(&why))),
            Err(UnreadConfig::Failed(e) | UnreadConfig::NotTheConfig(e)) => {
                Err(NotRecovered::Failed(format!(
                    "{target} cannot be read ({e}); nothing was changed. Its journal {journal} is all_renamed: keep {target} as it is, then delete the journal",
                    target = target.display(),
                    journal = path.display(),
                )))
            }
        },
    }
}

/// The journal at `path` for `target`, read through the config guard;
/// `None` when there is none. A journal naming another file is refused.
fn read_checked(
    target: &Path,
    path: &Path,
    original: &Path,
) -> Result<Option<Journal>, NotRecovered> {
    let journal = match read(path) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Ok(None),
        Err(UnreadConfig::Refused(why)) => return Err(NotRecovered::Refused(guard_refused(&why))),
        // Its state is unknown, and it may be `all_renamed`: the step is
        // conditional on what the operator finds in it.
        Err(UnreadConfig::Failed(e) | UnreadConfig::NotTheConfig(e)) => {
            return Err(NotRecovered::Failed(format!(
                "{journal} cannot be read ({e}); nothing was changed. Its state is unknown, so leave {target} as it is until you have inspected the journal. If it names {target} and its state is staged, restore the staged original {original} over {target} only if its SHA-256 matches the journal's original_revision, then delete the journal; if its state is all_renamed, only delete the journal; if it names another file, restore nothing over {target}",
                journal = path.display(),
                target = target.display(),
                original = original.display(),
            )));
        }
    };
    // Another file's journal says nothing about this one: no restore over it,
    // and the journal stays until that file is resolved.
    if journal.target != target {
        return Err(NotRecovered::Failed(format!(
            "{journal} names {other}, not {target}; nothing was changed. Resolve that journal for {other} first: restore nothing over {target}, and do not delete the journal",
            journal = path.display(),
            other = journal.target.display(),
            target = target.display(),
        )));
    }
    Ok(Some(journal))
}

/// The staged original's text, read through the config guard and checked
/// against the digest `journal` records: the one check both [`recover`]
/// (before it restores the bytes) and [`surviving_text`] run.
fn verified_original(
    target: &Path,
    path: &Path,
    original: &Path,
    journal: &Journal,
) -> Result<String, NotRecovered> {
    // The bytes restored as gateway.yaml: read through the config
    // guard, so a staged original another account could plant or
    // change, with a digest to match, is never restored. With no
    // original to restore, the file is checked by hand.
    let unreadable = |e: &dyn std::fmt::Display| {
        NotRecovered::Failed(format!(
            "{original} cannot be read ({e}); nothing was changed. Do not restore it: check {target} by hand against the change that was being made, then delete the journal {journal}",
            original = original.display(),
            target = target.display(),
            journal = path.display(),
        ))
    };
    let text = match crate::config::read_recovery_text(original) {
        Ok(Some(text)) => text,
        Ok(None) => return Err(unreadable(&"it is gone")),
        Err(UnreadConfig::Refused(why)) => {
            return Err(NotRecovered::Refused(guard_refused(&why)));
        }
        Err(UnreadConfig::Failed(e) | UnreadConfig::NotTheConfig(e)) => {
            return Err(unreadable(&e));
        }
    };
    if crate::hashing::sha256_hex(text.as_bytes()) != journal.original_revision {
        return Err(NotRecovered::Failed(format!(
            "{} does not match the digest its journal {} records, so it was not restored; compare it with {} by hand before restoring anything, then delete the journal",
            original.display(),
            path.display(),
            target.display()
        )));
    }
    Ok(text)
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

/// The journal at `path`, read through the config guard (it decides which
/// bytes are restored as gateway.yaml); `None` when there is none.
fn read(path: &Path) -> Result<Option<Journal>, UnreadConfig> {
    let Some(text) = crate::config::read_recovery_text(path)? else {
        return Ok(None);
    };
    let journal: Journal =
        serde_json::from_str(&text).map_err(|e| UnreadConfig::Failed(e.to_string()))?;
    if journal.version != VERSION {
        return Err(UnreadConfig::Failed(format!(
            "journal version {} is not {VERSION}",
            journal.version
        )));
    }
    Ok(Some(journal))
}

/// Why [`recover`] did not run a pending recovery.
#[derive(Debug)]
pub(crate) enum NotRecovered {
    /// The config guard refused the journal or the staged original. The text
    /// names no path; the guard's own text went to the log.
    Refused(String),
    /// Anything else; the message says what to do by hand.
    Failed(String),
}

impl NotRecovered {
    /// The message, whichever kind it is.
    pub(crate) fn into_message(self) -> String {
        match self {
            Self::Refused(message) | Self::Failed(message) => message,
        }
    }
}

/// A replace journal or its staged original the config guard refused. Either
/// may be another account's plant with a matching digest, so the answer never
/// says to fix their owner or mode, retry with them in place, or restore from
/// them: it calls both untrusted and says to move both aside before a retry.
/// The guard's text, which names the file, goes to the log only.
fn guard_refused(why: &str) -> String {
    tracing::warn!(detail = %why, "a replace journal or its staged original was refused by the config guard");
    "a pending config recovery was not run: its replace journal and staged original are \
     untrusted, because the config guard refuses one of them (another account could have planted \
     or changed it, it is not a regular file, or it is not UTF-8 text), so nothing was restored. \
     Leave their owner and mode alone: fixing them would make the next recovery restore them. \
     Check gateway.yaml against a known-good copy, move both files aside, then retry"
        .to_owned()
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
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
        /// A commit fails before its rename.
        FailWrite,
        /// The directory sync of the given A call fails, every time, while armed.
        FailDirSync(crate::config_persistence::commit::SyncKey),
        /// The read-back's file flush fails, every time, while armed.
        FailFileSync,
        /// A row's action on the target at a point inside an A call.
        Hook(HookAt, Arc<dyn Fn(&Path) + Send + Sync>),
        /// Several of the above armed together on one target.
        All(Vec<Fault>),
    }

    /// Where a `Hook` runs inside an A call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum HookAt {
        /// Just before the read-back opens the target.
        BeforeReadBack,
        /// Just before the configured path is checked again (step 5).
        BeforeRecheck,
    }

    /// Real directory syncs per target, so a row proves A synced.
    static SYNCED: Mutex<Option<HashMap<PathBuf, usize>>> = Mutex::new(None);

    /// Count one real directory sync for `target`.
    pub(crate) fn note_synced(target: &Path) {
        let mut synced = SYNCED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *synced
            .get_or_insert_with(HashMap::new)
            .entry(target.to_path_buf())
            .or_default() += 1;
    }

    /// The real directory syncs counted for `target`.
    pub(crate) fn synced(target: &Path) -> usize {
        SYNCED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|m| m.get(target).copied())
            .unwrap_or(0)
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

    /// How many times a fault fired for a target, so a row can prove its
    /// fault was reached and not merely armed.
    static FIRED: Mutex<Option<HashMap<PathBuf, usize>>> = Mutex::new(None);

    pub(crate) fn note_fired(target: &Path) {
        let mut fired = FIRED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *fired
            .get_or_insert_with(HashMap::new)
            .entry(target.to_path_buf())
            .or_default() += 1;
    }

    /// The times the fault set for `config` has fired since it was set.
    pub(crate) fn fired(config: &Path) -> usize {
        let key = crate::identity_grants::journal::resolved(config);
        let fired = FIRED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fired
            .as_ref()
            .and_then(|m| m.get(&key))
            .copied()
            .unwrap_or(0)
    }

    /// Set `fault` for `config` until the returned guard drops. Dropping it,
    /// on a panic too, clears the entry and releases a pause, so a failing
    /// test never leaves recovery parked or its fault visible to another.
    #[must_use]
    pub(crate) fn set(config: &Path, fault: Fault) -> Armed {
        let key = crate::identity_grants::journal::resolved(config);
        FIRED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .remove(&key);
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

    pub(crate) fn get(target: &Path) -> Option<Fault> {
        FAULTS
            .lock()
            .expect("faults")
            .as_ref()
            .and_then(|map| map.get(target).cloned())
    }

    /// The armed fault for `target` that `want` picks, looking inside
    /// [`Fault::All`]; a pick counts as fired.
    pub(crate) fn fires(target: &Path, want: impl Fn(&Fault) -> bool) -> Option<Fault> {
        fn find(f: &Fault, want: &dyn Fn(&Fault) -> bool) -> Option<Fault> {
            match f {
                Fault::All(all) => all.iter().find_map(|f| find(f, want)),
                f if want(f) => Some(f.clone()),
                _ => None,
            }
        }
        let picked = get(target).and_then(|f| find(&f, &want));
        if picked.is_some() {
            note_fired(target);
        }
        picked
    }
}
