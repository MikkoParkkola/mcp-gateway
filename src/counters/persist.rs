// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `counters.json`: restore at start, periodic and shutdown saves.
//!
//! A bad file is moved aside under a name no earlier quarantine holds, never
//! overwritten, before the store starts empty; if it cannot be moved, every
//! save of this run is off, so recoverable history is never replaced by an
//! empty store. A save clones the store under its lock and serializes and
//! writes after releasing it, so a slow disk never holds the invoke path.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::TimeZone;
use parking_lot::Mutex;
use tracing::{error, info, warn};

use super::{CounterStore, MarkerKind, VersionChange, snapshot};

/// The steps of a save, for the test that pins neither holds the store lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Serializing,
    Writing,
}

/// The file one store saves to.
#[derive(Debug)]
pub(crate) struct CounterFile {
    path: PathBuf,
    /// Set when a bad file could not be moved aside: no save this run.
    disabled: AtomicBool,
    /// One write at a time; a periodic save that finds it held is skipped.
    busy: Mutex<()>,
}

/// A restored store, its file, and how many warnings the restore logged.
#[derive(Debug)]
pub(crate) struct Restored {
    pub store: CounterStore,
    pub file: CounterFile,
    /// Warnings the restore logged; the server reads only the log.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "read by the restore tests; the server reads the log"
        )
    )]
    pub warnings: usize,
    /// The version change the restore marked, when another version saved the
    /// file.
    pub upgrade: Option<VersionChange>,
}

/// Move `path` aside to `<name>.unreadable-<now>`, adding `-1`, `-2`, …
/// when that name is taken. A hard link to the new name fails if the name
/// exists, so nothing is ever replaced; the original is unlinked after.
fn quarantine(path: &Path, now: u64) -> std::io::Result<PathBuf> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 0..1_000u32 {
        let candidate = if n == 0 {
            path.with_file_name(format!("{name}.unreadable-{now}"))
        } else {
            path.with_file_name(format!("{name}.unreadable-{now}-{n}"))
        };
        match std::fs::hard_link(path, &candidate) {
            Ok(()) => {
                // A failed unlink still leaves the link: the next save
                // renames over `path`, which leaves the linked bytes intact.
                if let Err(e) = std::fs::remove_file(path) {
                    warn!(error = %e, "counters.json was copied aside but not removed");
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free quarantine name"))
}

impl CounterFile {
    fn new(path: PathBuf, disabled: bool) -> Self {
        Self {
            path,
            disabled: AtomicBool::new(disabled),
            busy: Mutex::new(()),
        }
    }

    /// Restore the store from `path` at unix second `now`. A missing file is
    /// a fresh start (coverage begins `now`); a restored one records a
    /// `restart` marker, and an `upgrade` one when another version saved it.
    pub(crate) fn restore<Tz: TimeZone>(
        path: PathBuf,
        now: u64,
        binary_version: &str,
        zone: &Tz,
    ) -> Restored {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Restored {
                    store: CounterStore::new(now),
                    file: Self::new(path, false),
                    warnings: 0,
                    upgrade: None,
                };
            }
            Err(e) => {
                warn!(error = %e, "counters.json could not be read");
                Vec::new()
            }
        };
        match CounterStore::from_bytes_noting_change(&bytes, now, binary_version, zone) {
            Ok((store, cut, upgrade)) => {
                if cut {
                    warn!("counters.json held more than the caps allow; cut back to them");
                }
                store.mark(MarkerKind::Restart, None, now);
                info!("Restored call counters");
                Restored {
                    store,
                    file: Self::new(path, false),
                    warnings: usize::from(cut),
                    upgrade,
                }
            }
            Err(reason) => {
                let disabled = match quarantine(&path, now) {
                    Ok(aside) => {
                        warn!(%reason, aside = %aside.display(), "counters.json moved aside; counting starts empty");
                        false
                    }
                    Err(e) => {
                        error!(%reason, error = %e, "counters.json could not be moved aside; counter saves are off for this run");
                        true
                    }
                };
                Restored {
                    store: CounterStore::new(now),
                    file: Self::new(path, disabled),
                    warnings: 1,
                    upgrade: None,
                }
            }
        }
    }

    /// Whether saves are off for this run.
    pub(crate) fn disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    /// Save, waiting for a write in flight. The shutdown save.
    pub(crate) fn save(&self, store: &CounterStore, binary_version: &str, now: u64) {
        if self.disabled() {
            return;
        }
        let _turn = self.busy.lock();
        self.write(store, binary_version, now, &|_| {});
    }

    /// Save unless a write is in flight. The periodic save. Returns whether
    /// it wrote.
    pub(crate) fn save_unless_busy(
        &self,
        store: &CounterStore,
        binary_version: &str,
        now: u64,
    ) -> bool {
        if self.disabled() {
            return false;
        }
        let Some(_turn) = self.busy.try_lock() else {
            warn!(
                "periodic counter save skipped: the previous counters.json write has not finished"
            );
            return false;
        };
        self.write(store, binary_version, now, &|_| {});
        true
    }

    /// [`Self::save`] with `hook` called at each stage.
    #[cfg(test)]
    pub(crate) fn save_with(
        &self,
        store: &CounterStore,
        binary_version: &str,
        now: u64,
        hook: &dyn Fn(Stage),
    ) {
        let _turn = self.busy.lock();
        self.write(store, binary_version, now, hook);
    }

    /// Hold the write turn, as a write in flight does.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.busy.lock()
    }

    fn write(&self, store: &CounterStore, binary_version: &str, now: u64, hook: &dyn Fn(Stage)) {
        let inner = store.snapshot();
        hook(Stage::Serializing);
        let bytes = snapshot::encode(&inner, binary_version, now);
        drop(inner);
        hook(Stage::Writing);
        if let Some(parent) = self.path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(error = %e, "Failed to create the counters directory");
            return;
        }
        match crate::config_persistence::write_atomic(
            &self.path,
            &bytes,
            crate::config_persistence::FileMode::Private,
            crate::config_persistence::Symlink::Replace,
        ) {
            Ok(()) => info!(path = %self.path.display(), "Saved call counters"),
            Err(e) => warn!(error = %e, "Failed to save call counters"),
        }
    }
}
