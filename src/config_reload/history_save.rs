// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design D-2: one synchronous save, bounded. The job takes the sidecar,
//! reads the store once, appends the record, sends the updated state back,
//! writes a temp file and renames it only while the store's generation still
//! equals its ticket. The record task (or startup) bounds it by the deadline.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use super::{Bounds, Event, Snapshot, Source, State, StillRunning};
use crate::config_persistence::{FileMode, Symlink, write_atomic_checked};

/// One record, built from the publish's own inputs.
#[derive(Clone)]
pub(crate) struct Record {
    pub(crate) event: Event,
    pub(crate) snapshot: Option<Snapshot>,
    /// The revision an eviction must not drop.
    pub(crate) running: String,
    /// A refusal's served revision; its `since` is read from the loaded store.
    pub(crate) served: Option<String>,
    pub(crate) now: u64,
}

/// How one save ended.
pub(super) enum SaveOutcome {
    Saved,
    /// The read failed or did not parse: never taken as an empty store.
    ReadFailed(String),
    /// The sidecar stayed held by another holder up to the deadline.
    SidecarHeld,
    /// The write failed after the state was sent back.
    WriteFailed(std::io::Error),
    /// The generation moved: the deadline passed and the job wrote nothing.
    Stale,
}

/// The sidecar that serializes saves across processes.
pub(super) fn sidecar_path(file: &Path) -> PathBuf {
    file.with_file_name("config-history.json.lock")
}

/// Append `record` to `state` as it was loaded: a refusal's `since` from the
/// newest kept copy of its served revision, a restart of the newest kept
/// revision as an unchanged event (M2), then eviction.
pub(super) fn apply(state: &mut State, record: Record, bounds: Bounds) {
    let Record {
        mut event,
        mut snapshot,
        running,
        served,
        now,
    } = record;
    if let Some(revision) = served {
        let since = state
            .snapshots
            .iter()
            .rev()
            .find(|kept| kept.revision == revision)
            .map_or(now, |kept| kept.at);
        event.still_running = Some(StillRunning { revision, since });
    }
    if event.source == Source::Start
        && let Some(new) = &snapshot
        && state
            .snapshots
            .last()
            .is_some_and(|newest| newest.revision == new.revision)
    {
        event.unchanged = true;
        snapshot = None;
    }
    super::remember(state, event, snapshot, bounds, &running, now);
}

/// Take the sidecar, retried until `deadline`.
fn take_sidecar(
    lock: &Path,
    deadline: Instant,
) -> Result<crate::fs_lock::ExclusiveFileLock, SaveOutcome> {
    loop {
        match crate::fs_lock::ExclusiveFileLock::try_acquire(lock) {
            Ok(held) => return Ok(held),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SaveOutcome::SidecarHeld);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(SaveOutcome::ReadFailed(format!(
                    "the sidecar {}: {error}",
                    lock.display()
                )));
            }
        }
    }
}

/// The save job. Runs on a blocking thread (the record task's) or inline
/// (startup, tests); `deadline` bounds its sidecar wait, `sent` receives the
/// updated state before the write, and the rename happens only while
/// `generation` still equals `ticket`.
pub(super) fn save_record(
    file: &Path,
    bounds: Bounds,
    record: Record,
    (generation, ticket): (&AtomicU64, u64),
    deadline: Instant,
    sent: Sender<State>,
) -> SaveOutcome {
    #[cfg(test)]
    let job = super::seams::JobSeams::take(file);
    let _held = match take_sidecar(&sidecar_path(file), deadline) {
        Ok(held) => held,
        Err(outcome) => return outcome,
    };
    #[cfg(test)]
    job.park(super::seams::ParkAt::BeforeRead);
    #[cfg(test)]
    let loaded = job.read(file);
    #[cfg(not(test))]
    let loaded = super::load_state(file);
    let mut state = match loaded {
        Ok(state) => state,
        Err(reason) => return SaveOutcome::ReadFailed(reason),
    };
    apply(&mut state, record, bounds);
    #[cfg(test)]
    match job.fault {
        Some(super::seams::Fault::PanicBeforeSend) => {
            panic!("injected panic before the state is sent back")
        }
        Some(super::seams::Fault::DropSender) => {
            drop(sent);
            return SaveOutcome::WriteFailed(std::io::Error::other("injected dropped sender"));
        }
        _ => {}
    }
    let bytes = match serde_json::to_vec(&state) {
        Ok(bytes) => crate::wiped_bytes::WipedBytes::new(bytes),
        Err(error) => return SaveOutcome::WriteFailed(error.into()),
    };
    let _ = sent.send(state);
    #[cfg(test)]
    if job.fault == Some(super::seams::Fault::Write) {
        job.done();
        return SaveOutcome::WriteFailed(std::io::Error::other("injected write fault"));
    }
    let mut stale = false;
    let written = write_atomic_checked(
        file,
        bytes.as_bytes(),
        FileMode::Private,
        Symlink::Replace,
        || {
            #[cfg(test)]
            job.park(super::seams::ParkAt::BeforeCheck);
            if generation.load(Ordering::SeqCst) != ticket {
                stale = true;
                return Err(std::io::Error::other(
                    "the save was abandoned at its deadline",
                ));
            }
            #[cfg(test)]
            job.park(super::seams::ParkAt::AfterCheck);
            Ok(())
        },
    );
    #[cfg(test)]
    job.done();
    match written {
        Ok(()) => SaveOutcome::Saved,
        Err(_) if stale => SaveOutcome::Stale,
        Err(error) => SaveOutcome::WriteFailed(error),
    }
}

impl super::ConfigHistory {
    /// Leave disk mode for memory: with the state the job sent back when it
    /// arrived, else this record alone (complete). One warning names the
    /// file and the cause; the file is left as it is.
    fn to_memory(&self, record: Record, sent: Option<State>, cause: &str) {
        let state = sent.unwrap_or_else(|| {
            let mut alone = State::default();
            apply(&mut alone, record, self.bounds);
            alone
        });
        *self.mode.lock() = super::StoreMode::MemoryOnly { state };
        tracing::warn!(file = %self.file().display(), cause, "config history kept in memory only; its file is left as it is");
    }

    /// Append in memory when this store is memory-only; otherwise `None` with
    /// the file to save to (an unopened store is opened first).
    fn memory_or_file(&self, record: Record) -> Option<(Record, PathBuf)> {
        if matches!(*self.mode.lock(), super::StoreMode::Unopened { .. })
            && let Err(cause) = self.open_now(
                self.generation.load(Ordering::SeqCst),
                Instant::now() + super::SAVE_DEADLINE,
            )
        {
            self.to_memory(record, None, &cause);
            return None;
        }
        let mut mode = self.mode.lock();
        match &mut *mode {
            super::StoreMode::MemoryOnly { state } => {
                apply(state, record, self.bounds);
                None
            }
            _ => Some((record, self.file())),
        }
    }

    /// The outcome of a save that ran to its end.
    fn settle(&self, outcome: SaveOutcome, record: Record, sent: Option<State>) {
        match outcome {
            SaveOutcome::Saved | SaveOutcome::Stale => {}
            SaveOutcome::ReadFailed(reason) => self.to_memory(record, None, &reason),
            SaveOutcome::SidecarHeld => self.to_memory(record, None, &sidecar_cause(&self.file())),
            SaveOutcome::WriteFailed(error) => self.to_memory(record, sent, &error.to_string()),
        }
    }

    /// One record, saved on this thread (tests, and anything recording
    /// outside a reload); the sidecar wait is bounded by the save deadline.
    pub(crate) fn save_inline(&self, record: Record) {
        let Some((record, file)) = self.memory_or_file(record) else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let ticket = self.generation.load(Ordering::SeqCst);
        let deadline = Instant::now() + super::SAVE_DEADLINE;
        let outcome = save_record(
            &file,
            self.bounds,
            record.clone(),
            (&self.generation, ticket),
            deadline,
            tx,
        );
        self.settle(outcome, record, rx.try_recv().ok());
    }

    /// One record from the reload path's record task: the save runs on the
    /// blocking pool under the save deadline. Past it, the generation moves
    /// (a late job then renames nothing) and the store goes memory-only.
    pub(crate) async fn save_bounded(self: &std::sync::Arc<Self>, record: Record) {
        // Memory-only appends here; an unopened store is opened inside the job,
        // so the save deadline covers the open as well (code review r2).
        let unopened = {
            let mut mode = self.mode.lock();
            match &mut *mode {
                super::StoreMode::MemoryOnly { state } => {
                    apply(state, record, self.bounds);
                    return;
                }
                super::StoreMode::Unopened { .. } => true,
                super::StoreMode::Disk => false,
            }
        };
        let file = self.file();
        let (tx, rx) = std::sync::mpsc::channel();
        let ticket = self.generation.load(Ordering::SeqCst);
        let deadline = Instant::now() + super::SAVE_DEADLINE;
        let store = std::sync::Arc::clone(self);
        let job_record = record.clone();
        let job = tokio::task::spawn_blocking(move || {
            if unopened {
                if let Err(cause) = store.open_now(ticket, deadline) {
                    return SaveOutcome::ReadFailed(cause);
                }
                if matches!(*store.mode.lock(), super::StoreMode::MemoryOnly { .. }) {
                    return SaveOutcome::ReadFailed("the store is kept in memory".to_string());
                }
            }
            save_record(
                &file,
                store.bounds,
                job_record,
                (&store.generation, ticket),
                deadline,
                tx,
            )
        });
        match tokio::time::timeout(super::SAVE_DEADLINE, job).await {
            Ok(Ok(outcome)) => self.settle(outcome, record, rx.try_recv().ok()),
            Ok(Err(_)) => self.to_memory(
                record,
                rx.try_recv().ok(),
                "the save job stopped before it finished",
            ),
            Err(_) => {
                self.generation.fetch_add(1, Ordering::SeqCst);
                self.to_memory(
                    record,
                    rx.try_recv().ok(),
                    "the save did not finish within its deadline",
                );
            }
        }
    }
}

impl super::ConfigHistory {
    /// Read the file. `Ok` when the store is now a disk store, or when the
    /// generation moved past `ticket` (startup gave up on this worker: nothing
    /// changes); `Err(cause)` when it must keep memory only, for the caller to
    /// say once on its own thread. A missing file is an empty disk store; one
    /// that does not parse is moved aside by hard link (T5) and the store
    /// starts empty; one refused, unreadable, or behind another holder's
    /// sidecar past `deadline` is left as it is.
    pub(super) fn open_now(&self, ticket: u64, deadline: Instant) -> Result<(), String> {
        let file = self.file();
        #[cfg(test)]
        let opened = super::seams::for_file(&file);
        #[cfg(test)]
        if let Some(gate) = opened
            .as_ref()
            .and_then(|s| s.take_park(super::seams::ParkAt::OpenBeforeRead))
        {
            gate.park_blocking();
            gate.finished();
        }
        let now = match *self.mode.lock() {
            super::StoreMode::Unopened { now } => now,
            _ => return Ok(()),
        };
        let held = match take_sidecar(&sidecar_path(&file), deadline) {
            Ok(held) => held,
            Err(SaveOutcome::ReadFailed(reason)) => return Err(reason),
            Err(_) => return Err(sidecar_cause(&file)),
        };
        match super::read_stored(&file) {
            Ok(None) => {}
            Err(reason) => return Err(reason),
            Ok(Some(text)) => {
                if let Err(error) = serde_json::from_slice::<State>(text.as_bytes()) {
                    if self.generation.load(Ordering::SeqCst) != ticket {
                        return Ok(());
                    }
                    #[cfg(test)]
                    let linked = opened
                        .as_ref()
                        .and_then(|s| s.take_park(super::seams::ParkAt::BeforeQuarantineLink));
                    #[cfg(test)]
                    if let Some(gate) = &linked {
                        gate.park_blocking();
                    }
                    let moved = crate::counters::persist::quarantine(&file, now);
                    #[cfg(test)]
                    if let Some(gate) = linked {
                        gate.finished();
                    }
                    if let Err(quarantine_error) = moved {
                        return Err(format!(
                            "it does not parse ({error}) and could not be moved aside ({quarantine_error})"
                        ));
                    }
                }
            }
        }
        drop(held);
        let mut mode = self.mode.lock();
        if self.generation.load(Ordering::SeqCst) == ticket
            && matches!(*mode, super::StoreMode::Unopened { .. })
        {
            *mode = super::StoreMode::Disk;
        }
        Ok(())
    }
}

/// The cause named when another holder kept the sidecar past the deadline.
fn sidecar_cause(file: &Path) -> String {
    format!(
        "its sidecar {} stayed held past the save deadline",
        sidecar_path(file).display()
    )
}

impl super::ConfigHistory {
    /// Startup (design D-1, gpt G1): open and the startup record run on one
    /// worker thread, waited for until one deadline computed here. Past it the
    /// generation moves, so the worker changes nothing more on disk or in
    /// memory, and the store keeps the startup record in memory.
    pub(crate) fn start(self: &std::sync::Arc<Self>, record: Record) {
        let deadline = Instant::now() + super::SAVE_DEADLINE;
        let ticket = self.generation.load(Ordering::SeqCst);
        let (done, finished) = std::sync::mpsc::channel::<Option<SaveOutcome>>();
        let (tx, rx) = std::sync::mpsc::channel();
        let store = std::sync::Arc::clone(self);
        let job_record = record.clone();
        // Which step the worker is in, for the warning if it does not finish.
        let step = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saving = std::sync::Arc::clone(&step);
        #[cfg(test)]
        let injected = super::seams::for_file(&self.file()).is_some_and(|s| s.take_spawn_failure());
        #[cfg(not(test))]
        let injected = false;
        let spawned = if injected {
            Err(std::io::Error::other("injected spawn failure"))
        } else {
            std::thread::Builder::new()
                .name("config-history-start".to_string())
                .spawn(move || {
                    if let Err(cause) = store.open_now(ticket, deadline) {
                        let _ = done.send(Some(SaveOutcome::ReadFailed(cause)));
                        return;
                    }
                    saving.store(true, Ordering::SeqCst);
                    let file = {
                        let mut mode = store.mode.lock();
                        match &mut *mode {
                            super::StoreMode::MemoryOnly { state } => {
                                if store.generation.load(Ordering::SeqCst) == ticket {
                                    apply(state, job_record, store.bounds);
                                }
                                let _ = done.send(None);
                                return;
                            }
                            _ => store.file(),
                        }
                    };
                    let outcome = save_record(
                        &file,
                        store.bounds,
                        job_record,
                        (&store.generation, ticket),
                        deadline,
                        tx,
                    );
                    let _ = done.send(Some(outcome));
                })
        };
        if let Err(error) = spawned {
            // No unbounded fallback on this thread: without its worker, startup
            // touches no file and keeps this record in memory (code review r2).
            let cause = format!("the startup worker could not start: {error}");
            self.to_memory(record, None, &cause);
            return;
        }
        match finished.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(None) => {}
            Ok(Some(outcome)) => self.settle(outcome, record, rx.try_recv().ok()),
            Err(_) => {
                self.generation.fetch_add(1, Ordering::SeqCst);
                let unfinished = if step.load(Ordering::SeqCst) {
                    "the startup record's save"
                } else {
                    "the open of the history file"
                };
                let cause = format!(
                    "{unfinished} did not finish within {:?}; its sidecar is {}",
                    super::SAVE_DEADLINE,
                    sidecar_path(&self.file()).display()
                );
                self.to_memory(record, rx.try_recv().ok(), &cause);
            }
        }
    }
}

impl super::ConfigHistory {
    /// `open`, then the store's first open (`open_now`), on this thread. A
    /// refusal is dropped and leaves the store unopened: the real first open
    /// carries a record, which a refusal sends to memory, so a row about a
    /// refused file records before it reads.
    #[cfg(test)]
    pub(crate) fn open_eagerly(data_dir: &Path, bounds: Bounds, now: u64) -> Self {
        let store = Self::open(data_dir, bounds, now);
        let _ = store.open_now(0, Instant::now() + super::SAVE_DEADLINE);
        store
    }
}
