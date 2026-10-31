// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One HTTP process's segment in the shared v2 window.
//!
//! Every read-modify-write holds `.window.lock` from read to rename, and a
//! process rewrites only its own segment, so writers in other processes (a
//! predecessor's late final write, stdio children) serialize with it.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Segment, read_or_create, read_window_v2, window_paths, write_window_v2};
use crate::fs_lock::ExclusiveFileLock;
use crate::protocol_revision_telemetry::durable::{force_directory_owner_only, invalid_window};
use crate::protocol_revision_telemetry::{
    DURABLE_TELEMETRY_DIR, Snapshot, Transport, empty_shadow_counts, global,
};

/// Who an HTTP segment claims to be. Checked against the operator's
/// declaration at decision time, never trusted from the file alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriterIdentity {
    pub(crate) listen: String,
    pub(crate) exe: String,
    pub(crate) process_started_at_ms: u64,
}

/// Counts an HTTP segment writes: cumulative for this process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SegmentCounts {
    pub(crate) snapshot: Snapshot,
    pub(crate) missing_revision_agents: BTreeMap<String, u64>,
    pub(crate) tools_list_shadow: BTreeMap<String, u64>,
}

impl SegmentCounts {
    /// Valid counts for a process that has served nothing yet.
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            tools_list_shadow: empty_shadow_counts(),
            ..Self::default()
        }
    }
}

/// This process's segment. Once its seal is on disk nothing rewrites it:
/// every write reads the segment under the file lock and stops at a seal,
/// so the on-disk record, not this handle, is what ends the segment.
#[derive(Debug)]
pub(crate) struct HttpSegmentSink {
    window_path: PathBuf,
    lock_path: PathBuf,
    index: usize,
    identity: WriterIdentity,
    #[cfg(test)]
    created_by: crate::test_late_write::Creator,
}

impl HttpSegmentSink {
    /// Append this process's segment under the lock. It never waits for a
    /// predecessor: overlap is judged later from sealed timestamps.
    pub(crate) fn open(data_dir: &Path, identity: WriterIdentity, now: u64) -> io::Result<Self> {
        let (window_path, lock_path) = window_paths(data_dir);
        let directory = data_dir.join(DURABLE_TELEMETRY_DIR);
        // A missing data directory here means the open is about to rebuild a
        // test directory already removed: name the test that opened it.
        #[cfg(test)]
        let created_by = crate::test_late_write::Creator::default();
        #[cfg(test)]
        created_by.witness("telemetry window open", data_dir);
        std::fs::create_dir_all(&directory)?;
        force_directory_owner_only(&directory)?;
        #[cfg(test)]
        stall_seam::pass(&window_path, stall_seam::Role::Open);
        let _lock = ExclusiveFileLock::acquire(&lock_path)?;
        let mut window = read_or_create(&window_path, now)?;
        window.http_segments.push(Segment {
            listen: identity.listen.clone(),
            exe: identity.exe.clone(),
            process_started_at_ms: identity.process_started_at_ms,
            opened_at: now,
            last_checkpoint_at: now,
            sealed_at_ms: None,
            closed_cleanly: false,
            snapshot: Snapshot::default(),
            missing_revision_agents: BTreeMap::new(),
            tools_list_shadow: empty_shadow_counts(),
        });
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        let index = window.http_segments.len() - 1;
        write_window_v2(&window_path, &window)?;
        #[cfg(test)]
        stall_seam::record_opener(&window_path, created_by.name());
        Ok(Self {
            window_path,
            lock_path,
            index,
            identity,
            #[cfg(test)]
            created_by,
        })
    }

    /// Rewrite this segment's cumulative counts; a no-op once sealed. A
    /// failed write loses nothing: the next carries the same cumulative counts.
    pub(crate) fn checkpoint(&mut self, counts: &SegmentCounts, now: u64) -> io::Result<()> {
        self.write(counts, now, None)
    }

    /// The final write: the sealed counts and `sealed_at_ms` with
    /// `closed_cleanly` in one rename. A close that fails leaves the segment
    /// open on disk, so a retried close can still seal it.
    pub(crate) fn close(
        &mut self,
        counts: &SegmentCounts,
        now: u64,
        sealed_at_ms: u64,
    ) -> io::Result<()> {
        self.write(counts, now, Some(sealed_at_ms))
    }

    fn write(&self, counts: &SegmentCounts, now: u64, sealed_at_ms: Option<u64>) -> io::Result<()> {
        #[cfg(test)]
        stall_seam::pass(
            &self.window_path,
            if sealed_at_ms.is_some() {
                stall_seam::Role::Close
            } else {
                stall_seam::Role::Checkpoint
            },
        );
        #[cfg(test)]
        self.created_by
            .witness("telemetry window", &self.window_path);
        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        // A lock taken beside a missing window is the lock-only leftover.
        #[cfg(test)]
        self.created_by
            .witness("telemetry window lock", &self.window_path);
        let mut window = read_window_v2(&self.window_path)?;
        let segment = window
            .http_segments
            .get_mut(self.index)
            .filter(|segment| {
                segment.exe == self.identity.exe
                    && segment.process_started_at_ms == self.identity.process_started_at_ms
            })
            .ok_or_else(|| invalid_window("this process's segment is missing from the window"))?;
        // A sealed segment is never rewritten: not by a late checkpoint, and
        // not by a second close (a close whose rename landed but whose
        // directory sync failed reports an error with the seal on disk).
        if segment.closed_cleanly {
            return Ok(());
        }
        segment.snapshot = counts.snapshot.clone();
        segment.missing_revision_agents = counts.missing_revision_agents.clone();
        segment.tools_list_shadow = counts.tools_list_shadow.clone();
        segment.last_checkpoint_at = segment.last_checkpoint_at.max(now);
        segment.sealed_at_ms = sealed_at_ms;
        segment.closed_cleanly = sealed_at_ms.is_some();
        window.updated_at_unix_seconds = window.updated_at_unix_seconds.max(now);
        write_window_v2(&self.window_path, &window)
    }
}

/// This process's HTTP counts since start, as its segment records them.
///
/// With `seal`, the serving gateway's flag is set in the same critical
/// section its handlers check it under, so the counts returned hold every
/// request that gateway will ever serve.
pub(crate) fn global_segment_counts(seal: Option<&AtomicBool>) -> SegmentCounts {
    let registry = global()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(seal) = seal {
        seal.store(true, Ordering::SeqCst);
    }
    SegmentCounts {
        snapshot: registry.transport_snapshot(Transport::Http),
        missing_revision_agents: registry.missing_revision_agents(Transport::Http),
        tools_list_shadow: registry.shadow_snapshot(),
    }
}

/// Test support: block a segment write on a per-path, per-role gate, so a
/// row can hold one kind of write in flight and release it, waiting on
/// signals rather than sleeps. A role a row did not arm passes freely, so a
/// periodic checkpoint can never stand in for the final write.
#[cfg(test)]
pub(crate) mod stall_seam {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, PoisonError, mpsc};

    /// Which write is passing the gate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) enum Role {
        Open,
        Checkpoint,
        Close,
        /// A saver's checkpoint thread, before it tries the sink mutex.
        BeforeLock,
        /// The saver's seal closure, once it has finished.
        Sealed,
        /// A saver's checkpoint thread, as it ends.
        CheckpointDone,
        /// The saver, as it starts waiting for its writer threads.
        Draining,
    }

    type Gate = (mpsc::Sender<()>, Arc<Mutex<mpsc::Receiver<()>>>);
    static GATES: Mutex<Option<HashMap<(PathBuf, Role), Gate>>> = Mutex::new(None);

    /// Held `role` writes to `path` signal on the returned receiver as they
    /// enter; each `()` sent on the returned sender releases one. Dropping
    /// the sender releases every later one.
    pub(crate) fn arm(path: &Path, role: Role) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        GATES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(
                (path.to_path_buf(), role),
                (entered_tx, Arc::new(Mutex::new(release_rx))),
            );
        (entered_rx, release_tx)
    }

    static OPENERS: Mutex<Option<HashMap<PathBuf, String>>> = Mutex::new(None);

    /// Record the test a window at `path` was opened for.
    pub(crate) fn record_opener(path: &Path, opener: &str) {
        OPENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(path.to_path_buf(), opener.to_owned());
    }

    /// The test the window at `path` was last opened for, if any.
    pub(crate) fn opened_by(path: &Path) -> Option<String> {
        OPENERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|openers| openers.get(path).cloned())
    }

    pub(crate) fn pass(path: &Path, role: Role) {
        let gate = GATES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|gates| gates.get(&(path.to_path_buf(), role)).cloned());
        if let Some((entered, release)) = gate {
            let _ = entered.send(());
            let _ = release
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv();
        }
    }
}
