// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seams of `transparency_log_rotation`: fault injection, the F20
//! stall gate and the logger's test hooks. Compiled only under `cfg(test)`.

/// A write fault the tests arm on one logger.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteFault {
    /// Write half the line, then ENOSPC on every write until `<path>.reserve`
    /// is unlinked.
    FullUntilReserveFreed,
    /// ENOSPC on every write, and the reserve cannot be unlinked either.
    FullForever,
    /// The expiry record writes, its `sync_all` fails.
    ExpirySyncFails,
    /// ENOSPC on the open-record write right after a rename, once.
    FullAfterRename,
    /// A plain I/O error (not ENOSPC) on the next line write, once.
    WriteError,
    /// A plain I/O error on the next synced append's `sync_all`, once.
    SyncError,
}

/// F20: holds one write "in the kernel" until the test opens it. Every test
/// opens it explicitly (the guard from `stall_next_write_for_test` also
/// opens it on drop); the 60 s deadline is only a hang guard, turning an
/// unbounded append (a mutant) into a failed assertion, never a timing bound.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct StallGate {
    state: std::sync::Mutex<GateState>,
    cv: std::sync::Condvar,
}

#[cfg(test)]
impl StallGate {
    pub(crate) const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Record entry, then block the writer until opened or the deadline.
    pub(crate) fn hold(&self) {
        let mut s = self.state.lock().expect("gate lock");
        s.entered = true;
        self.cv.notify_all();
        let _ = self
            .cv
            .wait_timeout_while(s, Self::DEADLINE, |s| !s.open)
            .expect("gate lock");
    }

    /// Wait until a write has entered `hold` (up to the deadline); whether
    /// it did.
    pub(crate) fn wait_entered(&self) -> bool {
        let s = self.state.lock().expect("gate lock");
        self.cv
            .wait_timeout_while(s, Self::DEADLINE, |s| !s.entered)
            .expect("gate lock")
            .0
            .entered
    }

    /// Whether a write has reached `hold` (no wait).
    pub(crate) fn is_entered(&self) -> bool {
        self.state.lock().expect("gate lock").entered
    }

    /// Let the held write finish.
    pub(crate) fn release(&self) {
        self.state.lock().expect("gate lock").open = true;
        self.cv.notify_all();
    }
}

#[cfg(test)]
#[derive(Default)]
struct GateState {
    /// A write has reached `hold`.
    entered: bool,
    /// The test let the write go.
    open: bool,
}

/// Opens its gate on drop, so a failed assertion never leaves a write held.
#[cfg(test)]
#[must_use = "dropping the guard releases the stalled write at once"]
pub(crate) struct StallRelease(pub(crate) std::sync::Arc<StallGate>);

#[cfg(test)]
impl std::ops::Deref for StallRelease {
    type Target = StallGate;
    fn deref(&self) -> &StallGate {
        &self.0
    }
}

#[cfg(test)]
impl Drop for StallRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Files whose real `sync_all` succeeded, by (device, inode); keyed per file
/// so other tests' syncs cannot mask a skipped one.
#[cfg(all(test, unix))]
static SYNCED: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());

/// Record one successful real sync of `file`.
#[cfg(test)]
pub(crate) fn note_synced(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        SYNCED.lock().unwrap().push((meta.dev(), meta.ino()));
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// How many real syncs the file at `path` has had so far.
#[cfg(all(test, unix))]
pub(crate) fn syncs_of(path: &std::path::Path) -> usize {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).unwrap();
    let key = (meta.dev(), meta.ino());
    SYNCED.lock().unwrap().iter().filter(|k| **k == key).count()
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    /// The test that opened this logger, named on a late write.
    pub(crate) created_by: crate::test_late_write::Creator,
    pub(crate) fault: std::sync::Mutex<Option<WriteFault>>,
    /// A one-shot settle refusal (V.1 `FailSettle`).
    pub(crate) settle_fault: std::sync::Mutex<Option<super::super::settle::FailSettle>>,
    /// The id settle sees as the logger's (V.1 `Bind(OtherLog)`).
    pub(crate) presented_id: std::sync::Mutex<Option<super::super::identity::LogId>>,
    /// Holds settle's blocking task before it starts.
    pub(crate) settle_start: std::sync::Mutex<Option<std::sync::Arc<StallGate>>>,
    pub(crate) fault_fired: std::sync::atomic::AtomicUsize,
    /// Envelope evidence only; D7 reconstructs caller fields and the hash independently.
    pub(crate) partial_write_trace: std::sync::Mutex<Option<String>>,
    /// Runs once after a partial write, before `write_line` can call `cut_back`.
    pub(crate) after_partial_write: std::sync::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub(crate) clock_offset: std::sync::atomic::AtomicI64,
    /// F20: the next write blocks on this gate (a stalled filesystem).
    pub(crate) stall: std::sync::Mutex<Option<std::sync::Arc<StallGate>>>,
    /// F20: probe appends started.
    pub(crate) probes: std::sync::atomic::AtomicUsize,
    /// Set once the disk-full path has unlinked the reserve.
    pub(crate) reserve_released: std::sync::atomic::AtomicBool,
    /// Set while an expiry record is being written.
    pub(crate) expiry_in_flight: std::sync::atomic::AtomicBool,
    /// Called between rename and the new open record, with the logger.
    #[allow(clippy::type_complexity)]
    pub(crate) in_rotation:
        std::sync::Mutex<Option<Box<dyn Fn(&super::super::TransparencyLogger) + Send>>>,
}

#[cfg(test)]
impl super::super::TransparencyLogger {
    pub(crate) fn arm_write_fault(&self, fault: Option<WriteFault>) {
        *self.hooks.fault.lock().unwrap() = fault;
    }
    #[cfg(unix)]
    pub(crate) fn arm_after_partial_write(&self, callback: Option<Box<dyn Fn() + Send + Sync>>) {
        *self.hooks.after_partial_write.lock().unwrap() = callback;
    }
    pub(crate) fn write_faults_fired(&self) -> usize {
        self.hooks
            .fault_fired
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn note_partial_write_trace(&self, bytes: &[u8]) {
        let record: serde_json::Value = serde_json::from_slice(bytes).expect("faulted record");
        *self.hooks.partial_write_trace.lock().unwrap() =
            record["trace_id"].as_str().map(str::to_owned);
    }
    #[cfg(unix)]
    pub(crate) fn partial_write_trace_for_test(&self) -> Option<String> {
        self.hooks.partial_write_trace.lock().unwrap().clone()
    }
    pub(crate) fn set_clock_offset(&self, secs: i64) {
        self.hooks
            .clock_offset
            .store(secs, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn on_rotation_window(
        &self,
        f: Box<dyn Fn(&super::super::TransparencyLogger) + Send>,
    ) {
        *self.hooks.in_rotation.lock().unwrap() = Some(f);
    }
    /// Whether another thread could take `Inner` right now.
    pub(crate) fn inner_is_free(&self) -> bool {
        self.inner.try_lock().is_ok()
    }
}
