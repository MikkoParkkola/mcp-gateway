// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seams for the config history's record path: where a test parks the
//! record task or the save job, which fault the save job meets, and an
//! ordered log of every swap, overlay publication and refusal.
//!
//! Seams are found by the data directory the store lives in, so a store's
//! startup worker and its blocking jobs (other threads, other tasks) see the
//! seams a test installed for that directory and no other test's. Every wait
//! here is bounded, and a dropped [`Installed`] releases every gate it holds,
//! so a row that fails mid-way cannot leave a job parked for the next row.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

/// The longest any parked side waits for its release before giving up.
const PARK_BOUND: Duration = Duration::from_secs(30);

/// One stop point: the code under test signals its arrival and waits for the
/// test's release; the test can await the arrival and, afterwards, the
/// completion of the step the gate guards.
#[derive(Default)]
pub(crate) struct Gate {
    arrived: Notify,
    released: AtomicBool,
    wake: (Mutex<()>, Condvar),
    wake_async: Notify,
    completed: Notify,
}

impl Gate {
    /// The code under test, on a blocking thread: say it arrived, then wait
    /// for the release (at most [`PARK_BOUND`]).
    pub(crate) fn park_blocking(&self) {
        self.arrived.notify_one();
        let (lock, cv) = &self.wake;
        let guard = lock.lock().expect("gate lock");
        let _unused = cv
            .wait_timeout_while(guard, PARK_BOUND, |()| {
                !self.released.load(Ordering::SeqCst)
            })
            .expect("gate wait");
    }

    /// The code under test, in a task: say it arrived, then wait for the
    /// release (at most [`PARK_BOUND`] of real time).
    pub(crate) async fn park_async(&self) {
        self.arrived.notify_one();
        let released = async {
            while !self.released.load(Ordering::SeqCst) {
                let woken = self.wake_async.notified();
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                woken.await;
            }
        };
        // Real time, not the runtime's clock: a paused clock must not end the park.
        let bound = std::time::Instant::now() + PARK_BOUND;
        tokio::select! {
            () = released => {}
            () = until_real(bound) => {}
        }
    }

    /// The code under test: the step after the gate is done.
    pub(crate) fn finished(&self) {
        self.completed.notify_one();
    }

    /// The test: wait for the arrival.
    pub(crate) async fn arrival(&self) {
        self.arrived.notified().await;
    }

    /// The test: wait for the guarded step to finish.
    pub(crate) async fn completion(&self) {
        self.completed.notified().await;
    }

    /// The test: let the parked side go on.
    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let (lock, cv) = &self.wake;
        drop(lock.lock().expect("gate lock"));
        cv.notify_all();
        self.wake_async.notify_waiters();
    }
}

/// Polls real time on a blocking thread, so a paused tokio clock cannot end it early.
async fn until_real(deadline: std::time::Instant) {
    let wait = deadline.saturating_duration_since(std::time::Instant::now());
    let _ = tokio::task::spawn_blocking(move || std::thread::sleep(wait)).await;
}

/// Where the save job (or the startup worker) stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkAt {
    /// Startup: open, before it reads the file.
    OpenBeforeRead,
    /// A save, before it reads the store.
    BeforeRead,
    /// A save, after its temp file is written and before the generation check.
    BeforeCheck,
    /// A save, after a passed generation check and before the rename.
    AfterCheck,
    /// Startup: open, after a passed generation check, before the quarantine's hard link.
    BeforeQuarantineLink,
}

/// The one fault the next save job meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The read fails with an I/O error.
    ReadIo,
    /// The read returns bytes that do not parse.
    Unparseable,
    /// The temp-file write fails.
    Write,
    /// The job panics before it sends its state back.
    PanicBeforeSend,
    /// The job drops its sender without sending.
    DropSender,
}

/// One entry of the ordered log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observed {
    /// A swap under the swap locks: the revision published and the files of its inputs.
    Swap {
        revision: String,
        files: Vec<(String, Option<Vec<u8>>)>,
    },
    /// The overlay published for `revision`.
    Overlay { revision: String },
    /// A refused reload, at the point `record_refused` records it, under `lock_reload`.
    Refusal,
}

/// The seams installed for one data directory.
#[derive(Default)]
pub(crate) struct Seams {
    park: Mutex<Option<(ParkAt, Arc<Gate>)>>,
    fault: Mutex<Option<Fault>>,
    record_reached: Mutex<Option<Arc<Gate>>>,
    log: Mutex<Vec<Observed>>,
    guard_waits: Notify,
    fail_spawn: AtomicBool,
    /// Every gate handed out, taken by the code under test or not, so a
    /// dropped [`Installed`] can release them all.
    handed_out: Mutex<Vec<Arc<Gate>>>,
}

impl Seams {
    /// Park the next job that reaches `at`; the gate is returned to the test.
    pub(crate) fn park(&self, at: ParkAt) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        *self.park.lock().expect("park") = Some((at, Arc::clone(&gate)));
        self.handed_out
            .lock()
            .expect("gates")
            .push(Arc::clone(&gate));
        gate
    }

    /// Park the next record task at its start (the record-reached point).
    pub(crate) fn park_record(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        *self.record_reached.lock().expect("record") = Some(Arc::clone(&gate));
        self.handed_out
            .lock()
            .expect("gates")
            .push(Arc::clone(&gate));
        gate
    }

    /// The next save job meets `fault`.
    pub(crate) fn fail(&self, fault: Fault) {
        *self.fault.lock().expect("fault") = Some(fault);
    }

    /// The ordered log so far.
    pub(crate) fn log(&self) -> Vec<Observed> {
        self.log.lock().expect("log").clone()
    }

    /// Code under test: the gate for `at`, taken once.
    pub(crate) fn take_park(&self, at: ParkAt) -> Option<Arc<Gate>> {
        let mut slot = self.park.lock().expect("park");
        match slot.as_ref() {
            Some((want, _)) if *want == at => slot.take().map(|(_, gate)| gate),
            _ => None,
        }
    }

    /// Code under test: the record-reached gate, taken once.
    pub(crate) fn take_record_park(&self) -> Option<Arc<Gate>> {
        self.record_reached.lock().expect("record").take()
    }

    /// Code under test: the fault for this job, taken once.
    pub(crate) fn take_fault(&self) -> Option<Fault> {
        self.fault.lock().expect("fault").take()
    }

    /// The next startup's worker fails to spawn.
    pub(crate) fn fail_startup_spawn(&self) {
        self.fail_spawn.store(true, Ordering::SeqCst);
    }

    /// Code under test: whether this startup's worker spawn is to fail, taken once.
    pub(crate) fn take_spawn_failure(&self) -> bool {
        self.fail_spawn.swap(false, Ordering::SeqCst)
    }

    /// Code under test: a reload found the record guard held and waits for it.
    pub(crate) fn note_guard_wait(&self) {
        self.guard_waits.notify_one();
    }

    /// The test: wait until a reload waits for the record guard.
    pub(crate) async fn guard_waited(&self) {
        self.guard_waits.notified().await;
    }

    /// Code under test: append to the ordered log.
    pub(crate) fn observe(&self, entry: Observed) {
        self.log.lock().expect("log").push(entry);
    }

    fn release_all(&self) {
        // A failed row must not leave a job parked: the runtime's drop waits
        // for its blocking jobs, and a parked one would turn the row's own
        // failure into a hang.
        for gate in self.handed_out.lock().expect("gates").drain(..) {
            gate.release();
        }
        self.park.lock().expect("park").take();
        self.record_reached.lock().expect("record").take();
    }
}

static INSTALLED: LazyLock<Mutex<HashMap<PathBuf, Arc<Seams>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Seams for `data_dir` until this guard drops; dropping it releases every
/// gate not yet taken and removes the seams.
pub(crate) struct Installed {
    dir: PathBuf,
    pub(crate) seams: Arc<Seams>,
}

impl Drop for Installed {
    fn drop(&mut self) {
        self.seams.release_all();
        INSTALLED.lock().expect("installed").remove(&self.dir);
    }
}

/// Install seams for `data_dir`.
pub(crate) fn install(data_dir: &Path) -> Installed {
    let seams = Arc::new(Seams::default());
    INSTALLED
        .lock()
        .expect("installed")
        .insert(data_dir.to_path_buf(), Arc::clone(&seams));
    Installed {
        dir: data_dir.to_path_buf(),
        seams,
    }
}

/// Code under test: the seams installed for the directory `history_file` is in.
pub(crate) fn for_file(history_file: &Path) -> Option<Arc<Seams>> {
    let dir = history_file.parent()?;
    INSTALLED.lock().expect("installed").get(dir).cloned()
}

/// The seams one save job meets: its fault, taken once, and the gates it
/// parks at; every gate it parked at is told when the job is done.
pub(super) struct JobSeams {
    seams: Option<Arc<Seams>>,
    pub(super) fault: Option<Fault>,
    parked: std::cell::RefCell<Vec<Arc<Gate>>>,
}

impl JobSeams {
    pub(super) fn take(path: &Path) -> Self {
        let seams = for_file(path);
        let fault = seams.as_ref().and_then(|s| s.take_fault());
        Self {
            seams,
            fault,
            parked: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub(super) fn park(&self, at: ParkAt) {
        if let Some(gate) = self.seams.as_ref().and_then(|s| s.take_park(at)) {
            gate.park_blocking();
            self.parked.borrow_mut().push(gate);
        }
    }

    pub(super) fn read(&self, path: &Path) -> Result<super::State, String> {
        match self.fault {
            Some(Fault::ReadIo) => Err("injected read fault".to_string()),
            Some(Fault::Unparseable) => {
                serde_json::from_slice::<super::State>(b"{not json").map_err(|e| e.to_string())
            }
            _ => super::load_state(path),
        }
    }

    pub(super) fn done(&self) {
        for gate in self.parked.borrow_mut().drain(..) {
            gate.finished();
        }
    }
}
