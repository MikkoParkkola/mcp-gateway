// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only pause points for the health floor rows (restart slice 6b). A
//! row arms the Nth arrival at a named point for one key (a file path or a
//! history's address), waits until a thread reaches it, observes the state
//! inside the window, then releases it. Unarmed arrivals pass straight
//! through, so parallel rows never park each other's threads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// How long either side waits before giving up: a parked thread continues,
/// a row's wait fails with its own message. Never a hang.
const WAIT: Duration = Duration::from_secs(30);

/// The named points (test-plan P1-P8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Point {
    /// P1: the saver, the last statement before SAVES.try_lock.
    SaverBeforeLock,
    /// P2: a save, after its snapshot is encoded and before the write.
    AfterSnapshot,
    /// P3: the checkpoint worker, just before SAVES.lock().
    WorkerWaiting,
    /// P4: the checkpoint worker, after its live check passed.
    AfterLiveCheck,
    /// P5: admission, between the mark and the second read.
    AdmissionMark,
    /// P6: the sampler, after the sample is applied and before the tick.
    SampleBeforeTick,
    /// P7: the resume replay, before its sample.
    ReplayBeforeSample,
    /// P8: the sampler, the last statement before the history lock.
    SamplerBeforeLock,
}

struct Arm {
    /// Which `arm` call made it, so a stale handle never disarms a newer one.
    id: u64,
    /// Arrivals still to pass before the armed one.
    skip: usize,
    reached: Sender<()>,
    release: Receiver<()>,
}

type Key = (Point, String);

fn arms() -> &'static Mutex<HashMap<Key, Arm>> {
    static ARMS: OnceLock<Mutex<HashMap<Key, Arm>>> = OnceLock::new();
    ARMS.get_or_init(Mutex::default)
}

/// The row's side of one armed arrival.
pub(crate) struct Parked {
    id: u64,
    key: Key,
    what: String,
    reached: Receiver<()>,
    release: Option<Sender<()>>,
}

/// Arm the `nth` arrival (1 = the next) at `point` for `key`.
pub(crate) fn arm(point: Point, key: &str, nth: usize) -> Parked {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let (reached_tx, reached) = channel();
    let (release, release_rx) = channel();
    let arm = Arm {
        id,
        skip: nth.saturating_sub(1),
        reached: reached_tx,
        release: release_rx,
    };
    arms()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((point, key.to_owned()), arm);
    Parked {
        id,
        key: (point, key.to_owned()),
        what: format!("{point:?} for {key}"),
        reached,
        release: Some(release),
    }
}

/// Called at the point in the code under test.
pub(crate) fn at(point: Point, key: &str) {
    let armed = {
        let mut arms = arms()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let k = (point, key.to_owned());
        match arms.get_mut(&k) {
            Some(arm) if arm.skip > 0 => {
                arm.skip -= 1;
                None
            }
            Some(_) => arms.remove(&k),
            None => None,
        }
    };
    if let Some(arm) = armed {
        let _ = arm.reached.send(());
        let _ = arm.release.recv_timeout(WAIT);
    }
}

impl Parked {
    /// Wait until a thread is parked here; `missing` names the behaviour
    /// whose absence a timeout means.
    pub(crate) fn reached(&self, missing: &str) {
        assert!(
            self.reached.recv_timeout(WAIT).is_ok(),
            "{missing} (no arrival at {})",
            self.what
        );
    }

    /// Whether a thread has arrived here (non-blocking; consumes the signal).
    pub(crate) fn arrived(&self) -> bool {
        self.reached.try_recv().is_ok()
    }

    /// Let the parked thread go on.
    pub(crate) fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for Parked {
    /// A failing row still lets its parked thread go, and an arrival that
    /// never came is disarmed (the panic-safe guard).
    fn drop(&mut self) {
        self.release();
        let mut arms = arms()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if arms.get(&self.key).is_some_and(|arm| arm.id == self.id) {
            arms.remove(&self.key);
        }
    }
}
