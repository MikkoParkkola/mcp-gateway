// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8204 test-only seams (test plan t4, S1-S4). Every seam is a
//! thread-local: the rows run on `#[tokio::test]`'s current-thread runtime,
//! where the request, the worker and the slot writes all poll on the test's
//! own thread, so parallel tests cannot see each other's seams.
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::Map;
use tokio::sync::Notify;

use super::{DECISION_KIND, GrantNote, Slot, TransparencyLogger};

#[derive(Default)]
struct Hold {
    held: AtomicBool,
    held_notify: Notify,
    release: Notify,
}

/// S1: the parked write. Dropping it releases the write, so a failing row
/// cannot pin it.
pub(crate) struct HoldHandle(Arc<Hold>);

impl HoldHandle {
    /// Wait until a grant-record write has reached the hold.
    pub(crate) async fn held(&self) {
        loop {
            let notified = self.0.held_notify.notified();
            if self.has_held() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn has_held(&self) -> bool {
        self.0.held.load(Ordering::SeqCst)
    }

    pub(crate) fn release(&self) {
        self.0.release.notify_one();
    }
}

impl Drop for HoldHandle {
    fn drop(&mut self) {
        self.release();
    }
}

/// When an injected note enters a slot (S3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inject {
    /// The next outermost slot opened on this thread.
    NextSlotOpen,
    /// The slot open where the next worker is spawned, right after the spawn.
    AfterNextSpawn,
}

/// What `spawn_worker` saw at a worker spawn (S2's rising edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpawnSnapshot {
    pub(crate) appends: usize,
    pub(crate) holds_signalled: usize,
}

thread_local! {
    static HOLD: RefCell<Option<Arc<Hold>>> = const { RefCell::new(None) };
    static HOLD_BEST_EFFORT: RefCell<Option<Arc<Hold>>> = const { RefCell::new(None) };
    static FAIL_AT: Cell<usize> = const { Cell::new(0) };
    static FAIL_TOOL: RefCell<Option<String>> = const { RefCell::new(None) };
    static APPENDS: Cell<usize> = const { Cell::new(0) };
    static ON_OPEN: RefCell<Vec<GrantNote>> = const { RefCell::new(Vec::new()) };
    static AFTER_SPAWN: RefCell<Vec<GrantNote>> = const { RefCell::new(Vec::new()) };
    static HOLDS_SIGNALLED: Cell<usize> = const { Cell::new(0) };
    static SPAWNS: RefCell<Vec<SpawnSnapshot>> = const { RefCell::new(Vec::new()) };
    static SETTLE_WAITING: Cell<bool> = const { Cell::new(false) };
}

/// S1: park the next grant-record write at its start, before it is handed to
/// the log's blocking append, on whichever task performs it.
pub(crate) fn hold_next_write_for_test() -> HoldHandle {
    let hold = Arc::new(Hold::default());
    HOLD.with(|h| *h.borrow_mut() = Some(Arc::clone(&hold)));
    HoldHandle(hold)
}

pub(super) async fn at_write_start() {
    park_at(&HOLD).await;
}

/// S5: park the next best-effort (withheld-note) write at its start, so a row
/// can prove nothing awaits it and that it cannot take the append permit
/// ahead of the slot's own flush.
pub(crate) fn hold_next_best_effort_write_for_test() -> HoldHandle {
    let hold = Arc::new(Hold::default());
    HOLD_BEST_EFFORT.with(|h| *h.borrow_mut() = Some(Arc::clone(&hold)));
    HoldHandle(hold)
}

pub(super) async fn at_best_effort_start() {
    park_at(&HOLD_BEST_EFFORT).await;
}

async fn park_at(cell: &'static std::thread::LocalKey<RefCell<Option<Arc<Hold>>>>) {
    let Some(hold) = cell.with(|h| h.borrow_mut().take()) else {
        return;
    };
    HOLDS_SIGNALLED.with(|n| n.set(n.get() + 1));
    hold.held.store(true, Ordering::SeqCst);
    hold.held_notify.notify_waiters();
    hold.release.notified().await;
}

/// S4: fail the `n`-th grant-record append from now (1 = the next).
pub(crate) fn fail_append_at_for_test(n: usize) {
    FAIL_AT.with(|f| f.set(n));
}

/// Fail the next grant-record append whose note is for `tool`, wherever it
/// falls in the order of appends.
pub(crate) fn fail_append_of_tool_for_test(tool: &str) {
    FAIL_TOOL.with(|f| *f.borrow_mut() = Some(tool.to_owned()));
}

/// Whether the tool-targeted fault of [`fail_append_of_tool_for_test`] is
/// still armed, i.e. no append has consumed it yet.
pub(crate) fn tool_fault_pending_for_test() -> bool {
    FAIL_TOOL.with(|f| f.borrow().is_some())
}

/// Count one grant-record append for `note`; whether a seam fails it.
pub(super) fn fail_this_append(note: &GrantNote) -> bool {
    APPENDS.with(|a| a.set(a.get() + 1));
    let by_tool = FAIL_TOOL.with(|f| {
        let hit = f.borrow().as_deref() == Some(note.tool.as_str());
        if hit {
            *f.borrow_mut() = None;
        }
        hit
    });
    if by_tool {
        return true;
    }
    FAIL_AT.with(|f| match f.get() {
        0 => false,
        1 => {
            f.set(0);
            true
        }
        n => {
            f.set(n - 1);
            false
        }
    })
}

/// Grant-record appends attempted on this thread.
pub(crate) fn appends_for_test() -> usize {
    APPENDS.with(Cell::get)
}

/// S3: a decision note for `(server, tool)`, injected at `when`. It is only
/// put in the slot; the slot's own writes append it.
pub(crate) fn inject_note_for_test(server: &str, tool: &str, when: Inject) {
    let mut fields = Map::new();
    fields.insert("kind".into(), DECISION_KIND.into());
    fields.insert("capability".into(), server.into());
    fields.insert("tool".into(), tool.into());
    let note = GrantNote {
        server: server.to_owned(),
        tool: tool.to_owned(),
        trace_id: None,
        allowed: true,
        fields,
        subject: None,
        repeat: None,
        delivery: false,
        recorded: super::RecordedSet::default(),
        retry: None,
    };
    match when {
        Inject::NextSlotOpen => ON_OPEN.with(|n| n.borrow_mut().push(note)),
        Inject::AfterNextSpawn => AFTER_SPAWN.with(|n| n.borrow_mut().push(note)),
    }
}

pub(super) fn on_slot_open(slot: &Slot) {
    let pending = ON_OPEN.with(|n| std::mem::take(&mut *n.borrow_mut()));
    slot.notes.lock().expect("grant slot lock").extend(pending);
}

/// S2: called by `spawn_worker` at the worker's spawn.
pub(crate) fn count_worker_spawn() {
    SPAWNS.with(|s| {
        s.borrow_mut().push(SpawnSnapshot {
            appends: appends_for_test(),
            holds_signalled: HOLDS_SIGNALLED.with(Cell::get),
        });
    });
}

/// S3 `AfterNextSpawn`: put the pending notes in the slot open here.
pub(crate) fn after_worker_spawn() {
    let pending = AFTER_SPAWN.with(|n| std::mem::take(&mut *n.borrow_mut()));
    if pending.is_empty() {
        return;
    }
    super::GRANT_SLOT
        .try_with(|slot| slot.notes.lock().expect("grant slot lock").extend(pending))
        .expect("an injected after-spawn note needs an open slot");
}

/// S2: the snapshots of every worker spawn on this thread, in order.
pub(crate) fn worker_spawns_for_test() -> Vec<SpawnSnapshot> {
    SPAWNS.with(|s| s.borrow().clone())
}

/// Grant-record writes in flight, per transparency log (keyed by its path).
/// Unlike the seams above this is not a thread-local: the count belongs to
/// the fixture's log, so a write polled on another worker thread still
/// brings it back down.
static IN_FLIGHT: LazyLock<Mutex<HashMap<PathBuf, Arc<AtomicUsize>>>> =
    LazyLock::new(Mutex::default);

fn in_flight(log: &TransparencyLogger) -> Arc<AtomicUsize> {
    // invariant: nothing panics while holding the map lock, so it is never poisoned.
    let mut counts = IN_FLIGHT.lock().expect("in-flight map lock");
    Arc::clone(counts.entry(log.path()).or_default())
}

/// One grant-record write counted in flight. Dropping it, however the write
/// ends (finished, panicked or cancelled), takes it off the count.
pub(crate) struct WriteInFlight(Arc<AtomicUsize>);

impl Drop for WriteInFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A slot spawns a grant-record write to `log`; the spawned task holds the
/// returned guard until it ends.
pub(crate) fn write_spawned(log: &TransparencyLogger) -> WriteInFlight {
    let count = in_flight(log);
    count.fetch_add(1, Ordering::SeqCst);
    WriteInFlight(count)
}

/// How many grant-record writes to `log` are in flight now.
pub(crate) fn writes_in_flight_for_test(log: &TransparencyLogger) -> usize {
    in_flight(log).load(Ordering::SeqCst)
}

/// Wait until every grant-record write to `log` has finished, so a row
/// counting records sees the late ones too: a withheld call's own record is
/// written after its answer, on the slot's task, and no caller waits for it.
/// Then wait out an append still in the kernel: a write whose async bound
/// passed ends its task while its blocking append can still land. Panics
/// after 10 s, naming how many writes are still running.
pub(crate) async fn grant_writes_settled_for_test(log: &Arc<TransparencyLogger>) {
    let count = in_flight(log);
    let settled = crate::test_wait::wait_real_time(std::time::Duration::from_secs(10), || {
        let running = count.load(Ordering::SeqCst);
        SETTLE_WAITING.with(|w| w.set(running > 0));
        running == 0
    })
    .await;
    SETTLE_WAITING.with(|w| w.set(false));
    if let Err(late) = settled {
        panic!(
            "{} grant-record writes still running: {late}",
            count.load(Ordering::SeqCst)
        );
    }
    let drained = Arc::clone(log);
    let cleared = tokio::task::spawn_blocking(move || {
        drained.wait_write_cleared_for_test(crate::test_wait::HANG_BOUND)
    })
    .await
    .expect("the drain does not panic");
    assert!(cleared, "the last grant-record append left the kernel");
}

/// Whether [`grant_writes_settled_for_test`] is waiting on this thread now: a
/// row forcing a late write releases it only while a count waits for it.
pub(crate) fn settle_waiting_for_test() -> bool {
    SETTLE_WAITING.with(Cell::get)
}
