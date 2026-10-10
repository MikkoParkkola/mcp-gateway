// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8204 test-only seams (test plan t4, S1-S4). Every seam is a
//! thread-local: the rows run on `#[tokio::test]`'s current-thread runtime,
//! where the request, the worker and the slot writes all poll on the test's
//! own thread, so parallel tests cannot see each other's seams.
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Map;
use tokio::sync::Notify;

use super::{DECISION_KIND, GrantNote, Slot};

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
    static FAIL_AT: Cell<usize> = const { Cell::new(0) };
    static APPENDS: Cell<usize> = const { Cell::new(0) };
    static ON_OPEN: RefCell<Vec<GrantNote>> = const { RefCell::new(Vec::new()) };
    static AFTER_SPAWN: RefCell<Vec<GrantNote>> = const { RefCell::new(Vec::new()) };
    static HOLDS_SIGNALLED: Cell<usize> = const { Cell::new(0) };
    static SPAWNS: RefCell<Vec<SpawnSnapshot>> = const { RefCell::new(Vec::new()) };
}

/// S1: park the next grant-record write at its start, before it is handed to
/// the log's blocking append, on whichever task performs it.
pub(crate) fn hold_next_write_for_test() -> HoldHandle {
    let hold = Arc::new(Hold::default());
    HOLD.with(|h| *h.borrow_mut() = Some(Arc::clone(&hold)));
    HoldHandle(hold)
}

pub(super) async fn at_write_start() {
    let Some(hold) = HOLD.with(|h| h.borrow_mut().take()) else {
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

/// Count one grant-record append; whether S4 fails it.
pub(super) fn fail_this_append() -> bool {
    APPENDS.with(|a| a.set(a.get() + 1));
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
