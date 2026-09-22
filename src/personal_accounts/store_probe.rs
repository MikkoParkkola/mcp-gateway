// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only observation of REAL store operations.
//!
//! WHY IT LIVES HERE AND NOT IN A WRAPPER. A witness placed in a caller records
//! what the caller says it is about to do. `phase(kind, id, || ())` on a
//! blocking thread, with the actual store call made somewhere else entirely,
//! satisfies such a witness completely — it authenticates the wrapper, not the
//! store. So the observation point is inside the store operation itself, past
//! the authority guard and immediately before the real `storage::` call. A
//! caller that skips the store reaches nothing here, and a caller that performs
//! synchronous store I/O on the event loop records the runtime's own thread.
//!
//! SCOPED BY STORE DIRECTORY. Every test builds its own `TempDir`, so a
//! recording watches one path and unrelated parallel store tests are invisible.
//! Account digests are not enough: fixtures across tests share one account key.
//!
//! NO GUARD IS HELD ACROSS AN AWAIT. Everything here is synchronous; a parked
//! operation blocks its own thread and nothing else.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::oneshot;

/// Bounds a failure only. Progress is always made by a real event.
const DEADLOCK: Duration = Duration::from_secs(5);

/// The real operations, named where they actually happen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreOp {
    /// The single authority acquisition every operation passes through.
    AuthorityAcquired,
    Lookup,
    CommitGrant,
    RefreshTokens,
    Revoke,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) op: StoreOp,
    pub(crate) thread: String,
}

static SERIAL: Mutex<()> = Mutex::new(());
static STATE: Mutex<Option<State>> = Mutex::new(None);

struct State {
    store_dir: PathBuf,
    entered: Vec<Entry>,
    park: Option<(StoreOp, oneshot::Sender<()>, Receiver<()>)>,
}

fn state() -> MutexGuard<'static, Option<State>> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Called from inside a real store operation. Records the thread that is
/// actually executing it, and stalls there if a test armed this operation.
pub(crate) fn entered(op: StoreOp, store_dir: &Path) {
    let parked = {
        let mut slot = state();
        match slot.as_mut() {
            Some(state) if state.store_dir == store_dir => {
                state.entered.push(Entry {
                    op,
                    thread: format!("{:?}", std::thread::current().id()),
                });
                match &state.park {
                    Some((armed, _, _)) if *armed == op => state.park.take(),
                    _ => None,
                }
            }
            _ => None,
        }
    };
    if let Some((_, entered, release)) = parked {
        // Announce to an awaiting test, then block THIS thread only.
        let _ = entered.send(());
        let _ = release.recv_timeout(DEADLOCK);
    }
}

/// Watch one store directory. Also serialises the observing tests.
pub(crate) fn watch(store_dir: &Path) -> Recording {
    let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *state() = Some(State {
        store_dir: store_dir.to_path_buf(),
        entered: Vec::new(),
        park: None,
    });
    Recording { _serial: serial }
}

pub(crate) struct Recording {
    _serial: MutexGuard<'static, ()>,
}

impl Recording {
    #[expect(
        clippy::unused_self,
        reason = "self is the recording's exclusivity guard, not a data source; the entries live in the global state() singleton by design"
    )]
    pub(crate) fn entries(&self) -> Vec<Entry> {
        state()
            .as_ref()
            .map(|s| s.entered.clone())
            .unwrap_or_default()
    }

    pub(crate) fn ops(&self) -> Vec<StoreOp> {
        self.entries().into_iter().map(|entry| entry.op).collect()
    }

    /// Every thread a real store operation ran on.
    pub(crate) fn threads(&self) -> Vec<String> {
        let mut threads: Vec<String> = self
            .entries()
            .into_iter()
            .map(|entry| entry.thread)
            .collect();
        threads.sort();
        threads.dedup();
        threads
    }

    /// Stall the next occurrence of `op` inside the store operation itself.
    #[expect(
        clippy::unused_self,
        reason = "self is the recording's exclusivity guard, not a data source; the park state lives in the global state() singleton by design"
    )]
    pub(crate) fn park(&self, op: StoreOp) -> Park {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = channel();
        if let Some(state) = state().as_mut() {
            state.park = Some((op, entered_tx, release_rx));
        }
        Park {
            entered: Some(entered_rx),
            release: release_tx,
        }
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        *state() = None;
    }
}

pub(crate) struct Park {
    entered: Option<oneshot::Receiver<()>>,
    release: Sender<()>,
}

impl Park {
    /// Await the store operation actually reaching the stall.
    ///
    /// ASYNC on purpose: blocking here on a current-thread runtime would
    /// stop the very task trying to enter, and no implementation could pass.
    pub(crate) async fn wait_entered(&mut self) {
        let entered = self.entered.take().expect("wait_entered is called once");
        tokio::time::timeout(DEADLOCK, entered)
            .await
            .expect("a real store operation reached the stall within the deadlock bound")
            .expect("the parked store operation kept its entry signal");
    }

    pub(crate) fn release(self) {
        let _ = self.release.send(());
    }
}
