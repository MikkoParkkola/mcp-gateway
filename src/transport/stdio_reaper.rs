// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One reaper thread per process for stdio process trees (MIK-7923, design P4).
//!
//! A retired or closed child's tree is handed over here and ended without any
//! Tokio runtime: the thread steps every tree it holds with
//! [`ChildTree::reap_step`] every [`TICK`], so a retire on an idle runtime still
//! ends the tree, and one stuck leader delays no other. The thread is created
//! before any child is spawned ([`ensure_started`]); after that a handover is a
//! channel send that cannot fail while the thread lives.

use std::process::ExitStatus;
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::error;

use super::child_tree::{ChildTree, Reap};

/// How often the reaper steps the trees it holds.
const TICK: Duration = Duration::from_millis(10);

/// A handed-over tree's progress, as its waiters see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reaped {
    Pending,
    Done(Option<ExitStatus>),
}

struct Job {
    tree: ChildTree,
    done: watch::Sender<Reaped>,
}

static REAPER: OnceLock<mpsc::Sender<Job>> = OnceLock::new();
static START: parking_lot::Mutex<()> = parking_lot::const_mutex(());

/// Start the reaper thread if it is not running yet. Called by every stdio
/// start before it spawns a child, so no child exists that the reaper could
/// not take.
///
/// # Errors
///
/// The OS refused the thread; the start must spawn nothing.
pub(super) fn ensure_started() -> std::io::Result<()> {
    start_once(&REAPER, |receiver| {
        std::thread::Builder::new()
            .name("stdio reaper".to_string())
            .spawn(move || run(&receiver))
            .map(drop)
    })
}

/// Fill `cell` once, with a sender whose receiver `spawn` hands to a new
/// thread. A failed spawn leaves `cell` empty, so a later start tries again.
fn start_once(
    cell: &OnceLock<mpsc::Sender<Job>>,
    spawn: impl FnOnce(mpsc::Receiver<Job>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if cell.get().is_some() {
        return Ok(());
    }
    let _starting = START.lock();
    if cell.get().is_some() {
        return Ok(());
    }
    let (sender, receiver) = mpsc::channel();
    spawn(receiver)?;
    let _ = cell.set(sender);
    Ok(())
}

/// Hand `tree` to the reaper; the receiver turns `Done` once it is ended.
/// Needs no runtime and never blocks.
pub(super) fn hand_over(tree: ChildTree) -> watch::Receiver<Reaped> {
    let (done, receiver) = watch::channel(Reaped::Pending);
    let job = Job { tree, done };
    let refused = match REAPER.get() {
        Some(sender) => sender.send(job).err().map(|mpsc::SendError(job)| job),
        None => Some(job),
    };
    if let Some(job) = refused {
        // A bug, not a runtime condition: `ensure_started` ran before the
        // spawn and the thread never exits. Drop the tree (its Drop sends the
        // gated group signal) and say so.
        error!("stdio reaper unavailable; a child tree was dropped unreaped");
        let _ = job.done.send(Reaped::Done(None));
        drop(job.tree);
    }
    receiver
}

fn run(receiver: &mpsc::Receiver<Job>) {
    let mut jobs: Vec<Job> = Vec::new();
    loop {
        if jobs.is_empty() {
            match receiver.recv() {
                Ok(job) => jobs.push(job),
                Err(mpsc::RecvError) => return,
            }
        }
        match receiver.recv_timeout(TICK) {
            Ok(job) => jobs.push(job),
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
        }
        jobs.extend(receiver.try_iter());
        let now = Instant::now();
        jobs.retain_mut(|job| step(job, now));
    }
}

/// One step of one job; `false` once it is done (the tree is then dropped).
fn step(job: &mut Job, now: Instant) -> bool {
    let stepped =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.tree.reap_step(now)));
    match stepped {
        Ok(Reap::Pending) => true,
        Ok(Reap::Done(status)) => {
            #[cfg(all(test, unix))]
            FINISHED.lock().push(job.tree.counts(status));
            let _ = job.done.send(Reaped::Done(status));
            false
        }
        Err(_) => {
            error!("stdio reaper step panicked; the tree is dropped");
            let _ = job.done.send(Reaped::Done(None));
            false
        }
    }
}

/// Test record of every tree the reaper finished: its signal counts and
/// status by leader pid, since the tree itself is dropped once done.
#[cfg(all(test, unix))]
pub(super) static FINISHED: parking_lot::Mutex<Vec<super::child_tree::Counts>> =
    parking_lot::const_mutex(Vec::new());

/// A transport's child tree and the reaps it started (MIK-7923, design P2).
/// Every hold of its lock is sync and spans no await. The tree leaves the slot
/// only for the reaper, so a retire can always reach a live tree: it is either
/// here or already being ended.
#[derive(Default)]
pub(super) struct ChildSlot {
    pub(super) tree: Option<ChildTree>,
    /// Set by a retire: a start that finishes later must not install its tree.
    pub(super) retired: bool,
    /// Every handover's receiver, pruned once finished. A later handover
    /// never replaces an earlier one, so a close waits for all of them.
    reaping: Vec<watch::Receiver<Reaped>>,
    /// The status the last finished reap recorded, for callers that read it
    /// after another path already ended the tree.
    last_status: Option<ExitStatus>,
}

impl ChildSlot {
    /// Take the tree, if any, and hand it to the reaper. Returns its receiver,
    /// which also joins `reaping`.
    pub(super) fn take_for_reaper(&mut self) -> Option<watch::Receiver<Reaped>> {
        let tree = self.tree.take()?;
        Some(self.track(tree))
    }

    /// Hand over a tree that never entered the slot (a refused start).
    pub(super) fn track(&mut self, tree: ChildTree) -> watch::Receiver<Reaped> {
        let receiver = hand_over(tree);
        self.reaping.push(receiver.clone());
        receiver
    }

    /// Clones of every reap still running, pruning finished ones and keeping
    /// the newest finished status.
    pub(super) fn outstanding(&mut self) -> Vec<watch::Receiver<Reaped>> {
        let mut last = self.last_status;
        self.reaping.retain(|receiver| match *receiver.borrow() {
            Reaped::Pending => true,
            Reaped::Done(status) => {
                last = status.or(last);
                false
            }
        });
        self.last_status = last;
        self.reaping.clone()
    }

    pub(super) fn last_status(&self) -> Option<ExitStatus> {
        self.last_status
    }
}

/// Wait, up to `deadline`, for every receiver to finish. Returns `mine`'s
/// status when it finished in time.
pub(super) async fn wait_reaped(
    all: Vec<watch::Receiver<Reaped>>,
    mine: Option<watch::Receiver<Reaped>>,
    deadline: tokio::time::Instant,
) -> Option<ExitStatus> {
    for mut receiver in all {
        let _ = tokio::time::timeout_at(
            deadline,
            receiver.wait_for(|state| matches!(state, Reaped::Done(_))),
        )
        .await;
    }
    mine.and_then(|receiver| match *receiver.borrow() {
        Reaped::Done(status) => status,
        Reaped::Pending => None,
    })
}

impl super::StdioTransport {
    /// Hand the tree over, if any, and wait (bounded, needing no particular
    /// runtime for the work itself) for every reap this slot started. Returns
    /// the handed tree's status, else the newest one an earlier reap recorded.
    pub(super) async fn end_tree(&self) -> Option<ExitStatus> {
        let (mine, all) = {
            let mut slot = self.child.lock();
            let mine = slot.take_for_reaper();
            (mine, slot.outstanding())
        };
        let deadline =
            tokio::time::Instant::now() + super::child_tree::REAP_DEADLINE + Duration::from_secs(1);
        let status = wait_reaped(all, mine, deadline).await;
        let mut slot = self.child.lock();
        let _ = slot.outstanding();
        status.or_else(|| slot.last_status())
    }

    /// Install a freshly spawned tree, unless a retire landed while the start
    /// ran: then the tree is ended, never installed (MIK-7923, design P5).
    ///
    /// # Errors
    ///
    /// `BackendNotFound` (pre-dispatch) when the transport was retired.
    pub(super) fn install_tree(&self, tree: ChildTree) -> crate::Result<()> {
        let mut slot = self.child.lock();
        if slot.retired {
            slot.track(tree);
            return Err(crate::Error::BackendNotFound(
                "stdio backend retired while it started".to_string(),
            ));
        }
        // A tree still in the slot goes to the reaper, never to its Drop.
        if let Some(old) = slot.tree.replace(tree) {
            slot.track(old);
        }
        Ok(())
    }

    /// Wait up to `limit` for the leader to exit, without reaping and without
    /// holding the slot across an await. An empty slot counts as exited.
    pub(super) async fn wait_exited_in_slot(&self, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            {
                let mut slot = self.child.lock();
                if slot.tree.as_mut().is_none_or(ChildTree::exited) {
                    return true;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// End this transport's tree now, synchronously and without a runtime
    /// (MIK-7923, design P5). Under one slot hold: mark it retired (a start
    /// finishing later installs nothing), mark it disconnected, trip the
    /// stdout-closed latch so waiting requests fail at once, and hand the tree
    /// to the reaper. Then cancel the per-start stdin-write token, so a write
    /// stuck on a reader outside the group ends, and drop pending requests.
    /// Nobody waits here; `close` waits for the reap.
    pub(super) fn retire_tree_now(&self) {
        {
            let mut slot = self.child.lock();
            slot.retired = true;
            self.connected
                .store(false, std::sync::atomic::Ordering::SeqCst);
            self.start.trip_eof();
            slot.take_for_reaper();
        }
        self.shutdown.lock().cancel();
        self.pending.clear();
    }
}

#[cfg(test)]
mod start_tests {
    use super::*;

    /// MIK-7923 T1-nothread: when the OS refuses the reaper thread, the start
    /// is refused (so `StdioTransport::start` spawns no child, since it calls
    /// `ensure_started` before the spawn) and nothing is cached: the next start
    /// tries again.
    #[test]
    fn a_refused_reaper_thread_fails_the_start_and_is_retried() {
        let cell = OnceLock::new();
        let refused = start_once(&cell, |_| Err(std::io::Error::other("no threads")));
        assert!(refused.is_err(), "a refused thread fails the start");
        assert!(cell.get().is_none(), "a failed start caches nothing");
        let started = start_once(&cell, |receiver| {
            drop(receiver);
            Ok(())
        });
        assert!(started.is_ok(), "the next start tries again");
        assert!(cell.get().is_some());
    }
}
