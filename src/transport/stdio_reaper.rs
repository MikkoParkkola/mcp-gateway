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

use super::child_tree::{ChildTree, Ending, NESTED_TERM_NEED, REAP_DEADLINE, Reap};

/// What a stop leaves a backend's tree after its stdin closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopKind {
    /// A backend that may still save on its way out: the MCP stdio order,
    /// within the caller's stop deadline.
    Graceful,
    /// A backend judged dead or unresponsive (a failed start or handshake):
    /// the kill at once.
    Dead,
}

/// What a graceful stop keeps back for the kill and the reap after its
/// waits: the reap deadline, plus the margin the close waits beyond it.
pub(crate) const KILL_RESERVE: Duration = Duration::from_secs(REAP_DEADLINE.as_secs() + 1);

/// After a hurry, backends get SIGTERM about 100 ms before their kill, so a
/// nested gateway still sees SIGTERM and can hurry its own backends.
pub(crate) const HURRY_WINDOW: Duration = Duration::from_millis(300);

/// A close with no stop deadline from its caller gets this budget.
const DEFAULT_STOP_BUDGET: Duration = Duration::from_secs(10);

/// A wait shorter than this is skipped rather than sent for nothing.
pub(super) const MIN_PHASE: Duration = Duration::from_millis(100);

tokio::task_local! {
    /// The deadline by which the caller's stop must be over, waits included.
    static STOP_DEADLINE: tokio::time::Instant;
}

/// Run `stop` (a transport's close) under the caller's stop deadline: a
/// graceful stop splits what is left of it into its waits and the kill, so
/// it ends by then.
/// A plain function, not an `async fn`: an `async fn` would hold `stop` twice
/// (the argument beside the task-local future that owns it).
pub(crate) fn within_stop_deadline<F: std::future::Future>(
    deadline: tokio::time::Instant,
    stop: F,
) -> impl std::future::Future<Output = F::Output> {
    STOP_DEADLINE.scope(deadline, stop)
}

/// A gateway's stop deadline, shared with every tree its backends hand over,
/// so a tree already in its exit waits when the gateway stop begins is cut to
/// end by then too. Unset until the stop; after that it only moves earlier.
#[derive(Debug)]
pub(crate) struct StopDeadline {
    /// Keep a useful SIGTERM phase even after hurry setup consumes a few ms.
    hurried: std::sync::atomic::AtomicBool,
    /// Nanoseconds after [`STOP_EPOCH`]; `u64::MAX` while unset.
    at: std::sync::atomic::AtomicU64,
    /// Every graceful handover under this deadline, so the stop can wait for
    /// their kills before it returns; finished ones are pruned on each add.
    handed: parking_lot::Mutex<Vec<watch::Receiver<Reaped>>>,
}

/// The fixed origin [`StopDeadline`] counts from.
static STOP_EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

impl Default for StopDeadline {
    fn default() -> Self {
        Self {
            hurried: std::sync::atomic::AtomicBool::new(false),
            at: std::sync::atomic::AtomicU64::new(u64::MAX),
            handed: parking_lot::Mutex::default(),
        }
    }
}

impl StopDeadline {
    /// Whether a signal has shortened this stop's graceful waits.
    pub(crate) fn is_hurried(&self) -> bool {
        self.hurried.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Shorten the stop while reserving a minimum SIGTERM phase when it fits.
    pub(crate) fn hurry(&self, now: Instant) -> Instant {
        self.hurried
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let target = now + KILL_RESERVE + HURRY_WINDOW;
        self.move_earlier(target);
        self.get().unwrap_or(target)
    }

    /// Ordinary stops keep their last third; a hurry keeps at least the
    /// minimum phase if it fits, without moving the kill later.
    pub(super) fn term_phase(&self, waits: Duration) -> Duration {
        if self.hurried.load(std::sync::atomic::Ordering::SeqCst) && waits >= MIN_PHASE {
            (waits / 3).max(MIN_PHASE)
        } else {
            waits / 3
        }
    }

    /// Set the deadline, or move it earlier; a later one changes nothing, so
    /// a second stop can shorten a first one's waits, never extend them.
    pub(crate) fn move_earlier(&self, deadline: Instant) {
        let nanos = deadline.saturating_duration_since(*STOP_EPOCH).as_nanos();
        let nanos = u64::try_from(nanos).unwrap_or(u64::MAX - 1);
        self.at
            .fetch_min(nanos, std::sync::atomic::Ordering::SeqCst);
    }

    /// Track a graceful handover, so [`Self::wait_handed`] covers it.
    pub(super) fn track(&self, handed: watch::Receiver<Reaped>) {
        let mut all = self.handed.lock();
        all.retain(|receiver| *receiver.borrow() == Reaped::Pending);
        all.push(handed);
    }

    /// How many handovers are tracked, finished or not.
    #[cfg(all(test, unix))]
    pub(crate) fn handed_len(&self) -> usize {
        self.handed.lock().len()
    }

    /// Wait, up to `deadline`, for every tracked handover to be ended: a tree
    /// an earlier close handed over may still be in its waits, and its kill
    /// must land before the gateway returns.
    pub(crate) async fn wait_handed(&self, deadline: tokio::time::Instant) {
        let all = self.handed.lock().clone();
        wait_reaped(all, None, deadline).await;
    }

    /// The deadline, once set.
    pub(crate) fn get(&self) -> Option<Instant> {
        match self.at.load(std::sync::atomic::Ordering::SeqCst) {
            u64::MAX => None,
            nanos => Some(*STOP_EPOCH + Duration::from_nanos(nanos)),
        }
    }
}

/// What a backend does to a live stdio transport's tree without a runtime,
/// through a trait object so the backend's types stay shallow.
pub(crate) trait LiveTree: Send + Sync {
    /// End the tree at once (a dead backend, a revocation).
    fn kill_now(&self);
    /// Hand the tree to the reaper with the graceful order fitted to `budget`.
    fn hand_over_gracefully(&self, budget: Duration);
}

impl LiveTree for super::StdioTransport {
    fn kill_now(&self) {
        self.retire_tree_now();
    }

    fn hand_over_gracefully(&self, budget: Duration) {
        self.hand_over_gracefully_now(budget);
    }
}

/// The caller's stop deadline, when this runs inside [`within_stop_deadline`].
pub(crate) fn stop_deadline() -> Option<tokio::time::Instant> {
    STOP_DEADLINE.try_with(|deadline| *deadline).ok()
}

/// The graceful ending that fits `budget`: [`KILL_RESERVE`] is kept for the
/// kill, a third of the rest goes to the wait after SIGTERM and the remainder
/// to the wait after EOF. Stdin that could not be closed (a writer holds it)
/// gets no EOF wait, since the child never saw EOF. Windows has no SIGTERM.
/// A hurried deadline keeps at least `MIN_PHASE` for SIGTERM when it fits. An
/// unhurried stop keeps at least `NESTED_TERM_NEED` for it (capped so EOF keeps
/// `MIN_PHASE`): a nested gateway only learns to hurry at the SIGTERM.
pub(super) fn graceful_ending(
    budget: Duration,
    stdin_closed: bool,
    deadline: Option<&StopDeadline>,
) -> Ending {
    let waits = budget.saturating_sub(KILL_RESERVE);
    let (eof, term) = match (cfg!(unix), stdin_closed) {
        (true, true) => {
            let term = deadline.map_or(waits / 3, |deadline| deadline.term_phase(waits));
            // An unhurried stop keeps a SIGTERM phase a nested gateway can hurry
            // inside, leaving the EOF wait at least the minimum phase.
            let term = if deadline.is_some_and(StopDeadline::is_hurried) {
                term
            } else {
                term.max(NESTED_TERM_NEED.min(waits.saturating_sub(MIN_PHASE)))
            };
            (waits.saturating_sub(term), term)
        }
        (true, false) => (Duration::ZERO, waits),
        (false, true) => (waits, Duration::ZERO),
        (false, false) => (Duration::ZERO, Duration::ZERO),
    };
    let kept = |wait: Duration| {
        if wait < MIN_PHASE {
            Duration::ZERO
        } else {
            wait
        }
    };
    match (kept(eof), kept(term)) {
        (Duration::ZERO, Duration::ZERO) => Ending::Now,
        (eof, term) => Ending::Graceful { eof, term },
    }
}

/// The budget left for a stop started now: the caller's deadline, else
/// [`DEFAULT_STOP_BUDGET`].
fn stop_budget() -> Duration {
    stop_deadline().map_or(DEFAULT_STOP_BUDGET, |deadline| {
        deadline.saturating_duration_since(tokio::time::Instant::now())
    })
}

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
static START: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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
    // A graceful handover joins its gateway stop deadline before its first
    // step, so no stop's snapshot can miss a tree already in its waits.
    if let Some(deadline) = tree.graceful_deadline() {
        deadline.track(receiver.clone());
    }
    let mut job = Job { tree, done };
    // The first step runs here, on the caller's thread, not on the reaper's:
    // for an `Ending::Now` tree it sends the ownership-checked group signal
    // now, so a gateway that exits right after dropping a transport has
    // already signalled the backend's group. A graceful ending only starts
    // its waits here; its caller waits for the reap. The reaper takes the
    // rest of the order.
    if !step(&mut job, Instant::now()) {
        return receiver;
    }
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
    parking_lot::Mutex::new(Vec::new());

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
    /// Close the child's stdin now, unless a write holds it: one stuck on a
    /// peer that stopped reading. SIGTERM or the kill ends that one, and the
    /// child never sees EOF. `true` when stdin was closed.
    fn close_stdin_now(&self) -> bool {
        match self.writer.try_lock() {
            Ok(mut writer) => {
                *writer = None;
                true
            }
            Err(_) => false,
        }
    }

    /// The handover of a graceful stop, synchronous and without a runtime:
    /// retire the slot (a start finishing later installs nothing), close
    /// stdin, and hand the tree to the reaper with the MCP stdio order
    /// planned to fit `budget`. A later `close` waits for that reap.
    fn hand_over_gracefully_now(&self, budget: Duration) {
        self.connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let ending = graceful_ending(
            budget,
            self.close_stdin_now(),
            self.stop_deadline.get().map(AsRef::as_ref),
        );
        {
            let mut slot = self.child.lock();
            slot.retired = true;
            self.start.trip_eof();
            if let Some(tree) = slot.tree.as_mut() {
                tree.set_ending(ending, self.stop_deadline.get().cloned());
            }
            let _ = slot.take_for_reaper();
        }
        self.shutdown.lock().cancel();
        self.pending.clear();
    }

    /// Join the gateway stop deadline of the backend that owns this
    /// transport; set once, before its first start.
    pub(crate) fn attach_stop_deadline(&self, deadline: std::sync::Arc<StopDeadline>) {
        let _ = self.stop_deadline.set(deadline);
    }

    /// The tree for a freshly spawned `child`, carrying this transport's
    /// test-only reap deadline (MIK-8360).
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(super) fn new_tree(&self, child: Box<dyn process_wrap::tokio::ChildWrapper>) -> ChildTree {
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut tree = ChildTree::new(child);
        #[cfg(test)]
        {
            tree.reap_deadline_for_test = *self.slow_host_bound.lock();
        }
        tree
    }

    /// How long a handed-over tree may take: [`REAP_DEADLINE`], or the
    /// test-only slow-host bound (MIK-8360), the value each tree this
    /// transport spawned also carries.
    ///
    /// [`REAP_DEADLINE`]: super::child_tree::REAP_DEADLINE
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn reap_deadline(&self) -> Duration {
        #[cfg(test)]
        if let Some(bound) = *self.slow_host_bound.lock() {
            return bound;
        }
        super::child_tree::REAP_DEADLINE
    }

    /// Hand the tree over, if any, and wait (bounded, needing no particular
    /// runtime for the work itself) for every reap this slot started. Returns
    /// the handed tree's status, else the newest one an earlier reap recorded.
    pub(super) async fn end_tree(&self) -> Option<ExitStatus> {
        self.end_tree_with(Ending::Now).await
    }

    /// [`Self::end_tree`], ending the handed tree as `ending` says; the wait
    /// covers its waits as well as the reap.
    async fn end_tree_with(&self, ending: Ending) -> Option<ExitStatus> {
        let (mine, all) = {
            let mut slot = self.child.lock();
            if let Some(tree) = slot.tree.as_mut() {
                tree.set_ending(ending, self.stop_deadline.get().cloned());
            }
            let mine = slot.take_for_reaper();
            (mine, slot.outstanding())
        };
        let deadline = tokio::time::Instant::now()
            + ending.waits()
            + self.reap_deadline()
            + Duration::from_secs(1);
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

    /// What `close` does, which cannot fail: the failed-start path calls it
    /// directly instead of handling an error `close` never returns.
    pub(super) async fn shut(&self, kind: StopKind) {
        self.connected
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let stdin_closed = self.close_stdin_now();
        // The per-start stdin token first, then the tree to the reaper,
        // waited for (bounded) with any reap a retire started earlier. No
        // await comes before the handover, so a cancelled close cannot leave
        // the tree unended.
        self.shutdown.lock().cancel();
        let ending = match kind {
            StopKind::Graceful => graceful_ending(
                stop_budget(),
                stdin_closed,
                self.stop_deadline.get().map(AsRef::as_ref),
            ),
            StopKind::Dead => Ending::Now,
        };
        self.end_tree_with(ending).await;
        super::tree::clear_writer(&self.writer).await;
    }

    /// Test seam (MIK-7923 coverage): a retire that lands in `start` between
    /// the spawn and the install, as one from another thread can. Fires only
    /// for the transport armed by [`Self::retire_after_spawn_for_test`].
    #[cfg(all(test, unix))]
    pub(super) fn after_spawn_for_test(&self) {
        let mut armed = RETIRE_AFTER_SPAWN.lock();
        if armed
            .as_ref()
            .is_some_and(|it| std::ptr::eq(it.as_ptr(), self))
        {
            *armed = None;
            drop(armed);
            self.retire_tree_now();
        }
    }

    #[cfg(all(test, unix))]
    pub(super) fn retire_after_spawn_for_test(self: &std::sync::Arc<Self>) {
        *RETIRE_AFTER_SPAWN.lock() = Some(std::sync::Arc::downgrade(self));
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

#[cfg(all(test, unix))]
static RETIRE_AFTER_SPAWN: parking_lot::Mutex<Option<std::sync::Weak<super::StdioTransport>>> =
    parking_lot::Mutex::new(None);

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

/// Every caller's stop budget yields a plan that fits it, by construction.
#[cfg(test)]
mod plan_tests {
    #[cfg(unix)]
    use super::super::child_tree::NESTED_TERM_NEED;
    use super::{DEFAULT_STOP_BUDGET, Ending, KILL_RESERVE, MIN_PHASE, graceful_ending};
    use std::time::Duration;

    fn total(ending: Ending) -> Duration {
        ending.waits() + KILL_RESERVE
    }

    /// One row per caller: a gateway shutdown at the default and at a short
    /// `shutdown_timeout`, eviction and restart (`close_stage`), a close with
    /// no caller budget, and a budget at the reserve.
    #[test]
    fn every_callers_plan_fits_its_budget() {
        let callers = [
            (
                "shutdown, default shutdown_timeout",
                Duration::from_secs(30),
            ),
            ("shutdown, short shutdown_timeout", Duration::from_secs(9)),
            ("eviction close_stage", Duration::from_secs(10)),
            ("restart close_stage", Duration::from_secs(10)),
            ("no caller budget", DEFAULT_STOP_BUDGET),
            ("at the reserve", KILL_RESERVE),
        ];
        for (caller, budget) in callers {
            for stdin_closed in [true, false] {
                let ending = graceful_ending(budget, stdin_closed, None);
                assert!(
                    ending == Ending::Now || total(ending) <= budget,
                    "{caller}: plan {ending:?} exceeds its budget {budget:?}"
                );
            }
        }
    }

    /// An unhurried stop with 3.65 s of waits (the window of the failed CI run) leaves SIGTERM at
    /// least what a nested gateway needs to hurry and kill inside the outer's cut:
    /// the inner only learns to hurry at the SIGTERM, so a third of the waits
    /// (1.22 s) was under its worst case.
    /// Red if the SIGTERM phase is back to a third of the waits.
    #[cfg(unix)]
    #[test]
    fn the_sigterm_phase_covers_a_nested_gateways_hurried_path() {
        let waits = Duration::from_millis(3_650);
        let Ending::Graceful { eof, term } = graceful_ending(KILL_RESERVE + waits, true, None)
        else {
            panic!("waits above the minimum phase give a graceful ending");
        };
        assert_eq!(
            term, NESTED_TERM_NEED,
            "the SIGTERM phase is the nested need"
        );
        assert_eq!(eof + term, waits, "the split spends exactly the waits");
    }

    /// The SIGTERM floor takes from the EOF wait, so the minimum total carries a
    /// window big enough that the EOF wait is no shorter than it was before the
    /// floor: a third-split of the previous 3.4 s window gave 2.27 s. At the
    /// minimum's window (4.4 s) EOF is 2.9 s and SIGTERM is the nested need; these
    /// are the numbers the upgrade note gives operators, so they are pinned exactly.
    /// Red if the floor or a growing reap constant erodes the EOF wait.
    #[cfg(unix)]
    #[test]
    fn the_eof_wait_at_the_minimum_is_no_shorter_than_before_the_floor() {
        let before = Duration::from_millis(3_400) * 2 / 3;
        let waits = Duration::from_millis(4_400);
        let Ending::Graceful { eof, term } = graceful_ending(KILL_RESERVE + waits, true, None)
        else {
            panic!("waits above the minimum phase give a graceful ending");
        };
        assert!(
            eof >= before,
            "EOF wait {eof:?} is under the old {before:?}"
        );
        assert_eq!(eof, Duration::from_millis(2_900), "EOF wait at the minimum");
        assert_eq!(term, NESTED_TERM_NEED, "SIGTERM wait is the nested need");
    }

    /// The floor is met whenever the waits can afford it, leaving EOF at least the
    /// minimum phase: 2 s of waits give SIGTERM the whole need and EOF the rest.
    /// Red if a cap (such as half the waits) cuts the floor short of what the waits afford.
    #[cfg(unix)]
    #[test]
    fn the_floor_is_met_whenever_the_waits_can_afford_it() {
        let waits = Duration::from_secs(2);
        assert_eq!(
            graceful_ending(KILL_RESERVE + waits, true, None),
            Ending::Graceful {
                eof: waits - NESTED_TERM_NEED,
                term: NESTED_TERM_NEED,
            }
        );
    }

    /// Small waits cannot afford the floor: SIGTERM takes all but the minimum
    /// phase, so the EOF wait is never starved to nothing.
    /// Red if the floor ignores the small budget or eats the last minimum phase.
    #[cfg(unix)]
    #[test]
    fn a_small_wait_keeps_the_minimum_phase_for_eof_even_under_the_floor() {
        let waits = Duration::from_secs(1);
        assert_eq!(
            graceful_ending(KILL_RESERVE + waits, true, None),
            Ending::Graceful {
                eof: MIN_PHASE,
                term: waits - MIN_PHASE,
            }
        );
    }

    /// Waits big enough that a third already covers the need are untouched.
    /// Red if the floor reshapes a long stop.
    #[cfg(unix)]
    #[test]
    fn a_long_wait_keeps_its_third_for_sigterm() {
        let waits = Duration::from_secs(9);
        assert_eq!(
            graceful_ending(KILL_RESERVE + waits, true, None),
            Ending::Graceful {
                eof: waits - waits / 3,
                term: waits / 3,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_split_keeps_the_reserve_and_gives_a_third_to_sigterm() {
        // 30 s less the reserve (the 5 s reap deadline and the close's 1 s
        // margin) leaves 24 s: a third of it after SIGTERM.
        let waits = Duration::from_secs(24);
        assert_eq!(
            graceful_ending(Duration::from_secs(30), true, None),
            Ending::Graceful {
                eof: waits
                    .checked_sub(waits / 3)
                    .expect("a third never exceeds the whole"),
                term: waits / 3,
            }
        );
        // Stdin a writer still holds: no EOF wait, SIGTERM at once.
        assert_eq!(
            graceful_ending(Duration::from_secs(10), false, None),
            Ending::Graceful {
                eof: Duration::ZERO,
                term: Duration::from_secs(4),
            }
        );
    }

    #[test]
    fn a_budget_at_or_under_the_reserve_kills_at_once() {
        assert_eq!(graceful_ending(KILL_RESERVE, true, None), Ending::Now);
        assert_eq!(graceful_ending(Duration::ZERO, true, None), Ending::Now);
        assert_eq!(
            graceful_ending(KILL_RESERVE + MIN_PHASE / 2, true, None),
            Ending::Now,
            "waits under the minimum phase are skipped"
        );
    }

    /// A close begun after the hurry preserves a useful term phase.
    /// Red if setup latency drops SIGTERM, extends the budget, or extends an earlier stop.
    #[cfg(unix)]
    #[test]
    fn a_hurried_close_keeps_term_after_setup_latency() {
        let deadline = super::StopDeadline::default();
        let now = std::time::Instant::now();
        let cut = deadline.hurry(now);
        let budget = cut.duration_since(now + Duration::from_millis(10));
        let ending = graceful_ending(budget, true, Some(&deadline));
        assert_eq!(
            ending,
            Ending::Graceful {
                eof: Duration::from_millis(190),
                term: MIN_PHASE,
            }
        );
        assert!(total(ending) <= budget);
        deadline.move_earlier(now + KILL_RESERVE);
        assert_eq!(deadline.hurry(now), now + KILL_RESERVE);
    }
}
