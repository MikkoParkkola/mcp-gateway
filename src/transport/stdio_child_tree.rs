// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One owner per start for a stdio backend's process tree (MIK-8080).
//!
//! Invariant (Unix): the group leader is reaped only after the last signal
//! sent to its group. A zombie leader keeps its pid and process-group id
//! reserved, so every `killpg` names our own group and never one the kernel
//! handed to an unrelated process after a reap. `ChildTree` is the only code
//! that signals or reaps; it is not a `ChildWrapper`, so no caller can reach
//! the wrapper's reaping `try_wait`/`wait` around it.
//!
//! Windows ends the Job object by its handle, so there is no id to reuse and
//! no ownership probe: the Job is always ended before the wait.

use std::process::ExitStatus;

use process_wrap::tokio::ChildWrapper;

pub(super) struct ChildTree {
    wrapper: Box<dyn ChildWrapper>,
    #[cfg(unix)]
    pid: Option<rustix::process::Pid>,
    /// Set once the close phase has signalled the group (or the leader proved
    /// gone): `start_kill` sends at most one, and nothing signals after the
    /// reap. The pre-reap phase (A5) repeats while the group settles
    /// (MIK-8213), then closes the gate for good.
    signals_closed: bool,
    /// The leader's exit, from the single reap.
    status: Option<ExitStatus>,
    /// When the reaper first stepped this tree, and how far it got (MIK-7923).
    reaping: Option<(std::time::Instant, ReapPhase)>,
    /// How the reaper ends this tree; consumed by its first step.
    ending: Ending,
    /// The exit wait before the kill, once a graceful ending has started.
    grace: Option<Grace>,
    /// The gateway's stop deadline, when its backend belongs to one: cuts the
    /// waits so the kill lands in time (see `StopDeadline`).
    stop_deadline: Option<std::sync::Arc<super::reaper::StopDeadline>>,
    /// The descendant sweep: everything still attached to this
    /// backend by parent pid dies with it. Taken by the one run, before the
    /// group kill.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    sweep: Option<super::sweep::Sweep>,
    /// The leader's pid, so a start-time read that failed at construction is
    /// retried at the first snapshot.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    sweep_root: Option<u32>,
    #[cfg(all(test, unix))]
    pub(super) term_signals_sent: usize,
    #[cfg(test)]
    pub(super) group_signals_sent: usize,
    #[cfg(all(test, unix))]
    pub(super) signals_refused: usize,
    /// Test-only: replaces `PRE_REAP_GRACE` for this tree, so a test can tell
    /// "the leader's exit ended the wait" from "the grace ran out" by outcome
    /// rather than by elapsed time (MIK-8222).
    #[cfg(all(test, unix))]
    pub(super) grace_for_test: Option<std::time::Duration>,
    /// Test-only: replaces [`REAP_DEADLINE`] for this tree, so a row that
    /// asserts the reaped status does not race the deadline on a loaded host
    /// (MIK-8360). The deadline's own behaviour is pinned with synthetic
    /// `Instant`s, not through this.
    #[cfg(test)]
    pub(super) reap_deadline_for_test: Option<std::time::Duration>,
    /// Test-only: while set, every step of this tree is `Pending` before it
    /// starts, so a row can hold one tree in the real reaper loop and watch
    /// the others finish around it, by event rather than by stopwatch
    /// (MIK-8360).
    #[cfg(test)]
    pub(super) hold_for_test: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// How a tree handed to the reaper is ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    /// The kill at once: a dead or unresponsive backend, a dropped transport.
    Now,
    /// The MCP stdio order first (spec 2025-06-18, Lifecycle > Shutdown >
    /// stdio): stdin is already closed; wait up to `eof` for the leader to
    /// exit, then SIGTERM the group (Unix) and wait up to `term`, then the
    /// kill. A leader that exits in either wait goes straight to the kill,
    /// which sweeps what is left of its group.
    Graceful {
        eof: std::time::Duration,
        term: std::time::Duration,
    },
}

impl Ending {
    /// The longest the waits before the kill can take.
    pub(super) fn waits(self) -> std::time::Duration {
        match self {
            Self::Now => std::time::Duration::ZERO,
            Self::Graceful { eof, term } => eof + term,
        }
    }
}

/// The waits of a graceful ending, as instants from its first step.
#[derive(Debug, Clone, Copy)]
struct Grace {
    term_at: std::time::Instant,
    kill_at: std::time::Instant,
    /// When SIGTERM went out; Windows has no SIGTERM step.
    #[cfg(unix)]
    term_sent_at: Option<std::time::Instant>,
    /// The plan's SIGTERM came due before a cut was made: still owed, though the
    /// cut left less than the minimum phase.
    #[cfg(unix)]
    term_owed: bool,
}

/// What the kernel says about the leader, without reaping it.
/// How long a tree handed to the reaper may take before it is dropped
/// unreaped (MIK-7923, design P3).
pub(super) const REAP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Test record of a finished tree (see the reaper's `FINISHED`). Unix-only,
/// like the only tests that read it.
#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy)]
pub(super) struct Counts {
    pub(super) pid: Option<u32>,
    pub(super) sent: usize,
    pub(super) refused: usize,
    pub(super) status: Option<ExitStatus>,
}

/// One [`ChildTree::reap_step`]: still working, or finished with the leader's
/// status (`None` when the deadline passed unreaped).
pub(super) enum Reap {
    Pending,
    Done(Option<ExitStatus>),
}

/// Where a stepped tree is in the reap order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapPhase {
    /// Unix: the close signal is sent; waiting up to `PRE_REAP_GRACE` for the
    /// leader to exit before the A5 signal. Windows starts at `Reaping`.
    #[cfg_attr(not(unix), allow(dead_code))]
    Grace,
    /// Unix (MIK-8213): the leader has exited; the group is signalled again
    /// on every step until `PRE_REAP_SETTLE` after `since`, catching a member
    /// whose fork completed after an earlier signal's snapshot of the group.
    #[cfg_attr(not(unix), allow(dead_code))]
    Settle { since: std::time::Instant },
    /// The signal gate is closed; reaping the leader.
    Reaping,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Leader {
    Running,
    /// Exited but not reaped: its pid and group id are still ours.
    Zombie,
    /// Reaped (ECHILD): its ids may belong to someone else now.
    Gone,
    /// The probe failed some other way: ownership cannot be shown.
    Unproven,
}

#[cfg(unix)]
impl Leader {
    /// One `waitid(.., NOWAIT)` result (`Ok(exited)`) as a state; `None`
    /// means interrupted, so probe again.
    fn from_probe(probe: Result<bool, rustix::io::Errno>) -> Option<Self> {
        match probe {
            Ok(false) => Some(Self::Running),
            Ok(true) => Some(Self::Zombie),
            Err(rustix::io::Errno::CHILD) => Some(Self::Gone),
            Err(rustix::io::Errno::INTR) => None,
            Err(_) => Some(Self::Unproven),
        }
    }
}

impl ChildTree {
    pub(super) fn new(wrapper: Box<dyn ChildWrapper>) -> Self {
        #[cfg(unix)]
        let pid = wrapper
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let wrapper_pid = wrapper.id();
        Self {
            wrapper,
            #[cfg(unix)]
            pid,
            signals_closed: false,
            status: None,
            reaping: None,
            ending: Ending::Now,
            grace: None,
            stop_deadline: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            sweep: wrapper_pid
                .and_then(super::sweep::PlatformTable::identity_of)
                .map(|root| super::sweep::Sweep::new(root, super::sweep::config())),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            sweep_root: wrapper_pid,
            #[cfg(all(test, unix))]
            term_signals_sent: 0,
            #[cfg(test)]
            group_signals_sent: 0,
            #[cfg(all(test, unix))]
            signals_refused: 0,
            #[cfg(all(test, unix))]
            grace_for_test: None,
            #[cfg(test)]
            reap_deadline_for_test: None,
            #[cfg(test)]
            hold_for_test: None,
        }
    }

    /// The leader's state, by `waitid(.., NOWAIT)`: never reaps. Once the
    /// leader is reaped here the pid is not probed again, since it may have
    /// been reused.
    #[cfg(unix)]
    pub(super) fn leader_state(&self) -> Leader {
        use rustix::process::{WaitId, WaitIdOptions, waitid};
        if self.status.is_some() {
            return Leader::Gone;
        }
        let Some(pid) = self.pid else {
            return Leader::Unproven;
        };
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        loop {
            let probe = waitid(WaitId::Pid(pid), options).map(|exited| exited.is_some());
            if let Some(state) = Leader::from_probe(probe) {
                return state;
            }
        }
    }

    /// Whether the leader has exited. Never reaps on Unix; an unproven probe
    /// reads as running, so the caller's own connected flag decides.
    pub(super) fn exited(&mut self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.leader_state(), Leader::Zombie | Leader::Gone)
        }
        #[cfg(not(unix))]
        {
            self.status.is_some() || matches!(self.wrapper.try_wait(), Ok(Some(_)))
        }
    }

    /// The only place a group signal is sent, always after an ownership check
    /// (Unix): the close signal, then the pre-reap signal (A5) repeated while
    /// the group settles, never after the reap.
    fn send_group_signal(&mut self) {
        let _ = self.wrapper.start_kill();
        self.signals_closed = true;
        #[cfg(test)]
        {
            self.group_signals_sent += 1;
        }
    }

    /// Signal the group if it is provably ours (Unix), or end the Job
    /// (Windows). A leak is preferred to signalling a group we cannot show
    /// is ours.
    pub(super) fn start_kill(&mut self) {
        if self.signals_closed {
            return;
        }
        #[cfg(unix)]
        match self.leader_state() {
            Leader::Running | Leader::Zombie => self.send_group_signal(),
            Leader::Gone => {
                self.signals_closed = true;
                #[cfg(test)]
                {
                    self.signals_refused += 1;
                }
            }
            Leader::Unproven => {}
        }
        #[cfg(not(unix))]
        self.send_group_signal();
    }

    /// Choose how the reaper ends this tree, and the gateway stop deadline
    /// that may cut it short; set before the handover.
    pub(super) fn set_ending(
        &mut self,
        ending: Ending,
        stop_deadline: Option<std::sync::Arc<super::reaper::StopDeadline>>,
    ) {
        self.ending = ending;
        self.stop_deadline = stop_deadline;
    }

    /// The gateway stop deadline this tree's graceful ending runs under, if
    /// it has both.
    pub(super) fn graceful_deadline(&self) -> Option<std::sync::Arc<super::reaper::StopDeadline>> {
        match self.ending {
            Ending::Graceful { .. } => self.stop_deadline.clone(),
            Ending::Now => None,
        }
    }

    /// Record this tree's descendants now: called before the first signal of a
    /// stop (including the stdin close) and on every reaper step before the
    /// group kill. A start-time read that failed at construction is retried.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn sweep_snapshot(&mut self) {
        if self.sweep.is_none()
            && !self.signals_closed
            && let Some(root) = self
                .sweep_root
                .and_then(super::sweep::PlatformTable::identity_of)
        {
            self.sweep = Some(super::sweep::Sweep::new(root, super::sweep::config()));
        }
        if let Some(sweep) = self.sweep.as_mut() {
            sweep.snapshot(&mut super::sweep::PlatformTable::new());
        }
    }

    /// No descendant sweep on this platform.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[allow(clippy::unused_self)]
    pub(super) fn sweep_snapshot(&mut self) {}

    /// Freeze, verify and kill every descendant, once, before the group kill.
    /// Residuals are logged as a count and pids only: never a command line.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn sweep_descendants(&mut self) {
        let Some(mut sweep) = self.sweep.take() else {
            tracing::warn!(
                backend = self.wrapper.id(),
                "descendant sweep not run: the backend's start time could not be read"
            );
            return;
        };
        let report = sweep.run(
            &mut super::sweep::PlatformTable::new(),
            super::sweep::process_budget(),
        );
        if !report.residual.is_empty()
            || report.incomplete_reads > 0
            || report.unconfirmed > 0
            || report.stuck_stopped > 0
            || report.rescued > 0
            || report.stop_mismatch > 0
        {
            tracing::warn!(
                backend = self.wrapper.id(),
                residual = report.residual.len(),
                unreadable = report.unknown,
                unconfirmed_stopped = report.unconfirmed,
                stuck_stopped = report.stuck_stopped,
                rescued = report.rescued,
                stop_mismatch = report.stop_mismatch,
                incomplete_reads = report.incomplete_reads,
                killed = report.killed.len(),
                continued = report.continued.len(),
                passes = report.passes,
                pids = ?report.residual.iter().map(|who| who.pid).collect::<Vec<_>>(),
                "descendant sweep could not confirm every descendant gone (process table errors counted as unreadable)"
            );
        }
    }

    /// SIGTERM to the group, under the same ownership check as every other
    /// group signal (Unix). `false` when ownership could not be shown this
    /// step, so the caller tries again; an exited leader needs no SIGTERM.
    #[cfg(unix)]
    fn send_group_term(&mut self) -> bool {
        if self.signals_closed {
            return true;
        }
        match (self.leader_state(), self.pid) {
            (Leader::Running, Some(pid)) => {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
                #[cfg(test)]
                {
                    self.term_signals_sent += 1;
                }
                true
            }
            (Leader::Zombie | Leader::Gone, _) => true,
            (Leader::Running | Leader::Unproven, _) => false,
        }
    }

    /// One step of a graceful ending's waits; `true` while it still waits.
    /// Ends (and the kill follows) once the leader exits or `kill_at` passes.
    fn in_grace(&mut self, now: std::time::Instant) -> bool {
        let grace = match (self.grace.take(), self.ending) {
            (Some(grace), _) => grace,
            (None, Ending::Graceful { eof, term }) => Grace {
                term_at: now + eof,
                kill_at: now + eof + term,
                #[cfg(unix)]
                term_sent_at: None,
                #[cfg(unix)]
                term_owed: false,
            },
            (None, Ending::Now) => return false,
        };
        self.ending = Ending::Now;
        // Read on every step: a gateway stop that began after this tree's
        // handover still cuts its waits, so its kill lands before the stop's
        // deadline with the reap's own reserve left.
        let mut grace = grace;
        if let Some(deadline) = self.stop_deadline.as_ref()
            && let Some((cut, set_at)) = deadline.get_with_set_at()
        {
            let cut = cut.checked_sub(super::reaper::KILL_RESERVE).unwrap_or(now);
            if cut < grace.kill_at {
                // A SIGTERM the plan had due before this cut was made is owed,
                // however little the cut leaves: the reaper missed it, not the stop.
                #[cfg(unix)]
                if mutant!("s9509.m5", false, grace.term_sent_at.is_none()
                    && grace.term_at < grace.kill_at
                    && grace.term_at <= mutant!("s9509.m6", now, set_at))
                {
                    grace.term_owed = true;
                }
                #[cfg(not(unix))]
                let _ = set_at;
                // What is left is split as the plan was: its last third after
                // SIGTERM, unless that third is under the minimum phase.
                // A hurry preserves the minimum phase while it still fits.
                grace.kill_at = cut;
                let term = deadline.term_phase(cut.saturating_duration_since(now));
                grace.term_at = if term < super::reaper::MIN_PHASE {
                    // Too little left to use a SIGTERM wait: none is sent,
                    // even if the uncut plan had one due sooner.
                    cut
                } else {
                    grace.term_at.min(cut.checked_sub(term).unwrap_or(now))
                };
            }
        }
        if self.exited() {
            return false;
        }
        #[cfg(unix)]
        let kill_due = self.step_term(&mut grace, now);
        #[cfg(not(unix))]
        let kill_due = grace.kill_at;
        if now >= kill_due {
            tracing::warn!(
                pid = self.wrapper.id(),
                "stdio backend did not exit within its stop budget; killing its group"
            );
            return false;
        }
        self.grace = Some(grace);
        true
    }

    /// The SIGTERM step of a graceful ending, and the instant its kill is due.
    /// A due SIGTERM goes out on the first step that sees it, late or not, while
    /// its minimum phase still fits before `kill_at` plus the reserve's slack past
    /// the reap deadline; the kill then waits that phase, so a reaper woken late
    /// never kills a backend without the SIGTERM its plan gave it. Past that
    /// slack the stop's deadline wins: no SIGTERM, the kill at once.
    #[cfg(unix)]
    fn step_term(&mut self, grace: &mut Grace, now: std::time::Instant) -> std::time::Instant {
        use super::reaper::{KILL_RESERVE, MIN_PHASE};
        const _: () =
            assert!(KILL_RESERVE.as_nanos() >= REAP_DEADLINE.as_nanos() + MIN_PHASE.as_nanos());
        let slack_end = grace.kill_at + KILL_RESERVE.saturating_sub(REAP_DEADLINE);
        let planned = mutant!("s9509.m7", true, grace.term_at < grace.kill_at || grace.term_owed);
        let due = grace.term_owed || now >= grace.term_at;
        let fits = now < grace.kill_at
            || mutant!("s9509.m1", false, mutant!("s9509.m3", now + MIN_PHASE < slack_end, now + MIN_PHASE <= slack_end));
        if planned && due && fits && grace.term_sent_at.is_none() && self.send_group_term() {
            grace.term_sent_at = Some(now);
            if now >= grace.kill_at {
                tracing::warn!(
                    pid = self.wrapper.id(),
                    late_ms = now.saturating_duration_since(grace.kill_at).as_millis(),
                    "stdio backend's SIGTERM came due while the reaper ran late; sent it before the kill"
                );
            } else {
                tracing::warn!(
                    pid = self.wrapper.id(),
                    "stdio backend did not exit after its stdin closed; sent SIGTERM"
                );
            }
        }
        grace.term_sent_at.map_or(grace.kill_at, |sent| {
            mutant!("s9509.m4", (sent + MIN_PHASE).max(grace.kill_at), mutant!("s9509.m2", grace.kill_at.min(slack_end), (sent + MIN_PHASE).max(grace.kill_at).min(slack_end)))
        })
    }

    /// End the tree and reap the leader, one non-blocking step at a time, for
    /// the reaper thread
    /// (MIK-7923, design P3): it needs no runtime, never sleeps and never
    /// awaits. Order (MIK-8080): the close signal on the first step,
    /// then (Unix) up to `PRE_REAP_GRACE` for the leader to exit, the A5
    /// signal, the gate closed, then the reap. Past [`REAP_DEADLINE`] it
    /// gives up unreaped, with the gate closed, and the caller drops the tree.
    pub(super) fn reap_step(&mut self, now: std::time::Instant) -> Reap {
        if let Some(status) = self.status {
            return Reap::Done(Some(status));
        }
        #[cfg(test)]
        if self
            .hold_for_test
            .as_ref()
            .is_some_and(|held| held.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Reap::Pending;
        }
        // Before the first signal, and on every step while the waits run: the
        // sweep's picture of the tree is taken while the backend still holds it.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.reaping.is_none() {
            self.sweep_snapshot();
        }
        if self.reaping.is_none() && self.in_grace(now) {
            return Reap::Pending;
        }
        let (started, phase) = if let Some(state) = self.reaping {
            state
        } else {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            self.sweep_descendants();
            self.start_kill();
            let state = (now, Self::FIRST_REAP_PHASE);
            self.reaping = Some(state);
            state
        };
        let elapsed = now.saturating_duration_since(started);
        #[cfg(test)]
        let deadline = self.reap_deadline_for_test.unwrap_or(REAP_DEADLINE);
        #[cfg(not(test))]
        let deadline = REAP_DEADLINE;
        if elapsed >= deadline {
            self.signals_closed = true;
            tracing::warn!(
                pid = self.wrapper.id(),
                "stdio child not reaped within its deadline; dropped unreaped"
            );
            return Reap::Done(None);
        }
        #[cfg(all(test, unix))]
        let grace = self.grace_for_test.unwrap_or(PRE_REAP_GRACE);
        #[cfg(all(not(test), unix))]
        let grace = PRE_REAP_GRACE;
        #[cfg(unix)]
        if phase == ReapPhase::Grace {
            if !self.exited() && elapsed < grace {
                return Reap::Pending;
            }
            self.reaping = Some((started, ReapPhase::Settle { since: now }));
        }
        // A5, repeated until the group settles (MIK-8080, MIK-8213): a group
        // signal on every step for `PRE_REAP_SETTLE` after the leader exits.
        // One signal is not enough on macOS: a fork already under way when a
        // signal lands can complete after that signal's snapshot, and its
        // child is in the group but in no snapshot so far. Each signal is
        // ownership-checked: the unreaped leader holds the group id, so it
        // cannot name a reused group. A refusal closes the gate at once.
        #[cfg(unix)]
        if let Some((_, ReapPhase::Settle { since })) = self.reaping {
            if matches!(self.leader_state(), Leader::Running | Leader::Zombie) {
                self.send_group_signal();
                if now.saturating_duration_since(since) < PRE_REAP_SETTLE {
                    return Reap::Pending;
                }
            } else {
                #[cfg(test)]
                {
                    self.signals_refused += 1;
                }
            }
            self.signals_closed = true;
            self.reaping = Some((started, ReapPhase::Reaping));
        }
        #[cfg(not(unix))]
        let _ = phase;
        match self.try_reap() {
            Some(status) => {
                self.status = Some(status);
                Reap::Done(Some(status))
            }
            None => Reap::Pending,
        }
    }

    /// This tree's signal counts and `status`, for the test record.
    #[cfg(all(test, unix))]
    pub(super) fn counts(&self, status: Option<ExitStatus>) -> Counts {
        Counts {
            // Captured at spawn: tokio's `id()` is `None` once reaped.
            pid: self
                .pid
                .and_then(|pid| u32::try_from(pid.as_raw_nonzero().get()).ok()),
            sent: self.group_signals_sent,
            refused: self.signals_refused,
            status,
        }
    }

    #[cfg(unix)]
    const FIRST_REAP_PHASE: ReapPhase = ReapPhase::Grace;
    #[cfg(not(unix))]
    const FIRST_REAP_PHASE: ReapPhase = ReapPhase::Reaping;

    /// The leader's status if it can be reaped now, without blocking.
    ///
    /// Unix reaps through the NATIVE tokio child, never the wrapper:
    /// process-wrap's `ProcessGroupChild::try_wait` reaps with a raw group
    /// `waitpid` first, so tokio would not record the exit and its
    /// `kill_on_drop` would stay armed against a pid the kernel may reuse.
    /// Windows has no pid to reuse and keeps the Job wrapper's own `try_wait`,
    /// matching what the release line's async reap observed there.
    fn try_reap(&mut self) -> Option<ExitStatus> {
        #[cfg(unix)]
        {
            native_child(&mut *self.wrapper).and_then(|child| child.try_wait().ok().flatten())
        }
        #[cfg(not(unix))]
        {
            self.wrapper.try_wait().ok().flatten()
        }
    }

    /// Test-only: reap through the raw wrapper, behind the tree's back, as a
    /// regression that bypassed it would.
    #[cfg(all(test, unix))]
    pub(super) async fn reap_bypassing_tree(&mut self) {
        let _ = self.wrapper.wait().await;
    }

    #[cfg(all(test, unix))]
    pub(super) fn pid(&self) -> Option<u32> {
        self.wrapper.id()
    }
}

/// How long the pre-reap signal waits for a killed leader to exit.
#[cfg(unix)]
const PRE_REAP_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// How long, after the leader exits, the group keeps being signalled before
/// the gate closes and the leader is reaped (MIK-8213).
#[cfg(unix)]
const PRE_REAP_SETTLE: std::time::Duration = std::time::Duration::from_millis(50);

/// Slack added to the nested gateway's worst case below, for a kill or a reap
/// that lands late on a busy host.
#[cfg(unix)]
const NESTED_TERM_MARGIN: std::time::Duration = std::time::Duration::from_millis(150);

/// What a nested gateway needs after the SIGTERM that tells it to hurry: its
/// hurried backend waits ([`super::reaper::HURRY_WINDOW`]), then the reap's
/// grace for a killed leader and its settle, plus a margin. An outer stop gives
/// its SIGTERM wait at least this much when its waits can afford it, so the
/// inner's own kill lands before the outer's. Derived here, beside the reap
/// constants it depends on, so changing them moves it.
#[cfg(unix)]
pub(super) const NESTED_TERM_NEED: std::time::Duration = super::reaper::HURRY_WINDOW
    .saturating_add(PRE_REAP_GRACE)
    .saturating_add(PRE_REAP_SETTLE)
    .saturating_add(NESTED_TERM_MARGIN);
/// Windows has no SIGTERM phase.
#[cfg(not(unix))]
pub(super) const NESTED_TERM_NEED: std::time::Duration = std::time::Duration::ZERO;

#[cfg(all(test, unix))]
#[path = "stdio_child_tree_tests.rs"]
mod tests;
#[cfg(all(test, windows))]
#[path = "stdio_child_tree_windows_tests.rs"]
mod windows_tests;

impl Drop for ChildTree {
    /// The fallback kill, never the normal path: a dropped transport and a
    /// replaced slot hand their tree to the reaper (MIK-7923), so this runs
    /// for a tree the reaper finished (its gate already closed) or one it
    /// could not take. Gated like every other group signal.
    fn drop(&mut self) {
        self.start_kill();
    }
}

/// The native tokio child at the bottom of a wrapper chain: the same walk as
/// process-wrap's `try_inner_child_mut`, which is `unsafe` in its signature;
/// this crate is `#![deny(unsafe_code)]`. `None` when the chain ends in a
/// child that is not a tokio one.
#[cfg(unix)]
fn native_child(wrapper: &mut dyn ChildWrapper) -> Option<&mut tokio::process::Child> {
    let mut current = wrapper;
    loop {
        if (&*current as &dyn std::any::Any).is::<tokio::process::Child>() {
            return (current as &mut dyn std::any::Any).downcast_mut::<tokio::process::Child>();
        }
        let here = std::ptr::from_ref::<dyn ChildWrapper>(current).cast::<()>();
        let next = current.inner_mut();
        if std::ptr::eq(
            here,
            std::ptr::from_ref::<dyn ChildWrapper>(next).cast::<()>(),
        ) {
            return None;
        }
        current = next;
    }
}
