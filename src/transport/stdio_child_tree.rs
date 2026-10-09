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
    #[cfg(test)]
    pub(super) group_signals_sent: usize,
    #[cfg(all(test, unix))]
    pub(super) signals_refused: usize,
}

/// What the kernel says about the leader, without reaping it.
/// How long a tree handed to the reaper may take before it is dropped
/// unreaped (MIK-7923, design P3).
pub(super) const REAP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Test record of a finished tree (see the reaper's `FINISHED`).
#[cfg(test)]
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
        Self {
            wrapper,
            #[cfg(unix)]
            pid,
            signals_closed: false,
            status: None,
            reaping: None,
            #[cfg(test)]
            group_signals_sent: 0,
            #[cfg(all(test, unix))]
            signals_refused: 0,
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
        let (started, phase) = if let Some(state) = self.reaping {
            state
        } else {
            self.start_kill();
            let state = (now, Self::FIRST_REAP_PHASE);
            self.reaping = Some(state);
            state
        };
        let elapsed = now.saturating_duration_since(started);
        if elapsed >= REAP_DEADLINE {
            self.signals_closed = true;
            tracing::warn!(
                pid = self.wrapper.id(),
                "stdio child not reaped within its deadline; dropped unreaped"
            );
            return Reap::Done(None);
        }
        #[cfg(unix)]
        if phase == ReapPhase::Grace {
            if !self.exited() && elapsed < PRE_REAP_GRACE {
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
    #[cfg(test)]
    pub(super) fn counts(&self, status: Option<ExitStatus>) -> Counts {
        Counts {
            // Captured at spawn: tokio's `id()` is `None` once reaped.
            #[cfg(unix)]
            pid: self
                .pid
                .and_then(|pid| u32::try_from(pid.as_raw_nonzero().get()).ok()),
            #[cfg(not(unix))]
            pid: self.wrapper.id(),
            sent: self.group_signals_sent,
            #[cfg(unix)]
            refused: self.signals_refused,
            #[cfg(not(unix))]
            refused: 0,
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
