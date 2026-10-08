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
    /// reap. The pre-reap phase (A5) has its own latch.
    signals_closed: bool,
    /// The pre-reap phase ran to its probe (A5): at most one signal per
    /// phase. Set after the grace, so a cancelled grace retries the phase.
    #[cfg(unix)]
    pre_reap_done: bool,
    /// The leader's exit, from the single reap.
    status: Option<ExitStatus>,
    #[cfg(test)]
    pub(super) group_signals_sent: usize,
    #[cfg(all(test, unix))]
    pub(super) signals_refused: usize,
    #[cfg(test)]
    pub(super) after_close_before_wait: crate::test_pause::Slot,
    /// Test-only: inside the pre-reap phase, before its grace and latch.
    #[cfg(all(test, unix))]
    pub(super) in_pre_reap_grace: crate::test_pause::Slot,
}

/// What the kernel says about the leader, without reaping it.
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
            #[cfg(unix)]
            pre_reap_done: false,
            status: None,
            #[cfg(test)]
            group_signals_sent: 0,
            #[cfg(all(test, unix))]
            signals_refused: 0,
            #[cfg(test)]
            after_close_before_wait: crate::test_pause::Slot::default(),
            #[cfg(all(test, unix))]
            in_pre_reap_grace: crate::test_pause::Slot::default(),
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
    /// (Unix): close once, pre-reap once (A5), never after the reap.
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

    /// End the tree and reap the leader, once: the close signal, the pre-reap
    /// signal (Unix), then the signal gate closes BEFORE the wait is polled,
    /// so a cancelled or failed wait is never followed by another signal. The single reap is the
    /// wrapper's own `wait`, so tokio sees it. Idempotent; a failed wait may
    /// be retried, without a signal.
    pub(super) async fn finish(&mut self) -> Option<ExitStatus> {
        if self.status.is_some() {
            return self.status;
        }
        self.start_kill();
        #[cfg(unix)]
        self.pre_reap_signal().await;
        self.signals_closed = true;
        #[cfg(test)]
        self.after_close_before_wait.pause().await;
        if let Ok(status) = self.wrapper.wait().await {
            self.status = Some(status);
        }
        self.status
    }

    /// A5: one more group signal just before the reap, once the leader has
    /// exited. It catches a member forked after the close signal's snapshot
    /// of the group (a macOS window). Still ownership-checked: the unreaped
    /// leader holds the group id, so it cannot name a reused group.
    #[cfg(unix)]
    async fn pre_reap_signal(&mut self) {
        if self.pre_reap_done {
            return;
        }
        #[cfg(test)]
        self.in_pre_reap_grace.pause().await;
        wait_exited(self, PRE_REAP_GRACE).await;
        // Latched only now: a finish cancelled during the grace has not had
        // this phase, and a retried finish must still send it.
        self.pre_reap_done = true;
        if matches!(self.leader_state(), Leader::Running | Leader::Zombie) {
            self.send_group_signal();
        } else {
            #[cfg(test)]
            {
                self.signals_refused += 1;
            }
        }
    }

    /// The status the single reap recorded, if it has happened.
    pub(super) fn status(&self) -> Option<ExitStatus> {
        self.status
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

/// Wait up to `limit` for the leader to exit, without reaping it.
pub(super) async fn wait_exited(child: &mut ChildTree, limit: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if child.exited() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(all(test, unix))]
#[path = "stdio_child_tree_tests.rs"]
mod tests;
#[cfg(all(test, windows))]
#[path = "stdio_child_tree_windows_tests.rs"]
mod windows_tests;

impl Drop for ChildTree {
    /// The single kill owner on drop: a dropped transport, a slot replaced by
    /// a restart, or a retry all end the group here, before tokio reaps.
    fn drop(&mut self) {
        self.start_kill();
    }
}
