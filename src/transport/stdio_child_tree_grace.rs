// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The graceful phase of a tree's stop: the waits after EOF and after
//! SIGTERM, and when the SIGTERM goes out.

#[cfg(all(test, unix))]
use super::signal_log;
use super::{ChildTree, Ending, Grace};
#[cfg(unix)]
use super::{Leader, REAP_DEADLINE};

impl ChildTree {
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
                let sent = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
                #[cfg(test)]
                {
                    self.term_signals_sent += 1;
                    if sent.is_ok() {
                        signal_log::record(pid, signal_log::Sent::Term);
                    }
                }
                let _ = sent;
                true
            }
            (Leader::Zombie | Leader::Gone, _) => {
                #[cfg(test)]
                if let Some(pid) = self.pid {
                    signal_log::record(pid, signal_log::Sent::LeaderGone);
                }
                true
            }
            (Leader::Running | Leader::Unproven, _) => {
                #[cfg(test)]
                if let Some(pid) = self.pid {
                    signal_log::record(pid, signal_log::Sent::Unproven);
                }
                false
            }
        }
    }

    /// One step of a graceful ending's waits; `true` while it still waits.
    /// Ends (and the kill follows) once the leader exits or `kill_at` passes.
    pub(super) fn in_grace(&mut self, now: std::time::Instant) -> bool {
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
            let cut = cut
                .checked_sub(super::super::reaper::KILL_RESERVE)
                .unwrap_or(now);
            if cut < grace.kill_at {
                // A SIGTERM the plan had due before this cut was made is owed,
                // however little the cut leaves: the reaper missed it, not the stop.
                #[cfg(unix)]
                if grace.term_sent_at.is_none()
                    && grace.term_at < grace.kill_at
                    && grace.term_at <= set_at
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
                grace.term_at = if term < super::super::reaper::MIN_PHASE {
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
        use super::super::reaper::{KILL_RESERVE, MIN_PHASE};
        // What the stop keeps past the reap deadline: the kill may move this far.
        const SLACK: std::time::Duration = KILL_RESERVE.saturating_sub(REAP_DEADLINE);
        // Block form: a bare `assert!` here, inside a fn body, trips
        // semicolon_in_expressions_from_non_local_macros under Kani's toolchain.
        const _: () = {
            assert!(SLACK.as_nanos() >= MIN_PHASE.as_nanos());
        };
        let slack_end = grace.kill_at + SLACK;
        let planned = grace.term_at < grace.kill_at || grace.term_owed;
        let due = grace.term_owed || now >= grace.term_at;
        let fits = now < grace.kill_at || now + MIN_PHASE <= slack_end;
        #[cfg(test)]
        if planned
            && due
            && !fits
            && grace.term_sent_at.is_none()
            && let Some(pid) = self.pid
        {
            let late = now.saturating_duration_since(grace.kill_at);
            signal_log::record(pid, signal_log::Sent::SkipLate { late });
        }
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
            (sent + MIN_PHASE).max(grace.kill_at).min(slack_end)
        })
    }
}
