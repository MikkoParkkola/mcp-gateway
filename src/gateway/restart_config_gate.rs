// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config gate: one state word behind one mutex that every admission and
//! every state change takes, so a submission racing a change is admitted after
//! it or refused, never parked. Admitted work is counted in flight until its
//! guard drops; the settle wait observes that count without losing a wakeup.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use crate::gateway::restart_floor::FloorFault;

/// The gate's state word. `Paused` and `Certified` carry the attempt number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum GateState {
    #[default]
    Open,
    Paused(u64),
    Certified(u64),
    Terminal,
    Released,
}

/// Who asks the gate for admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmitKind {
    /// The byte writer, every UI write to the config file.
    Write,
    /// A manual reload: the UI route or the meta-tool.
    ManualReload,
    /// The watcher, before it takes its pending trigger.
    Watcher,
}

/// Why the gate refused. The caller maps it to its response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Paused or Certified: a UI write is refused, retry later.
    Busy,
    /// Paused or Certified: a manual reload folded into the owed replay.
    ReplayOwed,
    /// Terminal: "the gateway is restarting".
    Restarting,
    /// Released: "the gateway is stopping".
    Stopping,
}

#[derive(Debug, Default)]
pub(super) struct GateInner {
    pub(super) state: GateState,
    pub(super) in_flight: usize,
    pub(super) replay_owed: bool,
    /// Weak: a flag whose reload context is gone neither counts nor is kept.
    owed_flags: Vec<std::sync::Weak<AtomicBool>>,
}

/// One per gateway, shared by the byte writer, every reload context, the
/// watcher and the adapter. Cloning shares the same gate.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConfigGate {
    pub(super) inner: Arc<parking_lot::Mutex<GateInner>>,
    settled: Arc<Notify>,
    watcher: Arc<Notify>,
    #[cfg(test)]
    pub(super) seams: super::seams::GateSeams,
}

/// Counted in flight until dropped; cloning counts one more holder.
#[derive(Debug)]
pub(crate) struct AdmissionGuard {
    gate: ConfigGate,
}

impl Clone for AdmissionGuard {
    fn clone(&self) -> Self {
        self.gate.inner.lock().in_flight += 1;
        Self {
            gate: self.gate.clone(),
        }
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut inner = self.gate.inner.lock();
        inner.in_flight -= 1;
        if inner.in_flight == 0 {
            self.gate.settled.notify_waiters();
        }
    }
}

/// The refusal for `kind` in `state`, or `None` when it is admitted.
fn decide(state: GateState, kind: AdmitKind) -> Option<Refusal> {
    match (state, kind) {
        (GateState::Open, _) => None,
        (GateState::Paused(_) | GateState::Certified(_), AdmitKind::Write) => Some(Refusal::Busy),
        (GateState::Paused(_) | GateState::Certified(_), _) => Some(Refusal::ReplayOwed),
        (GateState::Terminal, _) => Some(Refusal::Restarting),
        (GateState::Released, _) => Some(Refusal::Stopping),
    }
}

impl ConfigGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Ask for admission; the guard is held for the whole operation. The state
    /// is read under the same mutex every state change takes.
    pub(crate) fn admit(&self, kind: AdmitKind) -> Result<AdmissionGuard, Refusal> {
        let mut inner = self.inner.lock();
        let refusal = decide(inner.state, kind);
        if refusal == Some(Refusal::ReplayOwed) && kind == AdmitKind::ManualReload {
            inner.replay_owed = true;
        }
        #[cfg(test)]
        self.seams
            .record_decision(inner.state, kind, refusal.is_none());
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        inner.in_flight += 1;
        Ok(AdmissionGuard { gate: self.clone() })
    }

    /// Wait until no admitted work is in flight. Enable-then-re-read: a signal
    /// between the count read and the await is never missed.
    pub(crate) async fn settle(&self) {
        loop {
            let notified = self.settled.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.lock().in_flight == 0 {
                return;
            }
            #[cfg(test)]
            self.seams.call_settle_window();
            if self.inner.lock().in_flight == 0 {
                return;
            }
            notified.await;
        }
    }

    /// A reload context or the watcher registers an owed-reload fault flag.
    pub(crate) fn register_owed(&self, flag: Arc<AtomicBool>) {
        let mut inner = self.inner.lock();
        inner.owed_flags.retain(|f| f.strong_count() > 0);
        inner.owed_flags.push(Arc::downgrade(&flag));
    }

    /// Whether any registered owed-reload flag is set (certify step 7).
    pub(crate) fn any_owed(&self) -> bool {
        let inner = self.inner.lock();
        inner
            .owed_flags
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .any(|f| f.load(Ordering::SeqCst))
    }

    /// Whether a manual reload folded into an owed replay.
    pub(crate) fn replay_owed(&self) -> bool {
        self.inner.lock().replay_owed
    }

    /// The watcher clears the flag once it holds its admission guard; the
    /// guard parameter makes the clear impossible without one.
    pub(crate) fn take_replay_owed(&self, _held: &AdmissionGuard) -> bool {
        std::mem::take(&mut self.inner.lock().replay_owed)
    }

    /// Wakes the watcher so the owed replay and any kept trigger run at once.
    /// `notify_one` stores a permit, so a poke before the wait is not lost.
    pub(crate) fn poke_watcher(&self) {
        #[cfg(test)]
        self.seams.record_resume_poke();
        self.watcher.notify_one();
    }

    /// The watcher awaits this between ticks.
    pub(crate) fn watcher_poked(&self) -> &Notify {
        &self.watcher
    }

    /// Pause for `attempt`. Final states answer Unavailable.
    pub(super) fn pause(&self, attempt: u64) -> Result<(), FloorFault> {
        let mut inner = self.inner.lock();
        match inner.state {
            GateState::Terminal | GateState::Released => Err(FloorFault::Unavailable),
            _ => {
                inner.state = GateState::Paused(attempt);
                Ok(())
            }
        }
    }

    /// Paused to Certified for `attempt`, only while that attempt is current.
    pub(super) fn certify(&self, attempt: u64) -> bool {
        let mut inner = self.inner.lock();
        let current = inner.state == GateState::Paused(attempt);
        if current {
            inner.state = GateState::Certified(attempt);
        }
        current
    }

    /// Open from Paused or Certified, then poke. True when it reopened.
    pub(super) fn reopen(&self) -> bool {
        let reopened = {
            let mut inner = self.inner.lock();
            let was = matches!(inner.state, GateState::Paused(_) | GateState::Certified(_));
            if was {
                inner.state = GateState::Open;
            }
            was
        };
        if reopened {
            self.poke_watcher();
        }
        reopened
    }

    /// Final state `to` (Terminal or Released) from anywhere but the other
    /// final state; the owed replay is discarded. True when it changed.
    pub(super) fn finish(&self, to: GateState) -> bool {
        let mut inner = self.inner.lock();
        let open = !matches!(inner.state, GateState::Terminal | GateState::Released);
        if open {
            inner.state = to;
            inner.replay_owed = false;
        }
        open
    }
}
