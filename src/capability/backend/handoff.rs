// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a capability snapshot reaches the live config.
//!
//! One mutex guards the handoff. Nothing is called while it is held: the
//! live config is updated only after the guard drops. Park, attach and
//! publish take that same mutex, so a scan cannot park after an attach
//! that already looked.

use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::config_reload::LiveConfig;
use crate::config_reload::revision::{CapabilityPart, PartDigest};

/// The part the design names. Digests, because delivery happens after the
/// catalogue lock has been released and the raw bytes are already gone.
type Part = CapabilityPart<PartDigest>;

/// Unattached holds the newest part until a live config exists. Attached is
/// that config.
enum State {
    Unattached { held: Option<(u64, Part)> },
    Attached(Arc<LiveConfig>),
}

/// The startup scan has not ended, is waiting for attach, has ended, or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scan {
    NotEnded,
    Parked,
    Ended,
    Failed,
}

struct Inner {
    state: State,
    max_seq: u64,
    scan: Scan,
}

/// What [`stage`] decided for one publish.
enum Staged {
    /// `seq` was at or below the highest already accepted. Not stored.
    Dropped,
    /// Accepted while no live config was attached. The part is held.
    Held,
    /// Accepted while attached. Deliver this handle after the unlock.
    Live(Arc<LiveConfig>),
}

/// Park, attach and publish share this mutex.
pub(crate) struct Handoff {
    inner: Mutex<Inner>,
    /// The backend's scan-complete bit. Shared so marking ready here is the
    /// same bit the backend reads, without the handoff holding the backend.
    scan_bits: Arc<AtomicU8>,
    /// Completions beside the bit. Shared with the backend so a row counting
    /// [`CapabilityBackend::mark_initial_scan_complete`] sees this transition.
    #[cfg(test)]
    completions: Arc<AtomicUsize>,
    /// Every `(seq, part)` accepted for delivery. Recorded once, when the
    /// publish is accepted, including while nothing is attached: the reload
    /// rows read this and have no live config. Attach does not record the
    /// part again. Not the handoff mutex.
    #[cfg(test)]
    delivered: Mutex<Vec<(u64, Part)>>,
}

impl Handoff {
    /// A handoff that has not attached and whose scan has not ended.
    /// `scan_bits` is the backend's bit, already complete for a backend that
    /// was not put into a startup scan.
    pub(crate) fn new(scan_bits: Arc<AtomicU8>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: State::Unattached { held: None },
                max_seq: 0,
                scan: Scan::NotEnded,
            }),
            scan_bits,
            #[cfg(test)]
            completions: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            delivered: Mutex::new(Vec::new()),
        }
    }

    /// The completion counter, so the backend and this handoff increment one.
    /// Visible to the parent module: `CapabilityBackend::new` shares it.
    #[cfg(test)]
    pub(super) fn share_completions(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.completions)
    }

    /// Publish `(seq, part)`. A seq at or below the highest accepted one is
    /// dropped in every state. Unattached, the part is held. Attached, it is
    /// delivered after this mutex is released.
    pub(crate) fn publish(&self, seq: u64, part: Part) {
        let staged = {
            let mut inner = self.inner.lock();
            stage(&mut inner, seq, &part)
        };
        self.remember(seq, &part, &staged);
        #[cfg(test)]
        reach(Step::Deliver);
        if let Staged::Live(live) = staged {
            live.set_capabilities(seq, part);
        }
    }

    /// The scan's publish and its end, one acquisition. A cancellation cannot
    /// fall between them, so a scan that published does not end failed.
    ///
    /// Returns whether this call is the one that marked the scan complete.
    /// Unattached, the scan is parked and this returns false: readiness stays
    /// false until attach takes the held part.
    pub(crate) fn publish_and_end(&self, seq: u64, part: Part) -> bool {
        let (staged, completes) = {
            let mut inner = self.inner.lock();
            // Inside the acquisition, so a test can start attach while this
            // scan still holds the mutex and before the park is stored.
            #[cfg(test)]
            reach(Step::Park);
            let staged = stage(&mut inner, seq, &part);
            // Attached: this call ends the scan. Unattached: park, and do
            // not mark ready — the rows read readiness while this returns.
            let completes = match &inner.state {
                State::Attached(_) => {
                    inner.scan = Scan::Ended;
                    true
                }
                State::Unattached { .. } => {
                    inner.scan = Scan::Parked;
                    false
                }
            };
            (staged, completes)
        };
        self.remember(seq, &part, &staged);
        #[cfg(test)]
        reach(Step::Deliver);
        if let Staged::Live(live) = staged {
            live.set_capabilities(seq, part);
        }
        if completes { self.complete_scan() } else { false }
    }

    /// Attach `live`. Always takes a held part, whatever the scan state.
    /// A second call is a programming error and panics in debug builds.
    pub(crate) fn attach_revision(&self, live: Arc<LiveConfig>) {
        let (taken, completes) = {
            let mut inner = self.inner.lock();
            #[cfg(test)]
            reach(Step::Attach);
            if matches!(inner.state, State::Attached(_)) {
                drop(inner);
                #[cfg(debug_assertions)]
                panic!("attach is once per backend; a second call would replace the live config");
                #[cfg(not(debug_assertions))]
                return self.deliver_attached(live, None, false);
            }
            let prev = std::mem::replace(&mut inner.state, State::Attached(Arc::clone(&live)));
            let taken = match prev {
                State::Unattached { held } => held,
                State::Attached(_) => None,
            };
            // Only a parked scan is completed by attach. A scan that has not
            // ended yet publishes and completes itself.
            let completes = if inner.scan == Scan::Parked {
                inner.scan = Scan::Ended;
                true
            } else {
                false
            };
            (taken, completes)
        };
        self.deliver_attached(live, taken, completes);
    }

    /// Deliver a part attach took. Not recorded: the publish that stored it
    /// recorded it once. The seq check is not applied again; the part already
    /// passed it.
    fn deliver_attached(&self, live: Arc<LiveConfig>, taken: Option<(u64, Part)>, completes: bool) {
        #[cfg(test)]
        reach(Step::Deliver);
        if let Some((seq, part)) = taken {
            live.set_capabilities(seq, part);
        }
        if completes {
            self.complete_scan();
        }
    }

    /// The scan failed or was cancelled, as far as this mutex is concerned.
    ///
    /// A scan that already published (parked) ends `Ended` and is marked
    /// complete here, before the caller checks readiness, so the caller does
    /// not also mark it failed. A scan that had not published is `Failed`;
    /// the caller marks it failed and completes it.
    fn end_failed(&self) {
        let completes = {
            let mut inner = self.inner.lock();
            match inner.scan {
                Scan::NotEnded => {
                    inner.scan = Scan::Failed;
                    false
                }
                Scan::Parked => {
                    inner.scan = Scan::Ended;
                    true
                }
                Scan::Ended | Scan::Failed => false,
            }
        };
        if completes {
            self.complete_scan();
        }
    }

    /// `true` when this call is the transition to complete.
    fn complete_scan(&self) -> bool {
        let fresh = super::initial_scan::note_scan_complete(&self.scan_bits);
        if fresh {
            #[cfg(test)]
            self.completions.fetch_add(1, Ordering::AcqRel);
        }
        fresh
    }

    /// Record an accepted publish once. A dropped seq is not a delivery.
    fn remember(&self, seq: u64, part: &Part, staged: &Staged) {
        if matches!(staged, Staged::Dropped) {
            return;
        }
        #[cfg(test)]
        self.delivered.lock().push((seq, part.clone()));
        #[cfg(not(test))]
        let _ = (seq, part);
    }

    /// The scan published or ended. A failure before any publish is neither.
    pub(crate) fn has_published(&self) -> bool {
        matches!(self.inner.lock().scan, Scan::Parked | Scan::Ended)
    }

    #[cfg(test)]
    fn scan(&self) -> Scan {
        self.inner.lock().scan
    }

    #[cfg(test)]
    fn delivered(&self) -> Vec<(u64, Part)> {
        self.delivered.lock().clone()
    }

    /// `true` while some caller holds the handoff mutex.
    #[cfg(test)]
    fn lock_held(&self) -> bool {
        self.inner.try_lock().is_none()
    }
}

/// Accept `seq` or drop it. The highest seq is remembered in every state,
/// including after the held part has been taken.
fn stage(inner: &mut Inner, seq: u64, part: &Part) -> Staged {
    if seq <= inner.max_seq {
        return Staged::Dropped;
    }
    inner.max_seq = seq;
    match &mut inner.state {
        State::Unattached { held } => {
            *held = Some((seq, part.clone()));
            Staged::Held
        }
        State::Attached(live) => Staged::Live(Arc::clone(live)),
    }
}

impl super::CapabilityBackend {
    /// The scan failed or was cancelled.
    ///
    /// The handoff half runs first. A parked scan is already complete when
    /// this returns, so the failure mark below does not apply to it. What
    /// follows for a scan that never published is the startup scan's drop
    /// guard: mark it failed, then finish it. Both run after the handoff
    /// mutex is released.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the startup scan's drop guard completes a published scan itself; rows call this for a scan that had not published"
        )
    )]
    pub(crate) fn end_failed(&self, registry: &crate::backend::BackendRegistry) {
        self.handoff.end_failed();
        if !self.initial_scan_complete() {
            self.mark_initial_scan_failed();
            self.finish_initial_scan(registry);
        }
    }

    /// Attach `live` to this backend's handoff. Once per backend.
    pub(crate) fn attach_revision(&self, live: Arc<LiveConfig>) {
        self.handoff.attach_revision(live);
    }

    /// The startup scan has published a part (parked or ended). A drop of the
    /// scan after that must not mark the scan failed.
    pub(crate) fn scan_has_published(&self) -> bool {
        self.handoff.has_published()
    }

    /// The handoff to the live config. One per backend.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production uses the methods on CapabilityBackend; rows hold the handoff directly"
        )
    )]
    pub(crate) fn handoff(&self) -> &Handoff {
        &self.handoff
    }

    /// What a delivery accepted. Empty until a publish is accepted.
    #[cfg(test)]
    pub(crate) fn delivered_revisions(&self) -> Vec<(u64, CapabilityPart<PartDigest>)> {
        self.handoff.delivered()
    }
}

/// Which step a test is holding. A gate pauses only at its own step, so the
/// park inside an acquisition does not consume a gate armed for the delivery
/// after the unlock.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Park,
    Attach,
    Deliver,
}

#[cfg(test)]
struct StepGate {
    step: Step,
    arrived: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl StepGate {
    fn open(step: Step) -> (Self, std::sync::mpsc::Receiver<()>, std::sync::mpsc::SyncSender<()>) {
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        (
            Self {
                step,
                arrived: arrived_tx,
                release: release_rx,
            },
            arrived_rx,
            release_tx,
        )
    }
}

#[cfg(test)]
thread_local! {
    static GATE: std::cell::RefCell<Option<StepGate>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn arm(gate: StepGate) {
    GATE.with(|slot| *slot.borrow_mut() = Some(gate));
}

/// If this thread armed `step`, tell the test and wait until it releases.
/// Any other armed step is left alone. A wait past 30s panics.
#[cfg(test)]
fn reach(step: Step) {
    let gate = GATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let armed = slot.as_ref().is_some_and(|gate| gate.step == step);
        if armed { slot.take() } else { None }
    });
    let Some(gate) = gate else {
        return;
    };
    gate.arrived
        .send(())
        .expect("the test stopped waiting for this step");
    match gate.release.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the release end was dropped");
        }
    }
}

#[cfg(test)]
#[path = "handoff_tests.rs"]
mod handoff_tests;
