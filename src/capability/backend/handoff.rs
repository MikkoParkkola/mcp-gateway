// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a capability snapshot reaches the live config.
//!
//! One mutex guards the handoff. Nothing is called while it is held: the
//! live config is updated only after the guard drops. Park, attach and
//! publish take that same mutex, so a scan cannot park after an attach
//! that already looked.

use std::sync::Arc;
use std::sync::atomic::AtomicU8;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::sync::atomic::Ordering;

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
    /// The registry the startup scan announces its catalogue through, left
    /// before the scan publishes. A parked scan is completed by attach, and
    /// attach announces through this, as the scan would have.
    announce: Option<Arc<crate::backend::BackendRegistry>>,
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
                announce: None,
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
        #[cfg(test)]
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
        #[cfg(test)]
        self.remember(seq, &part, &staged);
        #[cfg(test)]
        reach(Step::Deliver);
        if let Staged::Live(live) = staged {
            live.set_capabilities(seq, part);
        }
        if completes {
            self.complete_scan()
        } else {
            false
        }
    }

    /// Attach `live`. Always takes a held part, whatever the scan state.
    /// A second call is a programming error and panics in debug builds.
    ///
    /// Returns the registry to announce through when this call completed a
    /// parked scan and the scan left one; the caller announces after this
    /// mutex is released.
    pub(crate) fn attach_revision(
        &self,
        live: Arc<LiveConfig>,
    ) -> Option<Arc<crate::backend::BackendRegistry>> {
        let (target, taken, completes, announce) = {
            let mut inner = self.inner.lock();
            #[cfg(test)]
            reach(Step::Attach);
            if matches!(inner.state, State::Attached(_)) {
                drop(inner);
                #[cfg(debug_assertions)]
                panic!("attach is once per backend; a second call would replace the live config");
                #[cfg(not(debug_assertions))]
                {
                    self.deliver_attached(&live, None, false);
                    return None;
                }
            }
            // The handle this call delivers to; the state keeps `live` itself.
            let target = Arc::clone(&live);
            let prev = std::mem::replace(&mut inner.state, State::Attached(live));
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
            let announce = if completes {
                inner.announce.take()
            } else {
                None
            };
            (target, taken, completes, announce)
        };
        let fresh = self.deliver_attached(&target, taken, completes);
        announce.filter(|_| fresh)
    }

    /// Deliver a part attach took. Not recorded: the publish that stored it
    /// recorded it once. The seq check is not applied again; the part already
    /// passed it. `true` when this call marked the scan complete.
    fn deliver_attached(
        &self,
        live: &LiveConfig,
        taken: Option<(u64, Part)>,
        completes: bool,
    ) -> bool {
        #[cfg(test)]
        reach(Step::Deliver);
        if let Some((seq, part)) = taken {
            live.set_capabilities(seq, part);
        }
        completes && self.complete_scan()
    }

    /// The scan failed or was cancelled, as far as this mutex is concerned.
    ///
    /// A scan that already published is left as it is: an ended scan is
    /// complete, and a parked one stays not ready until attach delivers its
    /// part (R3-C). Only a scan that had not published becomes `Failed`;
    /// `true` then, and the caller marks it failed and completes it.
    fn end_failed(&self) -> bool {
        let mut inner = self.inner.lock();
        if inner.scan == Scan::NotEnded {
            inner.scan = Scan::Failed;
            return true;
        }
        false
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

    /// Record an accepted publish once, for the rows. A dropped seq is not a
    /// delivery.
    #[cfg(test)]
    fn remember(&self, seq: u64, part: &Part, staged: &Staged) {
        if matches!(staged, Staged::Dropped) {
            return;
        }
        self.delivered.lock().push((seq, part.clone()));
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
    /// The startup scan's end when it did not complete itself: a panic, a
    /// drop, or a return after parking. The scan's drop guard calls this.
    ///
    /// A scan that published is left alone: ended is complete, and parked
    /// waits for attach. A scan that never published, on a backend not
    /// already complete, is marked failed and then finished, after the
    /// handoff mutex is released.
    pub(crate) fn end_failed(&self, registry: &crate::backend::BackendRegistry) {
        if self.handoff.end_failed() && !self.initial_scan_complete() {
            self.mark_initial_scan_failed();
            self.finish_initial_scan(registry);
        }
    }

    /// Leave `registry` for the startup scan's announcement. Called before
    /// the scan publishes, so an attach that completes the parked scan finds
    /// it under the same mutex.
    pub(crate) fn announce_scan_through(&self, registry: Arc<crate::backend::BackendRegistry>) {
        self.handoff.inner.lock().announce = Some(registry);
    }

    /// Attach `live` to this backend's handoff. Once per backend. An attach
    /// that completes a parked scan announces its catalogue, as the scan's
    /// own end would have.
    pub(crate) fn attach_revision(&self, live: Arc<LiveConfig>) {
        // The readiness-order snapshot needs nothing here: a parked scan set
        // it in its publish, before this attach can make it ready.
        let announce = self.handoff.attach_revision(live);
        if let Some(registry) = announce {
            self.announce_scanned(&registry);
        }
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
    fn open(
        step: Step,
    ) -> (
        Self,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
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
    match gate
        .release
        .recv_timeout(std::time::Duration::from_secs(30))
    {
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
