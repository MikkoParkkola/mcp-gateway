// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a capability snapshot reaches the live config.
//!
//! One mutex guards the handoff. Nothing is called while it is held. The
//! bodies below are stubs: they take that mutex and then record nothing and
//! deliver nothing, so today's scan end is unchanged. The test observer and
//! the step gate are how a row holds park, attach, or the gap after the
//! unlock, without sleeping.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::config_reload::LiveConfig;
use crate::config_reload::revision::{CapabilityPart, PartDigest};

/// The part the design names. Digests, because delivery happens after the
/// catalogue lock has been released and the raw bytes are already gone.
type Part = CapabilityPart<PartDigest>;

/// Unattached holds the newest part until a live config exists. Attached is
/// that config. The stub never leaves [`State::Unattached`].
#[allow(
    dead_code,
    reason = "the stub never stores a part or attaches; the real handoff writes both"
)]
enum State {
    Unattached { held: Option<(u64, Part)> },
    Attached(Arc<LiveConfig>),
}

/// The startup scan has not ended, is waiting for attach, has ended, or failed.
#[allow(
    dead_code,
    reason = "the stub never moves the scan off NotEnded; rows name the other three"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scan {
    NotEnded,
    Parked,
    Ended,
    Failed,
}

#[allow(
    dead_code,
    reason = "the stub keeps the initial value; the real handoff writes these fields"
)]
struct Inner {
    state: State,
    max_seq: u64,
    scan: Scan,
}

/// Park, attach and publish share this mutex.
pub(crate) struct Handoff {
    inner: Mutex<Inner>,
    /// Every `(seq, part)` a delivery would hand to the live config. Stays
    /// empty while the stub delivers nothing. Not the handoff mutex: the
    /// design's one lock is `inner`.
    #[cfg(test)]
    delivered: Mutex<Vec<(u64, Part)>>,
}

impl Handoff {
    /// A handoff that has not attached and whose scan has not ended.
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: State::Unattached { held: None },
                max_seq: 0,
                scan: Scan::NotEnded,
            }),
            #[cfg(test)]
            delivered: Mutex::new(Vec::new()),
        }
    }

    /// Publish `(seq, part)`.
    ///
    /// Stub: lock and drop it. Records nothing. Delivers nothing.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    pub(crate) fn publish(&self, seq: u64, part: Part) {
        {
            let _held = self.inner.lock();
            let _ = (seq, &part);
        }
        // After the unlock, before a delivery. The stub does not deliver.
        #[cfg(test)]
        reach(Step::Deliver);
        let _ = part;
    }

    /// The scan's publish and its end, one acquisition.
    ///
    /// Stub: lock and drop it. Records nothing. Delivers nothing. Does not
    /// mark the scan complete.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    pub(crate) fn publish_and_end(&self, seq: u64, part: Part) {
        {
            let _held = self.inner.lock();
            // Inside the acquisition, so a test can start attach while this
            // scan still holds the mutex.
            #[cfg(test)]
            reach(Step::Park);
            let _ = (seq, part);
        }
        #[cfg(test)]
        reach(Step::Deliver);
    }

    /// Attach `live`. A second call is a programming error in the real
    /// handoff; this stub never panics.
    ///
    /// Stub: lock and drop it. Takes nothing. Delivers nothing. Does not
    /// finish the scan.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    pub(crate) fn attach_revision(&self, live: Arc<LiveConfig>) {
        {
            let _held = self.inner.lock();
            #[cfg(test)]
            reach(Step::Attach);
            let _ = &live;
        }
        #[cfg(test)]
        reach(Step::Deliver);
        let _ = live;
    }

    /// The scan failed or was cancelled, as far as this mutex is concerned.
    ///
    /// Stub: lock and drop it. Does not record [`Scan::Failed`]. The caller
    /// runs today's completion outside the lock.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    fn end_failed(&self) {
        let _held = self.inner.lock();
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

impl super::CapabilityBackend {
    /// The scan failed or was cancelled.
    ///
    /// The handoff half records nothing. What follows is the startup scan's
    /// drop guard, unchanged: an unfinished scan is marked failed and then
    /// finished. Both run after the handoff mutex is released.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "production call sites are a later slice; the tests are the caller until then"
        )
    )]
    pub(crate) fn end_failed(&self, registry: &crate::backend::BackendRegistry) {
        self.handoff.end_failed();
        if !self.initial_scan_complete() {
            self.mark_initial_scan_failed();
            self.finish_initial_scan(registry);
        }
    }

    /// What a delivery would have handed over. Empty while the publish stub
    /// delivers nothing.
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
