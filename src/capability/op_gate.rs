// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A test holds one catalogue operation at its load, at the swap, and in the
//! gap after the catalogue lock is released and before the publish.
//!
//! Same shape as the handoff step gate: the operation tells the test it
//! arrived, then waits for the test to release it. Several steps are armed
//! together because one reload passes all three. This is a different
//! thread-local from the handoff gate, so holding one does not consume the
//! other. Ungated, [`reach`] returns immediately.

use std::cell::RefCell;
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

/// Where a row holds the operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Before the directory is read.
    Load,
    /// Inside the catalogue write lock, before the catalogue is replaced.
    Swap,
    /// After that lock is released, before the publish.
    BeforePublish,
}

pub(crate) struct Gate {
    step: Step,
    arrived: SyncSender<()>,
    release: Receiver<()>,
}

impl Gate {
    /// `arrived` is signalled when the operation reaches `step`. Sending on
    /// `release` lets it continue.
    pub(crate) fn open(step: Step) -> (Self, Receiver<()>, SyncSender<()>) {
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

thread_local! {
    static GATES: RefCell<Vec<Gate>> = const { RefCell::new(Vec::new()) };
}

/// Replace this thread's armed steps. A reload runs on the thread that armed
/// them: the reaches are synchronous, before that thread's next await.
pub(crate) fn arm(gates: Vec<Gate>) {
    GATES.with(|slot| *slot.borrow_mut() = gates);
}

/// If this thread armed `step`, tell the test and wait until it releases.
/// Any other armed step is left alone. A wait past 30s panics.
pub(crate) fn reach(step: Step) {
    let gate = GATES.with(|slot| {
        let mut gates = slot.borrow_mut();
        gates
            .iter()
            .position(|gate| gate.step == step)
            .map(|pos| gates.remove(pos))
    });
    let Some(gate) = gate else {
        return;
    };
    gate.arrived
        .send(())
        .expect("the test stopped waiting for this step");
    match gate.release.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("hung past 30s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the release end was dropped");
        }
    }
}
