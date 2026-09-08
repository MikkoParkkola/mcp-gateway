// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One synchronized delivery history, shared with the selected client writer.

use std::sync::Arc;

use tokio::sync::watch;

#[derive(Clone, Copy, Debug)]
enum DeliveryState {
    Queued,
    Writing,
    HandedOff,
    Answered,
    Failed {
        handed_off: bool,
    },
    Cancelled {
        handed_off: bool,
        transport_failed: bool,
        writing_started: bool,
    },
}

/// The delivery history for one request sent through [`super::ClientChannel`].
///
/// Channel implementations acknowledge after handing the complete frame to
/// their transport. Queueing alone is not handoff. Cancellation is terminal;
/// the handle remains alive in queued frames so a late writer can suppress them.
#[derive(Debug)]
pub struct DeliveryProgress {
    state: watch::Sender<DeliveryState>,
}

impl Default for DeliveryProgress {
    fn default() -> Self {
        let (state, _) = watch::channel(DeliveryState::Queued);
        Self { state }
    }
}

impl DeliveryProgress {
    /// Record complete frame handoff, returning whether delivery was still live.
    ///
    /// HTTP acknowledges its complete body frame; stdio acknowledges a flushed
    /// frame. This does not establish peer receipt. A false return never revives
    /// an answered, failed or cancelled exchange.
    pub fn mark_handed_off(&self) -> bool {
        let mut admitted = false;
        self.state.send_if_modified(|state| match *state {
            DeliveryState::Queued | DeliveryState::Writing => {
                *state = DeliveryState::HandedOff;
                admitted = true;
                true
            }
            DeliveryState::Cancelled {
                ref mut handed_off,
                writing_started: true,
                ..
            } if !*handed_off => {
                // A started stdio write must finish its frame or close. If it
                // flushes after cancellation, retain that fact without revival.
                *handed_off = true;
                true
            }
            _ => false,
        });
        admitted
    }

    pub(crate) fn begin_write(&self) -> bool {
        self.state.send_if_modified(|state| {
            if matches!(state, DeliveryState::Queued) {
                *state = DeliveryState::Writing;
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn answered(&self) -> bool {
        self.state.send_if_modified(|state| {
            if matches!(
                state,
                DeliveryState::Queued | DeliveryState::Writing | DeliveryState::HandedOff
            ) {
                *state = DeliveryState::Answered;
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn fail(&self) {
        self.state.send_if_modified(|state| match *state {
            DeliveryState::Answered | DeliveryState::Failed { .. } => false,
            DeliveryState::Cancelled {
                ref mut transport_failed,
                ..
            } => {
                let changed = !*transport_failed;
                *transport_failed = true;
                changed
            }
            DeliveryState::HandedOff => {
                *state = DeliveryState::Failed { handed_off: true };
                true
            }
            DeliveryState::Queued | DeliveryState::Writing => {
                *state = DeliveryState::Failed { handed_off: false };
                true
            }
        });
    }

    pub(crate) fn cancel(&self) {
        self.state.send_if_modified(|state| {
            let (handed_off, transport_failed, writing_started) = match *state {
                DeliveryState::Answered | DeliveryState::Cancelled { .. } => return false,
                DeliveryState::Queued => (false, false, false),
                DeliveryState::Writing => (false, false, true),
                DeliveryState::HandedOff => (true, false, true),
                DeliveryState::Failed { handed_off } => (handed_off, true, false),
            };
            *state = DeliveryState::Cancelled {
                handed_off,
                transport_failed,
                writing_started,
            };
            true
        });
    }

    pub(crate) fn unanswered_live_timeout(&self) -> bool {
        matches!(
            *self.state.borrow(),
            DeliveryState::Cancelled {
                handed_off: true,
                transport_failed: false,
                ..
            }
        )
    }

    pub(crate) fn fail_unfinished_frame(&self) {
        self.state.send_if_modified(|state| {
            if matches!(state, DeliveryState::Queued | DeliveryState::Writing) {
                *state = DeliveryState::Failed { handed_off: false };
                true
            } else {
                false
            }
        });
    }

    pub(crate) async fn closed(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            if matches!(
                *receiver.borrow_and_update(),
                DeliveryState::Failed { .. } | DeliveryState::Cancelled { .. }
            ) {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    pub(crate) fn cancel_on_drop(self: &Arc<Self>) -> CancelDelivery {
        CancelDelivery(Arc::clone(self))
    }
}

pub(crate) struct CancelDelivery(Arc<DeliveryProgress>);

impl Drop for CancelDelivery {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
