// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! How a bridged round's dispatch settles the call's idempotency key.

use crate::idempotency::IdempotencyReservation;

use super::side_effect_markers::uncertain_side_effect;

/// #1962: arm (or disarm) a held reservation to settle as "outcome uncertain"
/// if the call is dropped before the dispatch result is handled.
pub(super) fn arm(slot: &parking_lot::Mutex<Option<IdempotencyReservation>>, armed: bool) {
    if let Some(reservation) = slot.lock().as_mut() {
        if armed {
            reservation.commit(&uncertain_side_effect());
        } else {
            reservation.disarm();
        }
    }
}

/// Decides whether a failed bridged dispatch releases the idempotency key.
///
/// The error type already carries a tight, deliberate allowlist of failures that
/// provably happened above the backend. A bridged round that hit one of those ran
/// nothing, so it releases the key on the same terms as a pre-dispatch refusal;
/// everything else stays dispatched and settles, because a round the backend may
/// have executed must not readmit a retry of a side effect (ADR-012 consequence 1).
pub(in crate::gateway::meta_mcp) fn classify_bridged_dispatch_error(
    error: &crate::Error,
) -> crate::gateway::input_bridge::BridgeError {
    let message = error.to_string();
    if error.is_pre_dispatch() {
        crate::gateway::input_bridge::BridgeError::NotAdmitted { message }
    } else {
        // Always `MayHaveActed`: `is_pre_dispatch()` already diverted every
        // provably-unexecuted case to `NotAdmitted` above, so anything
        // reaching here may have run.
        crate::gateway::input_bridge::BridgeError::BackendFailed {
            message,
            dispatch: crate::gateway::input_bridge::Dispatch::MayHaveActed,
        }
    }
}
