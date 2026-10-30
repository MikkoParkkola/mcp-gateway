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

/// Arm `reservation` for a backend dispatch: dropped before the result is
/// handled, it settles as "outcome uncertain" rather than freeing the key.
pub(in crate::gateway::meta_mcp) fn arm_for_dispatch(
    reservation: Option<&mut IdempotencyReservation>,
) {
    if let Some(reservation) = reservation {
        reservation.commit(&uncertain_side_effect());
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
    // `unsent`, not `is_pre_dispatch`: once an earlier round of this delivery
    // reached the backend, a later round's pre-send refusal no longer proves
    // the exchange ran nothing (MIK-9095 F2).
    if crate::gateway::delivery_facts::unsent(error) {
        crate::gateway::input_bridge::BridgeError::NotAdmitted { message }
    } else {
        // Always `MayHaveActed`: `unsent` already diverted every
        // provably-unexecuted case to `NotAdmitted` above, so anything
        // reaching here may have run.
        crate::gateway::input_bridge::BridgeError::BackendFailed {
            message,
            dispatch: crate::gateway::input_bridge::Dispatch::MayHaveActed,
        }
    }
}

/// #1989: a bridged round is refused before dispatch once the operator has
/// disabled the server. `NotAdmitted`, so the idempotency key is not burned by
/// work that never ran.
pub(super) fn refuse_if_killed(
    switch: &crate::kill_switch::KillSwitch,
    server: &str,
) -> Result<(), crate::gateway::input_bridge::BridgeError> {
    if switch.is_killed(server) {
        return Err(crate::gateway::input_bridge::BridgeError::NotAdmitted {
            message: format!("Server '{server}' is currently disabled by operator kill switch"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::classify_bridged_dispatch_error;
    use crate::gateway::input_bridge::BridgeError;

    /// MIK-8428 Case A: a bridged round whose account recheck met a busy
    /// custody (the sealed transient) ran nothing, so it is not admitted and
    /// frees the key; an unsealed look-alike may have acted.
    #[test]
    fn a_recheck_busy_is_not_admitted_and_its_look_alike_may_have_acted() {
        let sealed = crate::personal_accounts::refusal::transient_retry_error(None);
        let look_alike = crate::Error::JsonRpc {
            code: -32603,
            message: "temporarily unavailable, retry".to_owned(),
            data: crate::personal_accounts::refusal::transient_data(&sealed),
        };
        let busy = classify_bridged_dispatch_error(&sealed);
        assert!(matches!(busy, BridgeError::NotAdmitted { .. }), "sealed");
        let other = classify_bridged_dispatch_error(&look_alike);
        assert!(
            matches!(other, BridgeError::BackendFailed { .. }),
            "look-alike"
        );
    }
}
