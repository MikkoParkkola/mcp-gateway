// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8150: what a signed execution's steps record for its nonce. A step
//! refused before its backend asks for the nonce back; every dispatch marks the
//! execution. `MetaMcp::handle_tools_call` settles once, when the call returns,
//! and gives the nonce back only if a step asked and none dispatched.

use crate::gateway::meta_mcp::MetaMcpCallerContext;

/// Ask for the nonce back: this step was refused before its backend (its
/// continuation or its spend). Settled when the call returns.
pub(crate) fn ask_refund(caller: &MetaMcpCallerContext<'_>) {
    caller.signing.inspect(|signing| signing.want_refund());
}

/// Mark the execution lease and the signed execution dispatched, before the
/// backend is reached: from here on neither the key nor the nonce is given
/// back, as a replay would repeat what the backend did.
pub(crate) fn mark_dispatched(caller: &MetaMcpCallerContext<'_>) {
    if let Some(execution) = caller.execution {
        execution.mark_dispatched();
    }
    caller.signing.inspect(|signing| signing.mark_dispatched());
}

/// A call refused before its backend was reached gives back what it took:
/// its idempotency key (released, not settled: nothing acted) and, once the
/// call returns with no step dispatched, the signing nonce it admitted, so the
/// honest call re-sent under that nonce is judged on its merits, not refused as
/// a replay (MIK-8150, as the direct route does since #3451).
pub(crate) fn give_back_unsent(
    caller: &MetaMcpCallerContext<'_>,
    reservation: &mut Option<crate::idempotency::IdempotencyReservation>,
) {
    if let Some(reservation) = reservation.as_mut() {
        reservation.release();
    }
    ask_refund(caller);
}
