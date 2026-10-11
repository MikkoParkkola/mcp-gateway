// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8150: what a signed execution's steps record for its nonce. A step
//! refused before its backend asks for the nonce back; every dispatch marks the
//! execution. `MetaMcp::handle_tools_call` settles once, when the call returns,
//! and gives the nonce back only if a step asked and none dispatched.

use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::refund_witness::{Effect, RefundWitness};

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

/// The refund witness one invoke carries through its may-effect steps
/// (MIK-8353 slice 3a). Taken from the signing context on entry; a step that
/// may have acted drops it through [`Self::carry`]; the send spends it. Every
/// other exit, a refusal, an early answer or an error, hands back what
/// survived when this is dropped, so the settle may refund and a later step of
/// the same call starts from it. A step must carry its effect before any exit
/// that follows it.
pub(crate) struct Witnessed<'c, 'a> {
    caller: &'c MetaMcpCallerContext<'a>,
    witness: Option<RefundWitness>,
}

impl<'c, 'a> Witnessed<'c, 'a> {
    pub(crate) fn take(caller: &'c MetaMcpCallerContext<'a>) -> Self {
        let witness = caller
            .signing
            .and_then(crate::gateway::meta_mcp::signing::SigningInvocationContext::take_witness);
        Self { caller, witness }
    }

    /// Record what a step did: an effect drops the witness.
    pub(crate) fn carry(&mut self, effect: Effect) {
        self.witness = RefundWitness::carry(self.witness.take(), effect);
    }

    /// Something is about to act, or may have acted unreported: the nonce
    /// stays spent.
    pub(crate) fn spend(&mut self) {
        if let Some(witness) = self.witness.take() {
            witness.spend();
        }
    }
}

impl Drop for Witnessed<'_, '_> {
    fn drop(&mut self) {
        match (self.caller.signing, self.witness.take()) {
            (Some(signing), Some(witness)) => signing.keep_witness(witness),
            (None, Some(witness)) => witness.spend(),
            (_, None) => {}
        }
    }
}
