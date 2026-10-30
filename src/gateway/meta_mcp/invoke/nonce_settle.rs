// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8150: what a signed execution's steps record for its nonce. A step
//! refused before its backend asks for the nonce back; every dispatch marks the
//! execution. `MetaMcp::handle_tools_call` settles once, when the call returns,
//! and gives the nonce back only if a step asked and none dispatched.

use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::dispatch_log::PreSend;
use crate::gateway::meta_mcp::refund_witness::{Effect, RefundWitness};
use crate::gateway::task_service::execution::BeginOutcome;

/// The only entry outside `invoke` that spends a refund witness (MIK-8353
/// 3b): something outside the invoke path consumed or acted for this call (a
/// chain resume's handle), so no later refusal of it may give the nonce back.
pub(crate) fn spend_witness(caller: &MetaMcpCallerContext<'_>) {
    Witnessed::take(caller).spend();
}

/// Ask for the nonce back: this step was refused before its backend (its
/// continuation or its spend). Settled when the call returns.
pub(crate) fn ask_refund(caller: &MetaMcpCallerContext<'_>) {
    caller.signing.inspect(|signing| signing.want_refund());
}

/// A task submit refused before its task exists asks for the nonce back
/// (MIK-8353 3c): a key mismatch, a key in flight, no free worker and sealed
/// intake are decided before any write (`TaskService::create_targeted`), and a
/// dropped lease only releases the key. `Unavailable` may follow a commit, so
/// it stays spent, as do a created or stored task.
pub(crate) fn ask_if_refused_submit(
    caller: &MetaMcpCallerContext<'_>,
    outcome: BeginOutcome,
) -> BeginOutcome {
    if matches!(
        outcome,
        BeginOutcome::Mismatch
            | BeginOutcome::InFlight
            | BeginOutcome::Capacity
            | BeginOutcome::Sealed
    ) {
        ask_refund(caller);
    }
    outcome
}

/// A task submit refused before its task is begun (a backend that requires a
/// signature chain, MIK-8353 3c): ask for the nonce back, then answer `error`.
pub(crate) fn refused_submit_answer(
    caller: &MetaMcpCallerContext<'_>,
    id: crate::protocol::RequestId,
    error: &crate::Error,
) -> crate::protocol::JsonRpcResponse {
    ask_refund(caller);
    crate::gateway::meta_mcp::response_security::error_response_preserving_status(id, error)
}

/// Note the binding `step` is dispatched under (MIK-8407), on the execution
/// lease and on a task worker's dispatch log: the one noting point, so a
/// synchronous result and a task row record the same thing. Called with the
/// resolution the dispatch uses, never a second read of the target.
pub(crate) fn note_binding(
    caller: &MetaMcpCallerContext<'_>,
    step: (&str, &str),
    binding: Option<&str>,
) {
    if let Some(execution) = caller.execution {
        execution.note_binding(step, binding);
    }
    crate::gateway::meta_mcp::dispatch_log::note_binding(step, binding);
}

/// Note `step` on the execution lease as served to this execution: sent, or
/// answered from a stored or cached result. Retained data from it is in the
/// stored response, so a replay past its revocation meets its refusal
/// (#3872 review A).
pub(crate) fn note_served(caller: &MetaMcpCallerContext<'_>, step: (&str, &str)) {
    if let Some(execution) = caller.execution {
        execution.note_step(step);
    }
}

/// Mark the execution lease and the signed execution dispatched, before the
/// backend is reached: from here on neither the key nor the nonce is given
/// back, as a replay would repeat what the backend did.
pub(crate) fn mark_dispatched(caller: &MetaMcpCallerContext<'_>, step: (&str, &str)) {
    // A send after an earlier refusal in the same call (a fill retry, a
    // backstop that falls through) is a call: the refusal no longer stands.
    super::audit::note_pre_send(PreSend::Clear);
    // A web UI call learns the backend may act from here on (U12).
    #[cfg(feature = "webui")]
    crate::gateway::ui_call::note_dispatched(step);
    if let Some(execution) = caller.execution {
        execution.mark_dispatched();
    }
    note_served(caller, step);
    caller.signing.inspect(|signing| signing.mark_dispatched());
}

/// How an exit before the send settles the call's nonce, and its key where
/// the exit pairs the two (MIK-8488 INVOKE.6). Every such exit on the invoke
/// path goes through [`settle_pre_send`]; a key-only transition keeps
/// `IdempotencyReservation`'s own methods at its point.
pub(super) enum PreSendExit<'r> {
    /// Refused before anything this step does acted: ask for the nonce back;
    /// the witness decides.
    AskRefund,
    /// Refused before the backend was reached: give back what it took, its
    /// key (released, not settled: nothing acted) and, once the call returns
    /// with no step dispatched, the signing nonce it admitted, so the honest
    /// call re-sent under that nonce is judged on its merits, not refused as
    /// a replay (MIK-8150, as the direct route does since #3451).
    GiveBackUnsent(&'r mut Option<crate::idempotency::IdempotencyReservation>),
    /// The key half of a refusal whose nonce half is asked at the stage's
    /// exit: released here, at the refusal, so its drop never releases it as
    /// abandoned.
    ReleaseKey(Option<&'r mut crate::idempotency::IdempotencyReservation>),
    /// Answered from a stored or cached result: note `(server, tool)` on the
    /// execution as served.
    Served((&'r str, &'r str)),
}

/// Settle one pre-send exit: the one place the invoke path decides what a
/// refusal or an early answer before the send gives back.
pub(super) fn settle_pre_send(caller: &MetaMcpCallerContext<'_>, exit: PreSendExit<'_>) {
    // Every exit but `Served` is a refusal before the backend: no call the
    // task made. A served answer is the backend's earlier output: a call.
    super::audit::note_pre_send(match exit {
        PreSendExit::Served(_) => PreSend::Clear,
        _ => PreSend::Refused,
    });
    match exit {
        PreSendExit::AskRefund => ask_refund(caller),
        PreSendExit::GiveBackUnsent(reservation) => {
            if let Some(reservation) = reservation.as_mut() {
                reservation.release();
            }
            ask_refund(caller);
        }
        PreSendExit::ReleaseKey(reservation) => {
            if let Some(reservation) = reservation {
                reservation.release();
            }
        }
        PreSendExit::Served(step) => note_served(caller, step),
    }
}

/// A busy custody refused this call before its backend: ask for the nonce
/// back, so the same signed repeat is judged on its merits after recovery
/// (MIK-8392 Busy parity, R5n). Any other error asks for nothing.
pub(super) fn ask_if_transient(caller: &MetaMcpCallerContext<'_>, error: &crate::Error) {
    if crate::personal_accounts::refusal::transient_data(error).is_some() {
        settle_pre_send(caller, PreSendExit::AskRefund);
    }
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

// MIK-8353 PR-W: a joined fill keeps the nonce spent.
#[cfg(all(test, feature = "cost-governance"))]
#[path = "refund_waiter_tests.rs"]
mod refund_waiter_tests;

#[cfg(test)]
mod pre_send_tests {
    use super::{PreSendExit, mark_dispatched, settle_pre_send};
    use crate::gateway::authz::AllowAll;
    use crate::gateway::meta_mcp::authz_tests::ctx;
    use crate::gateway::meta_mcp::dispatch_log::PreSend;

    /// A refusal exit marks the call refused; a later send, or an answer
    /// served from a stored or cached result, makes it a call again.
    #[tokio::test]
    async fn a_refusal_marks_the_call_and_a_send_or_served_answer_clears_it() {
        let allow = AllowAll;
        let caller = ctx(&allow);
        let ((), notes) = super::super::audit::with_dispatch_scope(async {
            settle_pre_send(&caller, PreSendExit::AskRefund);
        })
        .await;
        assert_eq!(
            notes.pre_send(),
            PreSend::Refused,
            "refused before its backend"
        );
        let ((), notes) = super::super::audit::with_dispatch_scope(async {
            settle_pre_send(&caller, PreSendExit::AskRefund);
            mark_dispatched(&caller, ("s", "t"));
        })
        .await;
        assert_eq!(
            notes.pre_send(),
            PreSend::Clear,
            "a send after a refusal is a call"
        );
        let ((), notes) = super::super::audit::with_dispatch_scope(async {
            settle_pre_send(&caller, PreSendExit::AskRefund);
            settle_pre_send(&caller, PreSendExit::Served(("s", "t")));
        })
        .await;
        assert_eq!(
            notes.pre_send(),
            PreSend::Clear,
            "a served answer is a call"
        );
    }
}
