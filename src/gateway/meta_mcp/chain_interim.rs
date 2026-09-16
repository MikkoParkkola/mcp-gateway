// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MRTR.12: stopping a `gateway_execute` chain at an interim round.
//!
//! The chain loop treats every `Ok` as a completed step, so a step that comes
//! back asking a question is recorded as an answer and its successors run. The
//! seam here is what the loop consults instead: one classifier per step result,
//! one driver that owns the stop, and one validator for the sealed resume.
//!
//! Design: `docs/design/2026-09-16-mrtr-12-chain-interim-stop.md`.

use serde_json::Value;

use crate::protocol::continuation::{ContinuationState, Payload};
use crate::protocol::mrtr::InputRequired;
use crate::{Error, Result};

/// How many rounds one chain exchange may spend before a resume is refused.
///
/// A chain of `n` steps stops at most `n` times *at distinct steps*, because
/// each stop seals a strictly larger `next_step`. That is not the whole bound:
/// one step may ask again after being answered, sealing the same `next_step`
/// every time, and the bridge's per-exchange bound never applies to a native
/// resume.
pub const MAX_CHAIN_ROUNDS: u32 = 8;

/// Read one step's result as an interim round, or `None` if the step finished.
///
/// `None` rather than a two-armed enum because a completed step's value is the
/// result the caller already holds; only the asking case carries anything the
/// classifier had to extract.
///
/// Promotion is conditioned on [`InputRequired::from_result`] accepting the
/// result, never on the bare `resultType` string: a backend that merely writes
/// the discriminator into its output would otherwise stop a chain and mint a
/// continuation nobody can complete.
///
/// # Errors
///
/// A result that claims `input_required` and fails the parse is a fail-closed
/// stop: an upstream tool error naming the step, never a resumable round.
pub fn classify_step_result(
    idx: usize,
    tool_ref: &str,
    result: &Value,
) -> Result<Option<InputRequired>> {
    let _ = (idx, tool_ref, result);
    unimplemented!(
        "MRTR.12: classify a step result as completed, interim, or a malformed interim claim"
    )
}

/// Run `chain[start_step..]`, stopping at the first validated interim round.
///
/// `run_step` performs one step; `seal_stop` seals the [`ContinuationPurpose::ChainResume`]
/// envelope for a stop and yields the token that travels in the response.
/// Injected rather than reached for, so that what did and did not run is
/// observable — the invariant a chain stop exists to protect is about the
/// successor that must not execute, and nothing in a returned value shows that.
///
/// [`ContinuationPurpose::ChainResume`]: crate::protocol::continuation::ContinuationPurpose::ChainResume
///
/// # Errors
///
/// Propagates a step's own failure, and returns an upstream tool error for a
/// malformed interim claim.
pub fn drive_chain(
    chain: &[Value],
    start_step: usize,
    run_step: &mut dyn FnMut(usize, &str, &Value) -> Result<Value>,
    seal_stop: &mut dyn FnMut(usize, &InputRequired) -> Result<String>,
) -> Result<Value> {
    let _ = (chain, start_step, run_step, seal_stop);
    unimplemented!("MRTR.12: run the chain tail and stop at the first validated interim round")
}

/// What a validated resume is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainResumePlan {
    /// First step the resume may run. Steps `0..next_step` already ran.
    pub next_step: usize,
    /// Rounds this exchange has spent, carried forward from the envelope.
    pub rounds_used: u32,
}

/// Validate a presented resume against the chain, the caller, and the ledger.
///
/// Every binding it checks already exists on the envelope: the digest over the
/// whole chain array, the principal fingerprint, the single-use `jti`, the
/// expiry, the held exchange, and the purpose. What is new is `next_step` —
/// present, in range, and the only steps a redemption may skip.
///
/// # Errors
///
/// Refuses a resume presenting a different chain, a different caller, a
/// consumed or expired envelope, a purpose that is not `ChainResume`, a
/// `next_step` outside the sealed chain, or an exchange that has reached
/// [`MAX_CHAIN_ROUNDS`].
pub async fn plan_chain_resume(
    state: &ContinuationState,
    token: &str,
    chain: &[Value],
    principal_fingerprint: &str,
    now: u64,
) -> Result<ChainResumePlan> {
    let _ = (state, token, chain, principal_fingerprint, now);
    unimplemented!("MRTR.12: validate a sealed chain resume and yield the steps it may run")
}

/// Seal the successor envelope for a chain that stopped again at the same step.
///
/// `rounds_used` is incremented and the deadline is copied, never
/// re-initialised: a replacement envelope that reset either would hand a
/// re-asking backend an unbounded sequence of resumable rounds.
#[must_use]
pub fn reseal_chain_resume(previous: &Payload, backend_request_state: Option<String>) -> Payload {
    let _ = (previous, backend_request_state);
    unimplemented!("MRTR.12: carry next_step, rounds_used and the deadline into the next envelope")
}

/// The upstream tool error a malformed interim claim earns.
///
/// Named here so the abort path and its test agree on one spelling of "which
/// step lied", rather than each composing its own.
#[must_use]
pub fn malformed_interim_error(idx: usize, tool_ref: &str) -> Error {
    Error::json_rpc(
        -32603,
        format!(
            "Chain step {idx} ({tool_ref}) returned a malformed interim result: \
             resultType 'input_required' with no usable inputRequests or requestState"
        ),
    )
}
