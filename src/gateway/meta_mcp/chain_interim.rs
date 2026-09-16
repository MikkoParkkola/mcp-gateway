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

use std::future::Future;

use serde_json::{Value, json};

use crate::protocol::continuation::{
    ContinuationError, ContinuationPurpose, ContinuationState, Payload, Routing,
};
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
    if !InputRequired::claims_input_required(result) {
        return Ok(None);
    }
    InputRequired::from_result(result)
        .map(Some)
        .ok_or_else(|| malformed_interim_error(idx, tool_ref))
}

/// Run `chain[start_step..]`, stopping at the first validated interim round.
///
/// `run_step` performs one step; `seal_stop` seals the [`ContinuationPurpose::ChainResume`]
/// envelope for a stop and yields the token that travels in the response.
/// Injected rather than reached for, so that what did and did not run is
/// observable — the invariant a chain stop exists to protect is about the
/// successor that must not execute, and nothing in a returned value shows that.
///
/// `run_step` is async and takes its arguments owned. The live caller invokes a
/// backend, so a synchronous callback could not express it, and the seam this
/// driver exists to hold would be a second loop beside the one that ships.
/// Owned arguments keep the returned future free of borrows from the loop,
/// which is what lets the caller write a plain `async move` block.
///
/// The caller labels its own failures. A step error travels out of `run_step`
/// already carrying its step index and its kind — a refusal must stay a refusal
/// rather than arriving as an internal error — so this driver propagates rather
/// than rewraps.
///
/// [`ContinuationPurpose::ChainResume`]: crate::protocol::continuation::ContinuationPurpose::ChainResume
///
/// # Errors
///
/// Propagates a step's own failure, and returns an upstream tool error for a
/// malformed interim claim.
pub async fn drive_chain<R, F>(
    chain: &[Value],
    start_step: usize,
    mut run_step: R,
    mut seal_stop: impl FnMut(usize, &InputRequired) -> Result<String>,
) -> Result<Value>
where
    R: FnMut(usize, String, Value) -> F,
    F: Future<Output = Result<Value>>,
{
    let mut completed: Vec<Value> = Vec::new();
    for (idx, step) in chain.iter().enumerate().skip(start_step) {
        // A step with no tool reference is refused, never run under an empty
        // name: every other refusal in this module fails closed, and a chain
        // that silently skips an unnamed step still runs its successors.
        let tool_ref = step
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::json_rpc(-32602, format!("Chain step {idx}: missing 'tool' field"))
            })?
            .to_string();
        // An empty object, not `null`: the live loop this replaces defaults the
        // same way, and a backend whose `inputSchema` requires an object refuses
        // `null`. A driver that changed the default would turn a wiring change
        // into a behaviour change for every step that omits the field.
        let arguments = step.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let result = run_step(idx, tool_ref.clone(), arguments).await?;

        // Classified before the result is recorded, so a step that asked is
        // never pushed as an answer — the whole defect is one `Ok` treated as
        // two different things.
        let Some(round) = classify_step_result(idx, &tool_ref, &result)? else {
            completed.push(json!({"step": idx, "tool": tool_ref, "result": result}));
            continue;
        };

        // The token replaces the backend's own `requestState` in the response.
        // The backend's state is authorization it issued to us, not to the
        // caller; it travels sealed inside the envelope, and what the caller
        // echoes is the handle that carries it back.
        let request_state = seal_stop(idx, &round)?;
        return Ok(json!({
            "resultType": "input_required",
            "pendingStep": idx,
            "pendingTool": tool_ref,
            "inputRequests": round
                .requests
                .iter()
                .cloned()
                .collect::<serde_json::Map<String, Value>>(),
            "requestState": request_state,
            "steps": completed.len(),
            "results": completed,
        }));
    }
    Ok(json!({"steps": completed.len(), "results": completed}))
}

/// What the chain digest binds: the whole chain array, canonically.
///
/// Over the array rather than the step a resume starts at, because the binding
/// exists to stop a substituted *successor* — the steps `next_step` licenses
/// the gateway to run without the caller presenting them again.
fn chain_digest(chain: &[Value]) -> String {
    let canonical = crate::hashing::canonical_json(&json!(chain));
    crate::hashing::sha256_hex_chunks([canonical.as_bytes()])
}

/// The refusal a presented resume earns, in the spelling `invoke.rs` uses for
/// the backend-input domain: the client learns it cannot redeem, never which
/// binding told us so.
fn refused(reason: &ContinuationError) -> Error {
    Error::json_rpc(-32602, reason.client_message())
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
    let payload = state
        .keyring()
        .open(token, now)
        .map_err(|reason| refused(&reason))?;

    // Purpose first, for the reason `invoke.rs` gives at its own redemption:
    // an envelope minted for another domain is *authentic*, so only its purpose
    // can refuse it, and a refusal arriving after the hold or the ledger was
    // touched would spend what the exchange it really belongs to still needs.
    payload
        .require_purpose(ContinuationPurpose::ChainResume)
        .map_err(|reason| refused(&reason))?;
    payload
        .redeemable_by(principal_fingerprint, &chain_digest(chain))
        .map_err(|reason| refused(&reason))?;

    // `next_step` is the index of the step that asked, so the chain must still
    // contain it. `chain.len()` is already past the end: it names a step that
    // never existed, not a resume with nothing left to run.
    let Some(next_step) = payload.next_step.filter(|step| *step < chain.len()) else {
        return Err(refused(&ContinuationError::NotAuthentic));
    };

    // Before the hold and the ledger, and unlike them it is worth naming: a
    // caller that has hit the cap can stop presenting the handle, which is
    // exactly what a generic refusal would leave it retrying.
    if payload.rounds_used >= MAX_CHAIN_ROUNDS {
        return Err(Error::json_rpc(
            -32602,
            format!(
                "This chain exchange has used its {MAX_CHAIN_ROUNDS} interim rounds; \
                 start it again rather than answering once more"
            ),
        ));
    }

    // MRTR.6, unchanged for this domain: the exchange must still be open, here.
    // A key the table never knew and one whose exchange has ended both answer
    // `Gone`, and both refuse before the redemption is spent.
    if state.in_flight().route(&payload.hold_key, now).await == Routing::Gone {
        return Err(refused(&ContinuationError::NotAuthentic));
    }

    // Last, so nothing above burns the caller's one redemption.
    if !state
        .ledger()
        .consume(&payload.jti, payload.expires_at, now)
        .await
    {
        return Err(refused(&ContinuationError::NotAuthentic));
    }

    Ok(ChainResumePlan {
        next_step,
        rounds_used: payload.rounds_used,
    })
}

/// Seal the envelope a chain stop hands back, from the one the step already has.
///
/// `previous` is whatever envelope the stopping step arrived with: the
/// step-scoped one `invoke.rs` minted for a first stop, or the chain envelope
/// from the resume that ran the step when it asks again. Both are re-sealed
/// rather than replaced, because the hold that `begin_exchange` opened is
/// already in `previous` — minting a second envelope would open a second
/// exchange for a backend that is holding one.
///
/// Three fields are set rather than carried, and each is what makes the result
/// a *chain* resume: the purpose, so an envelope minted for one step cannot be
/// redeemed as a licence to run a chain; the digest over the whole chain, so a
/// resume presenting different steps is refused; and `next_step`, which is the
/// step that asked and not the one `previous` happened to name.
///
/// `rounds_used` is incremented and the deadline is copied, never
/// re-initialised: a replacement envelope that reset either would hand a
/// re-asking backend an unbounded sequence of resumable rounds.
#[must_use]
pub fn seal_chain_stop(
    previous: &Payload,
    chain: &[Value],
    next_step: usize,
    backend_request_state: Option<String>,
) -> Payload {
    Payload {
        backend_request_state,
        purpose: ContinuationPurpose::ChainResume,
        original_request_digest: chain_digest(chain),
        next_step: Some(next_step),
        // A fresh handle. The `jti` that reached this re-ask was consumed by
        // the redemption that ran the step, so carrying it forward would seal
        // an envelope the ledger has already retired.
        jti: uuid::Uuid::new_v4().to_string(),
        rounds_used: previous.rounds_used.saturating_add(1),
        ..previous.clone()
    }
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
