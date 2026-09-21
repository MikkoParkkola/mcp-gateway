// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The destructive-action confirmation gate, split out of `mod.rs` so that
//! file stays under the file-size ceiling.

use super::{JsonRpcResponse, MetaMcpCallerContext, RequestId, Value, json, warn};

/// Destructive-action confirmation. NOT the control -- the admin
/// requirement is, and `gateway_kill_server`, the only tool carrying
/// `destructiveHint: true`, is in the admin set. This is the prompt an
/// honest client shows its user before proceeding.
///
/// Enforced HERE for the same reason as the admin gate above: it lived
/// on the HTTP edge, so a transport that never ran that code was not
/// refused, it was unjudged. Whether an operator can be asked is a
/// property of the transport, and the transport says so in
/// `caller.confirmation` rather than being inferred here.
///
/// Deliberately not labelled OWASP ASI09. An earlier version was, and
/// `destructive_confirmation`'s own header was corrected to say why: the
/// citation reads as a control and invites over-trust in a prompt a
/// client may simply not support.
///
/// The one place a confirmation refusal is built.
///
/// Both refusal branches — nobody could be asked, and an operator who said no
/// — must carry `confirmation_refusal`, and each used to set it for itself.
/// Two sites owning one invariant is how one of them loses it in a later edit,
/// and the loss is silent: the response still looks right on the wire, and the
/// caller quietly starts accruing failures for a control working as designed.
/// Making the marker a property of the constructor removes the way they can
/// disagree rather than adding a check that they have not.
pub(super) fn confirmation_refusal_response(id: &RequestId, message: String) -> JsonRpcResponse {
    let mut response = JsonRpcResponse::error(Some(id.clone()), -32001, message);
    // The marker is internal and never reaches the wire; the accounting tail
    // reads it to tell a refusal apart from a client failure.
    response.confirmation_refusal = true;
    response
}

/// The request key the in-band confirmation is asked under, and the only key an
/// answer is read from.
///
/// The version travels in the key, not in a new envelope field: a `v2` question
/// can then coexist with this one and an old client's answer is never ambiguous
/// about which question it answers
/// (`docs/design/2026-09-09-confirm-2-in-band-schema-and-wiring.md:44-60`).
/// Spelled once — a second spelling is a discriminator that can disagree with
/// itself.
pub(super) const CONFIRMATION_INPUT_KEY: &str = "io.mcp-gateway.destructive-confirmation.v1";

/// Who a confirmation envelope is bound to.
///
/// `principal_fingerprint` answers `None` for a modern stateless caller: that
/// path authenticates by API key and the fingerprint is written for a verified
/// backend exchange. Minting on `None` would bind the envelope to nobody, and
/// refusing on `None` would leave the in-band ask unreachable on the one
/// transport it exists to serve — so the API-key *name* is the fallback. It
/// grants nothing new: it is the same authority the admin gate accepted one
/// frame earlier for this very call, sealing a caller to its own answer to a
/// question this gateway just asked it. A caller with neither is still refused.
pub(super) fn confirmation_principal(caller: &MetaMcpCallerContext<'_>) -> Option<String> {
    crate::protocol::mrtr::principal_fingerprint(caller.verified_identity).or_else(|| {
        caller
            .api_key_name
            .map(|name| crate::hashing::sha256_hex(format!("apikey-name:{name}").as_bytes()))
    })
}

/// Which call a confirmation authorises.
///
/// One function because the mint and the redemption must agree exactly; two
/// spellings of the same pair is how a digest silently stops matching. The
/// gateway answers its own meta-tools, so it is both the server and the tool.
pub(super) fn confirmation_digest(tool_name: &str, arguments: &Value) -> String {
    crate::protocol::mrtr::original_request_digest(tool_name, tool_name, arguments)
}

/// Spend the envelope an in-band confirmation was asked on.
///
/// `Err` means the envelope is unusable for any reason — forged, expired,
/// wrong domain, bound to another caller or call, already spent, or naming an
/// exchange this replica no longer holds. One shape for all of them: a caller
/// that could tell them apart could map gateway state one probe at a time, and
/// the answer to every one of them is to ask again.
///
/// Same order as `invoke::redeem_retry`, for the same reasons — purpose before
/// anything is read out of the payload, so an envelope from the backend domain
/// cannot spend the hold or the redemption belonging to the exchange whose
/// `jti` it happens to carry; binding before the ledger, so a handle this
/// gateway will not honour does not burn the caller's one redemption. Not that
/// function, because the principal differs: it derives the stricter
/// `principal_fingerprint`, which refuses exactly the API-key caller this
/// domain must bind (see `confirmation_principal`).
///
/// `std::result::Result` spelled out because this module's bare `Result` is the
/// crate alias, which fixes the error type and cannot carry the `()` this needs.
pub(super) async fn redeem_confirmation(
    continuation: &crate::protocol::continuation::ContinuationState,
    token: &str,
    principal: &str,
    digest: &str,
) -> std::result::Result<(), ()> {
    use crate::protocol::continuation::{ContinuationPurpose, now_unix_secs};

    let now = now_unix_secs();
    let payload = continuation.keyring().open(token, now).map_err(|error| {
        warn!(%error, "Confirmation envelope refused");
    })?;
    payload
        .require_purpose(ContinuationPurpose::DestructiveConfirm)
        .map_err(|_| {
            warn!("Continuation from another domain presented as a confirmation");
        })?;
    payload.redeemable_by(principal, digest).map_err(|error| {
        warn!(%error, "Confirmation not redeemable by this caller");
    })?;
    // Single use, and spent before the answer is read rather than after it is
    // acted on: a handle still redeemable afterwards is one an operator's "no"
    // can be replayed past.
    if !continuation
        .ledger()
        .consume(&payload.jti, payload.expires_at, now)
        .await
    {
        warn!("Confirmation envelope already spent");
        return Err(());
    }
    continuation
        .in_flight()
        .complete(&payload.hold_key, now)
        .await;
    Ok(())
}

/// The gate's three answers.
///
/// Three rather than an `Option<JsonRpcResponse>`, because a confirmed retry is
/// not the same as an ungoverned call: it carries a `requestState` the caller
/// echoed back, and the routing that reads one belongs to the backend path, not
/// to a meta-tool the gateway itself executes.
pub(super) enum GateOutcome {
    /// The call does not run. This is the answer to send.
    Refuse(Box<JsonRpcResponse>),
    /// Nothing to confirm, or confirmation obtained out of band. Dispatch
    /// normally.
    Proceed,
    /// A retry whose in-band confirmation was opened and spent here.
    ProceedConfirmed,
}

impl GateOutcome {
    /// The boxing lives here so the arms below read as what they answer.
    ///
    /// The accounting marker is set here rather than by each arm, because every
    /// arm owes it for the same reason: the destructive action did not run, so
    /// neither a strike nor a success reset describes what happened. The
    /// in-band ask is a success frame and would otherwise reset a breaker the
    /// caller had genuinely tripped.
    fn refuse(mut response: JsonRpcResponse) -> Self {
        response.confirmation_refusal = true;
        Self::Refuse(Box::new(response))
    }
}

/// Whether the call may run, and if so whether it spent a confirmation here.
///
/// Long by construction: one arm per `ConfirmationChannel` variant, and each
/// arm's refusal is only meaningful next to the others it is not.
#[expect(clippy::too_many_lines, reason = "one arm per confirmation channel")]
pub(super) async fn destructive_confirmation_gate(
    id: &RequestId,
    tool_name: &str,
    arguments: &Value,
    session_id: Option<&str>,
    caller: &MetaMcpCallerContext<'_>,
) -> GateOutcome {
    use crate::gateway::destructive_confirmation::{
        ConfirmationChannel, ConfirmationOutcome, ConfirmationPolicy, describe_destructive_action,
        require_destructive_confirmation,
    };

    if !crate::gateway::destructive_confirmation::is_destructive_meta_tool(tool_name) {
        return GateOutcome::Proceed;
    }

    let action_desc = describe_destructive_action(tool_name, arguments);
    let refused = |desc: &str| {
        warn!(
            tool = %tool_name,
            "refusing a destructive call that cannot be confirmed"
        );
        confirmation_refusal_response(
            id,
            format!(
                "Destructive action requires confirmation and none could be obtained: \
                     {desc}"
            ),
        )
    };

    match caller.confirmation {
        // No asker can exist on this transport. Nothing is elicited:
        // there is no one to elicit from, and producing an "unsupported"
        // outcome would only re-enter a policy written for a channel
        // that does exist.
        ConfirmationChannel::Unavailable => return GateOutcome::refuse(refused(&action_desc)),
        ConfirmationChannel::Elicit { proxy, policy } => {
            let outcome = require_destructive_confirmation(
                proxy,
                session_id.unwrap_or_default(),
                &action_desc,
            )
            .await;
            if outcome == ConfirmationOutcome::Declined {
                // A decline is the operator using the control, not the
                // client failing. Before this gate moved into the
                // dispatcher a decline returned earlier than the
                // accounting and was never counted; marking it keeps
                // that true, so exercising the safety control cannot
                // walk a caller toward a tripped breaker.
                return GateOutcome::refuse(confirmation_refusal_response(
                    id,
                    format!("Operator declined: {action_desc}"),
                ));
            }
            // Nobody could be asked. What that means depends on the era,
            // and the policy was decided at the edge that knows which era
            // this request belongs to.
            if outcome == ConfirmationOutcome::Unsupported
                && policy.on_unconfirmable() == ConfirmationPolicy::REFUSE
            {
                return GateOutcome::refuse(refused(&action_desc));
            }
        }
        // The asker is the caller itself, one round-trip away: the gate answers
        // the call with an `input_required` result and the caller confirms by
        // retrying with the answer.
        //
        // Redemption is tried BEFORE minting. The other order never reads the
        // answer the caller just sent, mints a second question instead, and
        // turns the ask into an unbounded loop — strictly worse than the honest
        // refusal it replaces.
        ConfirmationChannel::InBand { continuation } => {
            let Some(principal) = confirmation_principal(caller) else {
                return GateOutcome::refuse(refused(&action_desc));
            };
            let digest = confirmation_digest(tool_name, arguments);

            if let Some(token) = caller.retry.request_state.as_deref() {
                if redeem_confirmation(continuation, token, &principal, &digest)
                    .await
                    .is_err()
                {
                    return GateOutcome::refuse(refused(&action_desc));
                }
                // Only JSON `true` confirms. Absent, `false`, `"yes"`, `1` —
                // all decline, fail-closed. A malformed answer is deliberately
                // not a protocol error: an error would hand a caller a way to
                // turn a decline into a retryable condition.
                if caller
                    .retry
                    .input_responses
                    .as_ref()
                    .and_then(|answers| answers.get(CONFIRMATION_INPUT_KEY))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    return GateOutcome::ProceedConfirmed;
                }
                return GateOutcome::refuse(confirmation_refusal_response(
                    id,
                    format!("Operator declined: {action_desc}"),
                ));
            }

            let Some(payload) = continuation
                .begin_confirmation_exchange(
                    tool_name.to_owned(),
                    // A confirmation continues no backend exchange, so there is
                    // no backend state to carry. Absent rather than empty: an
                    // empty string is a state some backend never issued.
                    None,
                    principal,
                    digest,
                    crate::protocol::continuation::now_unix_secs(),
                )
                .await
            else {
                warn!(tool = %tool_name, "No slot to hold this confirmation open");
                return GateOutcome::refuse(refused(&action_desc));
            };
            let Ok(envelope) = continuation.keyring().mint(&payload) else {
                warn!(tool = %tool_name, "Confirmation envelope mint refused");
                return GateOutcome::refuse(refused(&action_desc));
            };
            return GateOutcome::refuse(JsonRpcResponse::success(
                id.clone(),
                json!({
                    "resultType": "input_required",
                    "inputRequests": {
                        CONFIRMATION_INPUT_KEY: {
                            "type": "boolean",
                            "title": "Confirm destructive action",
                            "description": action_desc,
                        },
                    },
                    "requestState": envelope,
                }),
            ));
        }
    }
    GateOutcome::Proceed
}
