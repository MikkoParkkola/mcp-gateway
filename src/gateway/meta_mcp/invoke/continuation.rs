// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Continuation minting and retry redemption (MRTR).

use serde_json::{Value, json};
use tracing::warn;

use crate::{Error, Result};

/// Seal one interim exchange into a continuation this caller can redeem, or
/// `None` when it cannot be bound (MRTR.2).
///
/// `None` is a refusal, not a degraded mint. A continuation names who may
/// redeem it, and there is no honest name for a caller the gateway cannot
/// identify: a placeholder would be shared with every other such caller, so the
/// envelope would satisfy its own binding check while binding nothing. See
/// `mrtr::source_fingerprint` for which credential schemes are constructible
/// today (a verified agent, and the stdio client) and why the others are not.
///
/// A keyring refusal — budget exhausted, envelope too large — lands here too,
/// and so does a full in-flight table. The cause is logged and not returned,
/// because the caller can act on none of them: they are properties of this
/// gateway's state, not of the request, and naming them tells a client how
/// close the mint budget is to being spent.
///
/// The exchange is opened on this replica before the envelope is sealed, so the
/// handle that goes out names a slot this process is holding (MRTR.8).
pub(super) async fn mint_continuation(
    continuation: &crate::protocol::continuation::ContinuationState,
    source: crate::protocol::mrtr::PrincipalSource<'_>,
    server: &str,
    tool: &str,
    arguments: &Value,
    backend_request_state: Option<String>,
) -> Option<String> {
    let Some(payload) = continuation
        .begin_exchange(
            server.to_string(),
            backend_request_state,
            crate::protocol::mrtr::source_fingerprint(source)?,
            crate::protocol::mrtr::original_request_digest(server, tool, arguments),
            crate::protocol::continuation::now_unix_secs(),
        )
        .await
    else {
        warn!(server, tool, "No slot to hold this exchange open; refusing");
        record_continuation_mint("no_slot");
        return None;
    };
    match continuation.keyring().mint(&payload) {
        Ok(envelope) => {
            record_continuation_mint("ok");
            Some(envelope)
        }
        Err(error) => {
            warn!(server, tool, %error, "Continuation mint refused");
            record_continuation_mint(continuation_error_reason(&error));
            None
        }
    }
}

/// The refusal for an interim exchange this gateway cannot bind to its caller
/// (MRTR.2).
///
/// `-32003` is the gateway's existing "Forbidden", reused rather than minted:
/// this is a refusal to proceed, and the client has done nothing it could undo.
/// Deliberately *not* `-32021`: that code invites the client to declare a
/// capability and retry, and no declaration makes an unnameable caller
/// nameable, so pointing at one would be a lie the client would act on.
///
/// One message for every cause. A client that could tell "we cannot name you"
/// from "our mint budget is spent" learns the gateway's internal state from a
/// call it was refused; the distinction is in the log, where the operator who
/// can act on it will look.
pub(super) fn unbindable_continuation(server: &str, tool: &str) -> Error {
    Error::JsonRpc {
        code: -32003,
        message: format!(
            "Tool '{tool}' on server '{server}' asked for input, but this exchange cannot be \
             continued for this caller"
        ),
        data: None,
    }
}

/// What a retry sends the backend beside `arguments` (MRTR.1).
///
/// A second type rather than reusing [`crate::protocol::mrtr::RetryFields`].
/// That one is inbound and attacker-controlled, and its `request_state` is this
/// gateway's own envelope; what goes upstream is the state the *backend*
/// issued, unsealed from inside it. One struct for both directions is how a
/// client-supplied string reaches a backend as if the gateway had issued it.
#[derive(Debug, Default)]
pub(super) struct OutboundRetry {
    /// The backend's own opaque state, or `None` when it issued none.
    pub(super) request_state: Option<String>,
    /// The client's answers, verbatim.
    pub(super) input_responses: Option<Value>,
}

impl OutboundRetry {
    /// Add whatever this retry carries beside `name` and `arguments`.
    ///
    /// Beside, never inside: the specification makes both fields siblings of
    /// `arguments`, so a tool whose own argument is called `requestState` keeps
    /// it, and a backend reads ours where it is looking for it.
    ///
    /// An absent field is left absent rather than sent empty. A backend is
    /// entitled to read the presence of `requestState` as meaning something,
    /// and a server that issued no state never sent one to echo.
    pub(super) fn apply(&self, params: &mut Value) {
        let Some(object) = params.as_object_mut() else {
            return;
        };
        if let Some(state) = &self.request_state {
            object.insert("requestState".to_string(), json!(state));
        }
        if let Some(responses) = &self.input_responses {
            object.insert("inputResponses".to_string(), responses.clone());
        }
    }
}

/// The refusal for a continuation this gateway will not redeem (MRTR.3).
///
/// One sentence for every cause, taken from [`ContinuationError`] itself rather
/// than written here: a caller able to tell a forged tag from a spent handle
/// from a passed deadline can map the keyring one probe at a time, and can do
/// nothing differently with any of them. The cause reaches the operator through
/// the log, where it can be acted on.
pub(super) fn rejected_continuation(
    reason: &crate::protocol::continuation::ContinuationError,
) -> Error {
    Error::JsonRpc {
        code: -32602,
        message: reason.client_message().to_string(),
        data: None,
    }
}

/// Stable, low-cardinality tag for a [`ContinuationError`], for metrics and
/// structured logs — never the client, which gets `client_message()`.
/// `UnknownVersion`/`UnknownKey` drop their payload here: a build supports a
/// handful of wire versions and a keyring holds a handful of live keys, but a
/// metric label is not where that bound should be re-proven, so the tag names
/// the cause, not the value.
pub(super) fn continuation_error_reason(
    reason: &crate::protocol::continuation::ContinuationError,
) -> &'static str {
    use crate::protocol::continuation::ContinuationError;
    match reason {
        ContinuationError::Malformed => "malformed",
        ContinuationError::UnknownVersion(_) => "unknown_version",
        ContinuationError::UnknownKey(_) => "unknown_key",
        ContinuationError::NotAuthentic => "not_authentic",
        ContinuationError::Expired => "expired",
        ContinuationError::MintBudgetExhausted => "mint_budget_exhausted",
        ContinuationError::TooLarge => "too_large",
        ContinuationError::LifetimeExceeded => "lifetime_exceeded",
    }
}

/// Count one continuation mint outcome (NFR.OBS.4). `reason` is `"ok"` for a
/// successful mint, [`continuation_error_reason`] for a keyring refusal, or a
/// call-site tag for a refusal with no `ContinuationError` of its own (a full
/// in-flight table refuses before the keyring is ever asked).
pub(super) fn record_continuation_mint(reason: &'static str) {
    telemetry_metrics::counter!("continuation_mint_total", "reason" => reason).increment(1);
}

/// Count one continuation rejection (NFR.OBS.4), and fold it into the expiry
/// signal when the cause is a deadline that has already passed. `reason` is
/// the real [`ContinuationError`] tag where one was returned, or a call-site
/// tag for a cause this module synthesizes rather than forwards: MRTR.2 and
/// MRTR.6 deliberately collapse several causes into one client message so a
/// caller cannot map the keyring or the in-flight table one probe at a time —
/// the metric keeps them apart for the operator that collapse was never meant
/// to blind.
pub(super) fn record_continuation_rejection(reason: &'static str) {
    telemetry_metrics::counter!("continuation_rejection_total", "reason" => reason).increment(1);
    if reason == "expired" {
        // A client presenting a stale envelope. Counted apart from the
        // in-flight table's own eviction of an aged-out exchange
        // (`reclaim_abandoned`, `continuation.rs`, `reason="hold_evicted"`
        // under NFR.OBS.4) by `reason`, not by a second counter.
        //
        // The two are observation points, not disjoint causes: a client that
        // returns too late is refused here AND has its hold evicted by the
        // next reader, so one continuation can raise both. Neither count is a
        // population of continuations, and summing them double-counts.
        telemetry_metrics::counter!("continuation_expiry_total", "reason" => "deadline_passed")
            .increment(1);
    }
}

/// Which backend holds the exchange a retry continues (MRTR.6).
///
/// `None` when the call carries no continuation at all — an ordinary call,
/// routed by its name like any other. `Some` otherwise, because a retry names
/// the *backend* tool it continues, and a backend tool is reachable by its own
/// name only where an operator surfaced it: routing a retry by name would
/// refuse every honest one on a tool nobody pinned. The route therefore comes
/// from the envelope this gateway minted, which is the one value in a retry a
/// client cannot author.
///
/// Only the route comes from here. The presented name and arguments are still
/// checked against the digest sealed inside the same envelope, downstream in
/// [`redeem_retry`] — that check, not this one, is what refuses a handle
/// replayed against another tool.
pub(in crate::gateway::meta_mcp) fn retry_origin_backend(
    continuation: &crate::protocol::continuation::ContinuationState,
    retry: &crate::protocol::mrtr::RetryFields,
) -> Option<Result<String>> {
    let token = retry.request_state.as_deref()?;
    let now = crate::protocol::continuation::now_unix_secs();
    let payload = match continuation.keyring().open(token, now) {
        Ok(payload) => payload,
        Err(error) => {
            warn!(%error, "Continuation refused before routing");
            record_continuation_rejection(continuation_error_reason(&error));
            return Some(Err(rejected_continuation(&error)));
        }
    };
    // A destructive confirmation continues no backend exchange: this gateway
    // asked the question and its own gate reads the answer. `None` already
    // means "nothing to route", which is exactly true here — routing it would
    // hand the answer to a backend named after a meta-tool, and the gate that
    // must see it would never run.
    //
    // A chain resume is the same shape for the same reason: the envelope
    // licenses the chain driver to run `chain[next_step..]`, and the step it
    // resumes is named by the sealed `next_step`, not by the tool the client
    // called. Routing it by `backend_id` would dispatch the pending step's
    // backend with the whole chain array as its arguments and skip every
    // binding `plan_chain_resume` exists to check.
    if matches!(
        payload.purpose,
        crate::protocol::continuation::ContinuationPurpose::DestructiveConfirm
            | crate::protocol::continuation::ContinuationPurpose::ChainResume
    ) {
        return None;
    }
    Some(Ok(payload.backend_id))
}

/// Open the continuation a retry presents and recover what the backend gets
/// (MRTR.1, MRTR.3-5).
///
/// Not a retry — neither field present — yields an empty [`OutboundRetry`], and
/// the call proceeds as the fresh one it is.
///
/// Answers with no envelope are carried, not refused: the specification lets a
/// server ask for input without state of its own, so there is nothing to open
/// and nothing a binding check could be performed against.
///
/// The continuation is spent the moment it opens, before the dispatch it
/// authorises. Spending it on success instead would leave it redeemable again
/// to anyone who can make a dispatch fail, which is the replay this ledger
/// exists to close.
pub(super) async fn redeem_retry(
    continuation: &crate::protocol::continuation::ContinuationState,
    (source, retry): (
        crate::protocol::mrtr::PrincipalSource<'_>,
        &crate::protocol::mrtr::RetryFields,
    ),
    server: &str,
    tool: &str,
    arguments: &Value,
) -> Result<OutboundRetry> {
    use crate::protocol::continuation::ContinuationError;

    let input_responses = retry.solicited_input_responses()?;
    let Some(token) = retry.request_state.as_deref() else {
        return Ok(OutboundRetry {
            request_state: None,
            input_responses,
        });
    };

    let now = crate::protocol::continuation::now_unix_secs();
    let payload = continuation.keyring().open(token, now).map_err(|error| {
        warn!(server, tool, %error, "Continuation refused");
        record_continuation_rejection(continuation_error_reason(&error));
        rejected_continuation(&error)
    })?;

    // Which domain the envelope was sealed for, before anything is read out of
    // it and before the hold or the ledger is touched.
    //
    // One keyring and one ledger serve two domains — this one, and the
    // destructive confirmation a task-augmented call is admitted through. An
    // envelope minted for the other one is *authentic*, so authentication
    // cannot refuse it; only its purpose can. Checked first so a wrong-domain
    // envelope cannot spend the hold or the redemption belonging to the
    // exchange whose `jti` and `hold_key` it happens to carry: a refusal that
    // arrived after either would leave the caller's own honest retry with
    // nothing left to redeem.
    payload
        .require_purpose(crate::protocol::continuation::ContinuationPurpose::BackendInput)
        .map_err(|error| {
            warn!(
                server,
                tool, "Continuation from another domain presented as a backend retry"
            );
            record_continuation_rejection("wrong_purpose");
            rejected_continuation(&error)
        })?;

    // The same fingerprint the mint bound to, derived the same way — both read
    // the caller's `principal_source()`. A caller the gateway cannot name cannot match
    // one it could: `source_fingerprint` returns `None` for exactly the
    // credential schemes no continuation is ever minted for, so there is no
    // handle here for such a caller to hold.
    let Some(fingerprint) = crate::protocol::mrtr::source_fingerprint(source) else {
        warn!(
            server,
            tool, "Retry from a caller no continuation can be bound to"
        );
        record_continuation_rejection("unidentifiable_caller");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    };
    payload
        .redeemable_by(
            &fingerprint,
            &crate::protocol::mrtr::original_request_digest(server, tool, arguments),
        )
        .map_err(|error| {
            warn!(server, tool, %error, "Continuation not redeemable by this caller");
            record_continuation_rejection(continuation_error_reason(&error));
            rejected_continuation(&error)
        })?;

    // MRTR.6: the exchange this handle continues must still be open, here. The
    // table is written only by this process's own mint, so a retry that reaches
    // a replica which did not mint it asks a table that never knew the key —
    // and one whose exchange has since ended asks a table that no longer does.
    // Both answer `Gone`, and both must refuse rather than dispatch: dispatching
    // would open a *second* exchange with a legacy backend, leaving the first
    // hanging and asking the user the same question twice.
    //
    // Checked before the handle is spent. A retry the gateway cannot honour
    // should not also burn the client's one redemption.
    if continuation.in_flight().route(&payload.hold_key, now).await
        == crate::protocol::continuation::Routing::Gone
    {
        warn!(
            server,
            tool, "Retry for an exchange this replica no longer holds"
        );
        record_continuation_rejection("hold_gone");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    }

    if !continuation
        .ledger()
        .consume(&payload.jti, payload.expires_at, now)
        .await
    {
        // Already spent, or the ledger is full and refuses rather than forgets.
        // One answer for both: a client can act on neither, and telling them
        // apart reports whether another caller has just redeemed a handle.
        warn!(
            server,
            tool, "Continuation already spent or ledger at capacity"
        );
        record_continuation_rejection("ledger_spent_or_full");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    }

    // The exchange ends here: this retry carries the answers it was waiting for.
    // Releasing the slot is what keeps capacity a measure of exchanges still
    // open rather than of every exchange ever started, and it is what makes the
    // refusal above true of a handle redeemed twice.
    continuation
        .in_flight()
        .complete(&payload.hold_key, now)
        .await;
    telemetry_metrics::counter!("continuation_redeem_total", "reason" => "ok").increment(1);

    Ok(OutboundRetry {
        request_state: payload.backend_request_state,
        input_responses,
    })
}

/// The tool and the argument object a direct-route `tools/call` names: the two
/// parts of the request a continuation is bound to (MIK-8078). Read from the
/// params as the client sent them, at the mint and at the redeem alike, so a
/// sanitized copy can never make the two digests disagree.
fn direct_call_parts(params: Option<&Value>) -> (&str, Value) {
    let tool = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    (tool, arguments)
}

impl crate::gateway::meta_mcp::MetaMcp {
    /// MRTR.1 and MRTR.3-6 on the direct route `POST /mcp/{name}` (MIK-8078):
    /// open the continuation a `tools/call` presents and put the backend's own
    /// state in `outbound` in its place.
    ///
    /// The same checks, in the same order, as the meta route's
    /// [`redeem_retry`]: authentic, sealed for a backend input round, bound to
    /// this caller and this call, still held here, and spent once. A call with
    /// neither retry field is left as it is.
    ///
    /// `sent` is the params as the client sent them; `outbound` is what goes
    /// upstream (the sanitized copy, or a copy of `sent`).
    ///
    /// # Errors
    ///
    /// `-32602` for a continuation this gateway will not redeem, or for
    /// answers that present none.
    pub(crate) async fn redeem_direct_retry(
        &self,
        identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        (server, sent): (&str, Option<&Value>),
        outbound: &mut Value,
    ) -> Result<()> {
        let retry = crate::protocol::mrtr::RetryFields::from_params(sent);
        let (tool, arguments) = direct_call_parts(sent);
        let source = crate::protocol::mrtr::PrincipalSource::Credential(identity);
        let redeemed = redeem_retry(
            &self.continuation,
            (source, &retry),
            server,
            tool,
            &arguments,
        )
        .await?;
        if retry.request_state.is_some()
            && let Some(object) = outbound.as_object_mut()
        {
            // The client's envelope never travels upstream: the backend gets
            // the state it issued, or none if it kept none.
            object.remove("requestState");
            redeemed.apply(outbound);
        }
        Ok(())
    }

    /// MRTR.2 on the direct route `POST /mcp/{name}` (MIK-8078): seal an
    /// interim answer's state into a continuation bound to this caller and this
    /// call, as the meta route does. An answer that is not interim is left as
    /// it is.
    ///
    /// # Errors
    ///
    /// `-32003` when no continuation can be bound to this caller, or the mint
    /// is refused: the backend's own state is never sent in its place.
    pub(crate) async fn seal_direct_interim(
        &self,
        identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        (server, sent): (&str, Option<&Value>),
        result: &mut Value,
    ) -> Result<()> {
        let Some(interim) = crate::protocol::mrtr::InputRequired::from_result(result) else {
            return Ok(());
        };
        let (tool, arguments) = direct_call_parts(sent);
        let source = crate::protocol::mrtr::PrincipalSource::Credential(identity);
        let Some(envelope) = mint_continuation(
            &self.continuation,
            source,
            server,
            tool,
            &arguments,
            interim.request_state,
        )
        .await
        else {
            warn!(
                server,
                tool, "Cannot mint a continuation for this direct-route caller; refusing"
            );
            return Err(unbindable_continuation(server, tool));
        };
        result["requestState"] = json!(envelope);
        super::gateway_writes::note(
            super::gateway_writes::Layer::Value,
            super::gateway_writes::REQUEST_STATE,
            result,
        );
        Ok(())
    }
}
