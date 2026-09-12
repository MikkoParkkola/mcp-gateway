// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Destructive confirmation for a task-augmented call, in the modern era.
//!
//! The legacy gate (`gateway::destructive_confirmation`) asks an SSE session a
//! question and waits for the answer inside the call. A modern request has no
//! session to ask through and no call to wait in: the revision replaced
//! server-initiated requests with an interim result the client *retries*. So a
//! destructive call is answered here with `input_required` and a sealed grant,
//! and the work happens on the retry that carries that grant back.
//!
//! Three properties hold this together, and each is a property because the
//! alternative is a gate that can be walked past:
//!
//! * **Nothing is claimed by the question.** A challenge mints no task, reaches
//!   no backend and reserves no idempotency key. A refusal does the same. The
//!   caller's key is still free for the operation it does mean to run.
//! * **The grant is bound to one call, not to a caller.** The sealed envelope
//!   carries a digest over the outer tool name, its arguments, the `task`
//!   member and the idempotency key, beside the owner fingerprint the
//!   continuation layer already binds. Change any of them and the retry is a
//!   different request presenting someone else's grant.
//! * **The domain is sealed, not assumed.** The envelope is
//!   [`Purpose::DestructiveConfirm`]; a backend-elicitation envelope cannot
//!   authorise a destructive task, and this one cannot continue a backend
//!   exchange (`meta_mcp::invoke::redeem_retry` refuses it before it touches
//!   the hold or the spent ledger).
//!
//! The acceptance key is the gateway's own, derived from the `jti` sealed
//! inside the envelope. A fixed key would let a client answer a question it was
//! never asked; a client-chosen one would let it answer its own.

use serde_json::{Value, json};
use tracing::warn;

use crate::gateway::task_service::OwnedAdmissionRequest;
use crate::hashing::{canonical_json, sha256_hex};
use crate::idempotency::admission::ExecutionAdmission;
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::continuation::{Payload, Purpose, now_unix_secs};
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::{RetryFields, principal_fingerprint};
use crate::protocol::{JsonRpcResponse, RequestId};

use super::MetaMcp;

mod helpers;
pub(crate) use helpers::task_admission_request;
use helpers::{challenge_key, cleared, operation_digest, record, refuse, refuse_grant};

/// The interim `resultType` a challenge carries. Spelled once: a second
/// spelling is a discriminator that can disagree with itself.
const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// The method a confirmation is asked with, and the capability the client must
/// have declared to be asked it.
const CONFIRMATION_METHOD: &str = "elicitation/create";

/// The one answer that authorises the call. Per the elicitation contract the
/// other two values are `decline` and `cancel`; anything that is not this is a
/// refusal, including a missing or malformed action.
const ACCEPT: &str = "accept";

/// Domain tag for the operation digest sealed into a grant. Tagged so this
/// digest can never collide with the backend-request digest the same field
/// carries for a [`Purpose::BackendInput`] envelope.
const DIGEST_DOMAIN: &str = "mcp-gateway.destructive-confirmation.v1";

/// What the gate decided.
#[derive(Debug)]
pub(crate) enum TaskConfirmation {
    /// Not a call this gate governs. Dispatch exactly as before.
    NotRequired,
    /// A valid grant was presented. Dispatch with these fields: the
    /// confirmation metadata is stripped, so what reaches admission and the
    /// backend is the original call and nothing this gate added.
    Granted(RetryFields),
    /// Answer the client with this and admit nothing — the challenge, or the
    /// refusal of a grant that does not authorise this call.
    Answer(Box<JsonRpcResponse>),
}

/// One call, as much of it as the gate binds.
///
/// Every field is part of the grant except `admission`, which is consulted
/// read-only for the already-committed replay. Taken as a struct rather than
/// nine parameters so a future binding cannot be added at the definition and
/// forgotten at the call site.
pub(crate) struct TaskConfirmationRequest<'a> {
    /// The JSON-RPC id to answer under.
    pub id: RequestId,
    /// The outer tool name the client called — never a wrapper's target.
    pub tool_name: &'a str,
    /// The outer arguments, as they will be dispatched.
    pub arguments: &'a Value,
    /// The `task` member verbatim, or `None` for an ordinary synchronous call.
    /// `None` is what makes this gate a *task-admission* gate: the synchronous
    /// path keeps the behaviour it has always had.
    pub task: Option<&'a Value>,
    /// The retry pair and idempotency key this call carried, already parsed.
    pub retry: &'a RetryFields,
    /// The strong verified owner. A caller with none is refused rather than
    /// bound weakly — see [`principal_fingerprint`].
    pub verified_identity: Option<&'a VerifiedIdentity>,
    /// What this request declared it can be asked.
    pub input_capabilities: Declared,
    /// Whether the request was written against the modern revision.
    pub is_modern: bool,
    /// The sole admission authority, read-only.
    pub admission: &'a ExecutionAdmission,
}

impl MetaMcp {
    /// Decide a destructive task-augmented call before it is admitted.
    ///
    /// Called after every existing authorization, admin and firewall check and
    /// before task admission, so a refusal here has cost the caller nothing: no
    /// task handle, no backend call, no reserved key.
    pub(crate) async fn confirm_destructive_task(
        &self,
        request: &TaskConfirmationRequest<'_>,
    ) -> TaskConfirmation {
        // Not task-augmented, not modern, or not a truthfully destructive
        // surfaced tool: this gate has nothing to say. The legacy gate still
        // governs the built-in meta-tools it always governed.
        let Some(task) = request.task else {
            return TaskConfirmation::NotRequired;
        };
        if !request.is_modern {
            return TaskConfirmation::NotRequired;
        }
        let Some(backend_id) = self.destructive_surfaced_backend(request.tool_name) else {
            return TaskConfirmation::NotRequired;
        };
        // A keyless call is refused by admission itself, in its own words. A
        // challenge here would ask a question whose answer could never be
        // admitted.
        let Some(key) = request.retry.idempotency_key.as_deref() else {
            return TaskConfirmation::NotRequired;
        };

        let Some(fingerprint) = principal_fingerprint(request.verified_identity) else {
            return refuse(
                request,
                "unbindable_caller",
                -32003,
                "this destructive call cannot be confirmed for a caller this gateway cannot name",
            );
        };
        let digest = operation_digest(request.tool_name, request.arguments, task, key);

        match (
            request.retry.request_state.as_deref(),
            request.retry.input_responses.as_ref(),
        ) {
            // A fresh call: ask, and admit nothing.
            //
            // Unless it is not fresh. A retry that carries no grant — a lost
            // continuation, a job-queue replay, a retry after the grant's five
            // minutes ran out at `keyring().open` — is the same owner, key and
            // operation as work this gateway already admitted, and the answer it
            // needs is the handle it already owns. Asking again would mint a
            // second question for a task that is already running, and the caller
            // would still never be told its id.
            //
            // Nothing is widened by letting it through: the entry consulted
            // exists only because an earlier call for this exact operation
            // passed this gate with a valid grant, and what it is let through
            // to is admission, which returns that task rather than starting
            // one. No hold is taken, no envelope minted, no ledger spent.
            (None, None) => {
                if Self::already_admitted(request, key) {
                    record("admitted_replay");
                    return TaskConfirmation::Granted(cleared(request.retry));
                }
                self.challenge(request, &backend_id, fingerprint, digest)
                    .await
            }
            // Answers with no grant. Not a fresh call — it claims to be
            // continuing one — and not a retry this gateway can place.
            (None, Some(_)) => refuse(
                request,
                "no_grant",
                -32602,
                "this destructive call carries answers but no confirmation grant",
            ),
            (Some(token), _) => {
                self.redeem(request, token, &fingerprint, &digest, key)
                    .await
            }
        }
    }

    /// The backend behind a surfaced tool whose own catalog entry says it is
    /// destructive, or `None`.
    ///
    /// Read from the backend's cached descriptor — the same annotation the
    /// public catalog shows — so eligibility is the tool's truthful claim about
    /// itself. Nothing is relabelled here, and no wrapper inherits its target's
    /// annotation: a `gateway_invoke` is not this tool, whatever it points at.
    fn destructive_surfaced_backend(&self, tool_name: &str) -> Option<String> {
        let server = self.surfaced_tool_server(tool_name)?;
        let backend = self.backends.get(server)?;
        let tool = backend.get_cached_tool(tool_name)?;
        tool.annotations
            .as_ref()
            .is_some_and(|annotations| annotations.destructive_hint == Some(true))
            .then(|| server.to_owned())
    }

    /// Mint the grant and ask the question.
    ///
    /// The hold and the mint are one operation, in the continuation layer, for
    /// the reason stated there: an envelope naming an exchange nobody holds is
    /// redeemable against nothing.
    async fn challenge(
        &self,
        request: &TaskConfirmationRequest<'_>,
        backend_id: &str,
        fingerprint: String,
        digest: String,
    ) -> TaskConfirmation {
        let Some(capability) = crate::protocol::meta::required_capability(CONFIRMATION_METHOD)
        else {
            return refuse(
                request,
                "unaskable",
                -32603,
                "this gateway cannot classify its own confirmation request",
            );
        };
        if !request.input_capabilities.has(capability) {
            record("undeclared");
            return TaskConfirmation::Answer(Box::new(JsonRpcResponse::error_with_data(
                Some(request.id.clone()),
                -32021,
                format!(
                    "'{}' is destructive and must be confirmed, which needs the '{capability}' \
                     capability the client did not declare",
                    request.tool_name
                ),
                json!({ "requiredCapabilities": [capability] }),
            )));
        }

        let Some(payload) = self
            .continuation
            .begin_confirmation_exchange(
                backend_id.to_owned(),
                // A confirmation continues no backend exchange, so there is no
                // backend state to carry. Left absent rather than emptied: an
                // empty string is a state the backend never issued.
                None,
                fingerprint,
                digest,
                now_unix_secs(),
            )
            .await
        else {
            warn!(
                tool = request.tool_name,
                "No slot to hold this confirmation open; refusing"
            );
            return refuse(
                request,
                "no_slot",
                -32003,
                "this destructive call cannot be confirmed right now",
            );
        };
        let issued_key = challenge_key(&payload);
        let envelope = match self.continuation.keyring().mint(&payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                warn!(tool = request.tool_name, %error, "Confirmation grant mint refused");
                return refuse(
                    request,
                    "mint_refused",
                    -32003,
                    "this destructive call cannot be confirmed right now",
                );
            }
        };

        record("challenged");
        TaskConfirmation::Answer(Box::new(JsonRpcResponse::success(
            request.id.clone(),
            json!({
                "resultType": RESULT_TYPE_INPUT_REQUIRED,
                "inputRequests": {
                    issued_key: {
                        "method": CONFIRMATION_METHOD,
                        "params": {
                            "message": format!(
                                "Confirm the destructive tool '{}'. It runs as a task once \
                                 accepted, and cannot be undone. Accept to proceed, decline \
                                 to abort.",
                                request.tool_name
                            ),
                        },
                    },
                },
                "requestState": envelope,
            }),
        )))
    }

    /// Open the grant a retry presents and decide whether it authorises *this*
    /// call.
    ///
    /// Ordered so that a refusal never costs the caller a redemption: the
    /// envelope is authenticated, its domain and its bindings are checked, the
    /// answer is read, the already-committed case is answered, and only then is
    /// the hold consulted and the grant spent.
    async fn redeem(
        &self,
        request: &TaskConfirmationRequest<'_>,
        token: &str,
        fingerprint: &str,
        digest: &str,
        key: &str,
    ) -> TaskConfirmation {
        let now = now_unix_secs();
        let payload = match self.continuation.keyring().open(token, now) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(tool = request.tool_name, %error, "Confirmation grant refused");
                return refuse_grant(request, "not_authentic");
            }
        };
        // Domain before bindings: an envelope minted to continue a backend
        // exchange is authentic, and authenticity is not authority.
        if payload
            .require_purpose(Purpose::DestructiveConfirm)
            .is_err()
        {
            warn!(
                tool = request.tool_name,
                "Grant from another domain presented as a confirmation"
            );
            return refuse_grant(request, "wrong_purpose");
        }
        // Owner and operation together, in constant time, by the same method
        // the backend path uses.
        if payload.redeemable_by(fingerprint, digest).is_err() {
            warn!(
                tool = request.tool_name,
                "Confirmation grant does not belong to this caller and call"
            );
            return refuse_grant(request, "not_bound");
        }
        // The gateway's own key, derived from the sealed `jti`. A client that
        // did not receive the challenge cannot name it.
        let issued_key = challenge_key(&payload);
        let accepted = request
            .retry
            .input_responses
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|answers| answers.get(&issued_key))
            .and_then(|answer| answer.get("action"))
            .and_then(Value::as_str)
            == Some(ACCEPT);
        if !accepted {
            record("declined");
            let mut response = JsonRpcResponse::error(
                Some(request.id.clone()),
                -32003,
                format!(
                    "the destructive tool '{}' was not confirmed, so it was not run",
                    request.tool_name
                ),
            );
            // The gate working, not the caller misbehaving: kept out of the
            // client failure accounting the dispatcher does.
            response.confirmation_refusal = true;
            return TaskConfirmation::Answer(Box::new(response));
        }

        // The retry the caller already ran. Exact-bound and read-only: the same
        // owner, the same key and the same operation, answered by the sole
        // admission authority rather than by a second index. Consulted before
        // the hold, because the hold for that first acceptance is long gone —
        // and answered by letting the call through, so the original task comes
        // back from admission itself rather than from a handle minted here.
        //
        // "Already admitted" and not "already published": the first acceptance
        // spends the hold and the ledger the moment it is granted, and only
        // then commits. In the window between the record becoming readable and
        // the dedupe entry naming it, a client that has timed out and retried
        // the same acceptance would otherwise be told its grant is unusable —
        // while its destructive task runs — and its next honest attempt would
        // carry a fresh key and run the operation twice.
        if Self::already_admitted(request, key) {
            record("committed_replay");
            return TaskConfirmation::Granted(cleared(request.retry));
        }

        // MRTR.6, for this domain: the exchange this grant names must still be
        // held here. Checked before the spend, so a grant this gateway cannot
        // honour does not also burn the caller's one redemption.
        if self
            .continuation
            .in_flight()
            .route(&payload.hold_key, now)
            .await
            == crate::protocol::continuation::Routing::Gone
        {
            warn!(
                tool = request.tool_name,
                "Confirmation for an exchange this replica no longer holds"
            );
            return refuse_grant(request, "hold_gone");
        }
        if !self
            .continuation
            .ledger()
            .consume(&payload.jti, payload.expires_at, now)
            .await
        {
            warn!(
                tool = request.tool_name,
                "Confirmation grant already spent or ledger at capacity"
            );
            return refuse_grant(request, "spent");
        }
        self.continuation
            .in_flight()
            .complete(&payload.hold_key, now)
            .await;

        record("granted");
        TaskConfirmation::Granted(cleared(request.retry))
    }

    /// Whether this exact operation already owns an admitted task under this
    /// caller's key — one being created, or one already published.
    ///
    /// Built through [`OwnedAdmissionRequest`] — the same type the admitting
    /// call site builds — so the identity asked about here is the identity that
    /// would be admitted, not a second rendering of it. Which also fixes what
    /// this question does *not* bind: the `task` member is part of the grant
    /// digest but not of the admission identity, so a repeat differing only in
    /// its TTL is answered here exactly as `admit_task` would answer it, with
    /// the task it already owns. That is admission's contract for every
    /// task-augmented call and is not relaxed for this one.
    fn already_admitted(request: &TaskConfirmationRequest<'_>, key: &str) -> bool {
        let Some(identity) = request.verified_identity else {
            return false;
        };
        let admission_request = task_admission_request(
            identity.stable_actor_id(),
            key.to_owned(),
            request.tool_name,
            request.arguments,
        );
        request
            .admission
            .already_admitted(admission_request.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(name: &str, arguments: &Value, task: &Value, key: &str) -> String {
        operation_digest(name, arguments, task, key)
    }

    #[test]
    fn every_bound_field_changes_the_digest() {
        let base = digest_of("erase", &json!({"record": "a"}), &json!({}), "key-a");
        assert_ne!(
            base,
            digest_of("read", &json!({"record": "a"}), &json!({}), "key-a"),
            "name"
        );
        assert_ne!(
            base,
            digest_of("erase", &json!({"record": "b"}), &json!({}), "key-a"),
            "arguments"
        );
        assert_ne!(
            base,
            digest_of(
                "erase",
                &json!({"record": "a"}),
                &json!({"ttl": 1}),
                "key-a"
            ),
            "task options"
        );
        assert_ne!(
            base,
            digest_of("erase", &json!({"record": "a"}), &json!({}), "key-b"),
            "idempotency key"
        );
        assert_eq!(
            base,
            digest_of("erase", &json!({"record": "a"}), &json!({}), "key-a"),
            "the same call digests the same way"
        );
    }

    #[test]
    fn a_cleared_retry_keeps_only_the_callers_key() {
        let retry = RetryFields {
            input_responses: Some(json!({"confirm-x": {"action": "accept"}})),
            request_state: Some("sealed".to_owned()),
            idempotency_key: Some("key-a".to_owned()),
            malformed: Vec::new(),
        };
        let cleared = cleared(&retry);
        assert!(cleared.request_state.is_none());
        assert!(cleared.input_responses.is_none());
        assert_eq!(cleared.idempotency_key.as_deref(), Some("key-a"));
    }
}
