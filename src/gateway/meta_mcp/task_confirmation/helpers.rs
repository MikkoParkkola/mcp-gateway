// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request binding and refusal helpers for the confirmation gate.

use super::{
    DIGEST_DOMAIN, JsonRpcResponse, OwnedAdmissionRequest, Payload, RetryFields, TaskConfirmation,
    TaskConfirmationRequest, Value, canonical_json, json, sha256_hex,
};

/// The credential principal an execution is admitted under when the caller
/// has no verified identity (`MIK-8193`). The synchronous lease and task
/// admission share one store keyed `(principal, key)`, so they must spell the
/// caller alike, or one key admits the same operation twice: once in each
/// spelling. HTTP mints it from the task owner key (`task_owner_key`: proven
/// subject, else `credential:<principal>`), stdio from its reserved owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionOwner<'a>(Option<&'a str>);

impl<'a> AdmissionOwner<'a> {
    /// An HTTP caller's task owner key; empty is no owner (refused when keyed).
    pub(crate) fn credential(owner_key: &'a str) -> Self {
        Self((!owner_key.is_empty()).then_some(owner_key))
    }

    /// The stdio transport's reserved owner (MIK-7272.OWNER.3).
    pub(crate) const fn local_operator() -> Self {
        Self(Some(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL))
    }

    /// A test's owner, written as the production paths would mint it.
    #[cfg(test)]
    pub(crate) const fn for_test(principal: Option<&'a str>) -> Self {
        Self(principal)
    }

    pub(crate) const fn principal(self) -> Option<&'a str> {
        self.0
    }
}

/// The admission identity a task-augmented `tools/call` is admitted under.
///
/// One builder, so the gate's read-only lookup and the admitting call site
/// cannot render the same call two different ways — a drift that would be
/// invisible until a committed replay quietly started a second task.
pub(crate) fn task_admission_request(
    principal: String,
    key: String,
    tool_name: &str,
    arguments: &Value,
) -> OwnedAdmissionRequest {
    OwnedAdmissionRequest::new(
        principal,
        key,
        json!({ "name": tool_name, "arguments": arguments }),
        arguments.clone(),
    )
}

/// What the call carries once its confirmation metadata is removed.
///
/// The idempotency key survives — it is the caller's, not the gate's, and the
/// admission this call is about to face is keyed on it. So does the attestation
/// token: the confirmed call faces the same attestation check as any other. The retry pair does
/// not: it named a question this gateway asked, and forwarding it would send a
/// backend a `requestState` it never issued and answers to a question it never
/// posed.
pub(super) fn cleared(retry: &RetryFields) -> RetryFields {
    RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: retry.idempotency_key.clone(),
        malformed: Vec::new(),
        attestation: retry.attestation.clone(),
    }
}

/// Which call a grant authorises.
///
/// Over the *outer* call: the tool name the client asked for, its arguments,
/// the `task` member it asked to be run under, and the idempotency key it
/// chose. All four are what a caller could otherwise change between being asked
/// and answering — a grant for one record used to erase another, or an
/// acceptance replayed under a second key to run the action twice.
pub(super) fn operation_digest(
    tool_name: &str,
    arguments: &Value,
    task: &Value,
    key: &str,
) -> String {
    sha256_hex(
        canonical_json(&json!({
            "domain": DIGEST_DOMAIN,
            "name": tool_name,
            "arguments": arguments,
            "task": task,
            "key": key,
        }))
        .as_bytes(),
    )
}

/// The key the challenge asks under, and the only key an acceptance is read
/// from.
///
/// Derived from the `jti` sealed inside the envelope: unique per challenge, and
/// unknowable to a client that was not handed that challenge, because the
/// envelope it comes from is encrypted rather than merely signed.
pub(super) fn challenge_key(payload: &Payload) -> String {
    format!("confirm-{}", sha256_hex(payload.jti.as_bytes()))
}

/// One refusal shape for every unusable grant.
///
/// A caller that could tell a forged envelope from a stale one from a grant
/// bound to another call could map this gateway's state one probe at a time,
/// and can act on none of them: the answer to all of them is to ask again. The
/// cause reaches the operator through the log and the metric.
pub(super) fn refuse_grant(
    request: &TaskConfirmationRequest<'_>,
    reason: &'static str,
) -> TaskConfirmation {
    refuse(
        request,
        reason,
        -32602,
        "this destructive call was not confirmed by a grant this gateway will honour",
    )
}

pub(super) fn refuse(
    request: &TaskConfirmationRequest<'_>,
    reason: &'static str,
    code: i32,
    message: &str,
) -> TaskConfirmation {
    record(reason);
    TaskConfirmation::Answer(Box::new(JsonRpcResponse::error(
        Some(request.id.clone()),
        code,
        message.to_owned(),
    )))
}

/// Count one gate outcome. A distinct metric from the continuation counters,
/// which measure the backend-elicitation domain: folding the two would report a
/// declined confirmation as a rejected backend continuation.
pub(super) fn record(outcome: &'static str) {
    telemetry_metrics::counter!("destructive_confirmation_total", "outcome" => outcome)
        .increment(1);
}

#[cfg(test)]
impl crate::gateway::meta_mcp::MetaMcp {
    /// Test-only: admit against `other`'s store, as production shares one
    /// authority between this surface and the task runtime
    /// (`server/task_runtime.rs`). A fixture that rebuilds the surface must
    /// keep the store the task runtime already holds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn admitting_as(mut self, other: &Self) -> Self {
        self.execution_admission = std::sync::Arc::clone(&other.execution_admission);
        self
    }
}
