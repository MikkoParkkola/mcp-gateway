// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input bridge: undeclared requests and bridged re-dispatch.

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::debug;

use super::bridge_settle::{arm, refuse_if_killed};
use super::classify_bridged_dispatch_error;
#[cfg(feature = "cost-governance")]
use super::dispatch_guards;
use super::relay;
use crate::Error;
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::IdempotencyReservation;
use crate::identity_grants::GrantSubject;
use crate::identity_propagation::CallerProof;
use crate::protocol::mrtr::Refusal;
use crate::security::http_diagnostics::is_upstream_unauthorized;

use super::OutboundRetry;

/// The key under which a refusal names the capabilities the client would have
/// had to declare. Shared with `error_response_preserving_status`, which
/// forwards this key out of a gateway-authored error's `data` — a literal in
/// both places would let the two drift apart silently, and the drift would be
/// invisible because the field would simply be absent.
pub(in crate::gateway::meta_mcp) const REQUIRED_CAPABILITIES_DATA_KEY: &str =
    "requiredCapabilities";

/// The key under which a mode refusal names the mode it refused, rendered from
/// the gateway's own enum and never from the caller's string. Forwarded by the
/// same allowlist and named here for the same reason: the write site, the
/// allowlist and the test must not each pick their own spelling.
pub(in crate::gateway::meta_mcp) const UNSUPPORTED_ELICITATION_MODE_DATA_KEY: &str =
    "unsupportedElicitationMode";

/// The refusal for an interim result naming a request type this client cannot
/// be asked (MRTR.9).
///
/// `-32021` with a `requiredCapabilities` payload is the router's existing
/// answer to "the client did not declare that", reused here so one condition
/// meets a client in one shape however the request reached it. The payload
/// tracks what the client can actually do about it: a missing capability names
/// itself, a missing *mode* names the mode instead (the capability is already
/// declared), and neither an unrecognised method nor an unrecognised mode names
/// anything at all — there is nothing a client could add to its declaration to
/// make either acceptable, and naming something would invite exactly that.
pub(super) fn undeclared_input_request(
    server: &str,
    tool: &str,
    refused: &crate::protocol::mrtr::Undeclared<'_>,
) -> Error {
    let (message, data) = match refused.reason {
        Refusal::Capability(capability) => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}', which needs the \
                 '{capability}' capability the client did not declare",
                refused.key
            ),
            Some(json!({ REQUIRED_CAPABILITIES_DATA_KEY: [capability] })),
        ),
        Refusal::UnrecognisedMethod => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' of unrecognised type \
                 '{}', which no client can have declared",
                refused.key, refused.method
            ),
            None,
        ),
        // No `requiredCapabilities`: this client *did* declare elicitation, and
        // naming it again would send the client to add what it already has.
        Refusal::Mode(mode) => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' in elicitation mode \
                 '{}', which the client did not declare",
                refused.key,
                mode.as_str()
            ),
            Some(json!({ UNSUPPORTED_ELICITATION_MODE_DATA_KEY: mode.as_str() })),
        ),
        // The refused mode is not echoed: it is the caller's string, and the
        // gateway names only modes it can render from its own vocabulary.
        Refusal::UnrecognisedMode => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' in an elicitation mode \
                 this gateway does not recognise",
                refused.key
            ),
            None,
        ),
    };
    Error::JsonRpc {
        code: -32021,
        message,
        data,
    }
}

/// Re-dispatches the original call with the answers collected so far.
///
/// Holds the dispatch arguments rather than a closure because
/// [`crate::gateway::input_bridge::BackendInvoker`] is an async trait and every
/// bridged round needs the same values the first dispatch used: a round that
/// differed in any of them would be a second call, not a retry of this one.
/// Every field is read off the first `accounted_dispatch` call site, argument
/// for argument, so a parameter added there is a compile error here rather than
/// a retry that silently diverges.
pub(super) struct BridgeDispatcher<'a> {
    pub(super) meta: &'a MetaMcp,
    pub(super) server: &'a str,
    pub(super) tool: &'a str,
    pub(super) arguments: &'a Value,
    pub(super) prompt_cache_key: Option<&'a str>,
    pub(super) inbound_meta: Option<&'a Value>,
    pub(super) want_full: bool,
    pub(super) session_id: Option<&'a str>,
    pub(super) arm_key: Option<&'a str>,
    pub(super) caller_identity: Option<&'a GrantSubject>,
    pub(super) caller_proof: CallerProof<'a>,
    pub(super) headers: &'a [(String, String)],
    pub(super) cache_binding: Option<&'a str>,
    pub(super) account_credential:
        Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
    pub(super) api_key_name: Option<&'a str>,
    pub(super) trace_id: &'a str,
    pub(super) policy_epoch: u64,
    pub(super) protocol_revision: Option<&'a str>,
    pub(super) routing_profile: &'a str,
    pub(super) scope: super::super::InvokeScope<'a>,
    /// The backend the call was judged on, dispatched through unchanged.
    pub(super) captured: Option<Arc<crate::backend::Backend>>,
    /// A11: the managed lease the headers were released under, if any.
    pub(super) managed: Option<&'a crate::personal_accounts::ManagedLease>,
    /// A11: a round's 401 turned into a reconnect refusal or a rejection mark.
    /// A side slot, not a `BridgeError` variant, because that enum is public:
    /// the bridge sees today's `BackendFailed`, and the call site answers with
    /// this instead of the generic bridged-exchange refusal.
    pub(super) account_refusal: &'a parking_lot::Mutex<Option<Error>>,
    /// #1962: the call's idempotency reservation, held here for the exchange
    /// so each round can arm it around its dispatch.
    pub(super) reservation: &'a parking_lot::Mutex<Option<IdempotencyReservation>>,
    /// COLLUDE.1: who a round's relay check keys on, and its refusal slot.
    pub(super) relay: relay::RelayKey<'a>,
    pub(super) relay_refused: &'a parking_lot::Mutex<Option<Error>>,
}

/// A round's batch as the client receives it: each prompt's params, or a
/// handed-back result, in [`relay::delivered_form`].
fn delivered_challenge(challenge: &Value) -> Value {
    let mut shown = challenge.clone();
    match shown.as_array_mut() {
        Some(prompts) => prompts
            .iter_mut()
            .filter_map(|prompt| prompt.get_mut("params"))
            .for_each(relay::delivered_form),
        None => relay::delivered_form(&mut shown),
    }
    shown
}

impl crate::gateway::input_bridge::ChallengeGate for BridgeDispatcher<'_> {
    /// Scans the batch as the client receives it (MIK-7910: what delivery
    /// drops is never shown), against the backend's own target, and refuses
    /// the exchange rather than rewriting the question:
    /// `enforce_firewall_challenge` runs `Immutable`, so a redaction is not
    /// one of the outcomes available here.
    fn admit(
        &self,
        challenge: &Value,
    ) -> std::result::Result<(), crate::gateway::input_bridge::BridgeError> {
        let targets = [crate::security::response_policy::ResponsePolicyTarget {
            server: self.server.to_owned(),
            tool: self.tool.to_owned(),
        }];
        let correlation = crate::security::response_policy::ResponseCorrelation {
            session_id: self.session_id.unwrap_or_default(),
            caller: self.api_key_name.unwrap_or("anonymous"),
            external_server: "gateway",
            external_tool: "gateway_invoke",
            subject: None,
        };
        self.meta
            .enforce_firewall_challenge(&delivered_challenge(challenge), &targets, &correlation)
            .map_err(
                |_| crate::gateway::input_bridge::BridgeError::ChallengeRefused {
                    dispatched: false,
                },
            )
    }
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::BackendInvoker for BridgeDispatcher<'_> {
    #[allow(clippy::too_many_lines)]
    async fn invoke(
        &self,
        retry_params: Value,
    ) -> std::result::Result<Value, crate::gateway::input_bridge::BridgeError> {
        // The kill switch is read once at the top of the call, so re-read it per round.
        refuse_if_killed(&self.meta.kill_switch, self.server)?;

        // Admitted here as well as at the first dispatch, because the spend
        // check is per backend call and `invoke_tool` ran it once, before the
        // backend asked anything. A bridged exchange adds a call per round, so
        // a budget enforced only at the top is a budget a backend can walk past
        // by asking. The warnings are dropped: the ones that ride the envelope
        // are the first call's, and a bridged round has nowhere to put its own.
        //
        // `NotAdmitted`, not `BackendFailed`: the round is refused before the
        // dispatch, so there is no side effect for the settlement arm to
        // protect and burning the idempotency key here would deny the caller a
        // retry of work that never ran.
        #[cfg(feature = "cost-governance")]
        let admission = self
            .meta
            .admit_spend_for(&dispatch_guards::BackendCall {
                server: self.server,
                tool: self.tool,
                session_id: None,
                api_key_name: self.api_key_name,
                trace_id: "",
                caller_key: None,
            })
            .map_err(|e| crate::gateway::input_bridge::BridgeError::NotAdmitted {
                message: e.to_string(),
            })?;

        // Through `accounted_dispatch`, not `dispatch_to_backend`: a bridged
        // round is a real backend call and is accounted and gated exactly like
        // the first one. A round that skipped the accounting would let a
        // backend that keeps asking spend an unmetered budget.
        // The same key rule as the first round, against the slot as it is now.
        let checked_at = std::time::Instant::now();
        let refusal = self.meta.undeclared_key_refusal(
            (self.server, self.captured.as_ref()),
            self.tool,
            self.arguments,
            self.cache_binding,
            self.headers,
            (self.scope, self.session_id),
        );
        let refusal = match refusal.await {
            Ok(refusal) => refusal,
            Err(e) => {
                // NotAdmitted: no `tools/call` left, so the key stays retryable.
                let (at, parked) = ((self.server, self.tool), self.account_refusal);
                let fill = self
                    .meta
                    .bridged_refused_fill(at, e, self.managed, checked_at, parked);
                let message = fill.await;
                return Err(crate::gateway::input_bridge::BridgeError::NotAdmitted { message });
            }
        };
        if let Some(refusal) = refusal {
            return Err(crate::gateway::input_bridge::BridgeError::NotAdmitted {
                message: refusal["content"][0]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        // The check above may have awaited a cold `tools/list`: re-read the kill.
        refuse_if_killed(&self.meta.kill_switch, self.server)?;
        let outbound = OutboundRetry {
            request_state: retry_params
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_owned),
            input_responses: retry_params.get("inputResponses").cloned(),
        };
        self.refuse_relaying_round(&outbound)?;
        // #1962: armed for the dispatch, so a dropped exchange settles the key.
        arm(self.reservation, true);
        let dispatched = self
            .meta
            .accounted_dispatch(
                self.server,
                self.tool,
                self.arguments.clone(),
                &outbound,
                self.prompt_cache_key,
                self.inbound_meta,
                self.want_full,
                self.session_id,
                self.arm_key,
                self.caller_identity,
                self.caller_proof,
                self.headers,
                self.cache_binding,
                self.account_credential.clone(),
                self.api_key_name,
                self.trace_id,
                self.policy_epoch,
                self.protocol_revision,
                self.routing_profile,
                self.scope,
                self.captured.clone(),
                &super::super::response_security::chain_receipt::ChainSlot::default(),
            )
            .await;
        // The round's spend is recorded: give its reservation back.
        #[cfg(feature = "cost-governance")]
        drop(admission);
        let error = match dispatched {
            Ok(value) => {
                // Asked again: the backend has not acted on this round.
                if crate::protocol::mrtr::InputRequired::claims_input_required(&value) {
                    arm(self.reservation, false);
                }
                return Ok(value);
            }
            Err(error) => error,
        };
        // A11-c: a 401 on a managed credential forces at most one refresh.
        let classified = classify_bridged_dispatch_error(&error);
        if matches!(
            classified,
            crate::gateway::input_bridge::BridgeError::NotAdmitted { .. }
        ) {
            arm(self.reservation, false);
        }
        // Every error that reached the 401 site is parked, marked or not, so
        // the call site answers it as the first dispatch would.
        if let Some(managed) = self.managed
            && is_upstream_unauthorized(&error)
        {
            *self.account_refusal.lock() = Some(managed.after_upstream_401(error).await);
        }
        Err(classified)
    }
}

/// Runs one bridged exchange in a frame of its own.
///
/// A free function taking the dispatcher and the pending round BY VALUE rather
/// than an inline `async` block: everything the exchange needs then lives in
/// this future instead of in `invoke`'s state machine, which is what keeps
/// `invoke` under clippy's `large_futures` threshold at every call site in the
/// tree.
pub(super) async fn run_input_bridge(
    dispatcher: BridgeDispatcher<'_>,
    channel: &dyn crate::gateway::input_bridge::ClientChannel,
    session: &str,
    declared: crate::protocol::meta::Declared,
    pending: crate::protocol::mrtr::InputRequired,
    trace_id: &str,
) -> std::result::Result<Value, crate::gateway::input_bridge::BridgeError> {
    let observer = TracingBridgeObserver { trace_id };
    let bridge = crate::gateway::input_bridge::InputBridge {
        channel,
        backend: &dispatcher,
        gate: &dispatcher,
        observer: &observer,
        bounds: crate::gateway::input_bridge::BridgeBounds::DEFAULT,
    };
    // `None` slice: the per-request capability slice narrows a *modern*
    // caller's declaration, and this call is the legacy one — there is no
    // per-request `_meta` to narrow by, so the session store's value stands
    // alone.
    bridge.run(session, declared, None, &pending).await
}

/// Emits the bridge's counters as structured trace events.
///
/// ponytail: tracing rather than the metrics registry — the record carries no
/// answer body, so a log line is a complete rendering of it. Move to a counter
/// when an operator needs it aggregated rather than searched.
pub(super) struct TracingBridgeObserver<'a> {
    pub(super) trace_id: &'a str,
}

impl crate::gateway::input_bridge::BridgeObserver for TracingBridgeObserver<'_> {
    fn record(&self, record: crate::gateway::input_bridge::BridgeRecord) {
        debug!(trace_id = self.trace_id, record = ?record, "input bridge round");
    }
}
