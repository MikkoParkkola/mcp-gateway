// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection (COLLUDE.1, OWASP ASI10) on the meta route, design
//! `2026-09-28-asi10-verbatim-relay.md` §13.3: the egress check on what a
//! backend receives, and the per-call receipts committed at delivery.

use std::cell::RefCell;

use serde_json::Value;

use super::OutboundRetry;
use crate::gateway::meta_mcp::prompt_cache::build_outbound_meta;
use crate::gateway::meta_mcp::{LOCAL_OPERATOR_PRINCIPAL, MetaMcp, MetaMcpCallerContext};

/// Who a relay is keyed on: a caller's key, or the unkeyed fallback bucket.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct RelayKey<'a> {
    key: &'a str,
    keyed: bool,
}

impl<'a> RelayKey<'a> {
    /// A caller's key, and whether it is a real identity.
    #[cfg(feature = "firewall")]
    pub(crate) const fn new(key: &'a str, keyed: bool) -> Self {
        Self { key, keyed }
    }
}

#[cfg(test)]
impl<'a> RelayKey<'a> {
    /// A test round's caller: unkeyed, in its own bucket.
    pub(crate) fn unkeyed_for_test(key: &'a str) -> Self {
        Self { key, keyed: false }
    }
}

impl MetaMcpCallerContext<'_> {
    /// The relay principal: the HTTP caller key (inherited by playbooks,
    /// chains and HTTP tasks), else the stdio operator, one principal that no
    /// caller key can spell, else the unkeyed `session_id` bucket.
    pub(crate) fn relay_caller<'s>(&'s self, session_id: Option<&'s str>) -> RelayKey<'s> {
        if let Some(key) = self.caller_key.filter(|key| !key.is_empty()) {
            return RelayKey { key, keyed: true };
        }
        if self.stdio_nonce.is_some() {
            let key = LOCAL_OPERATOR_PRINCIPAL;
            return RelayKey { key, keyed: true };
        }
        let key = session_id.unwrap_or("meta:unkeyed");
        RelayKey { key, keyed: false }
    }
}

/// The `tools/call` params a backend receives: `name`, `arguments`, the
/// propagable `_meta`, and a retry's `requestState`/`inputResponses`. The one
/// builder for dispatch and for the relay check, so the two cannot drift.
pub(super) fn outbound_params(
    tool: &str,
    arguments: Value,
    inbound_meta: Option<&Value>,
    prompt_cache_key: Option<&str>,
    retry: &OutboundRetry,
) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("name".to_string(), Value::String(tool.to_owned()));
    map.insert("arguments".to_string(), arguments);
    if let Some(meta) = build_outbound_meta(inbound_meta, prompt_cache_key) {
        map.insert("_meta".to_string(), meta);
    }
    let mut params = Value::Object(map);
    retry.apply(&mut params);
    params
}

/// What one egress is checked on, besides its target.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(super) struct Egress<'a> {
    pub(super) arguments: &'a Value,
    pub(super) inbound_meta: Option<&'a Value>,
    pub(super) prompt_cache_key: Option<&'a str>,
    pub(super) retry: &'a OutboundRetry,
}

impl MetaMcp {
    /// The relay check on `server:tool`'s egress, before secret injection.
    /// A capability gets `arguments` only: nothing else is forwarded to it.
    /// `Some` is the `-32002` refusal to answer with.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn relay_refusal(
        &self,
        who: RelayKey<'_>,
        audit: (&str, &str),
        (server, tool): (&str, &str),
        egress: &Egress<'_>,
    ) -> Option<crate::Error> {
        #[cfg(feature = "firewall")]
        {
            use crate::security::firewall::{FirewallAction, RelayCaller};
            let fw = self.firewall.as_ref().filter(|fw| fw.relay_active())?;
            let capability = self
                .get_capabilities()
                .is_some_and(|cap| server == cap.name && cap.get(tool).is_some());
            // Secret injection overwrites its keys after this check: what the
            // caller put there never leaves, so it is not checked.
            let mut arguments = egress.arguments.clone();
            self.secret_injector
                .strip_overwritten(server, tool, &mut arguments);
            let params = if capability {
                arguments
            } else {
                let (meta, key) = (egress.inbound_meta, egress.prompt_cache_key);
                outbound_params(tool, arguments, meta, key, egress.retry)
            };
            let caller = RelayCaller::new(who.key, who.keyed);
            let verdict = fw.check_relay(caller, server, tool, &params, audit);
            if verdict.action == FirewallAction::Warn {
                tracing::warn!(server, tool, "Firewall: relay observed");
            }
            if verdict.allowed {
                return None;
            }
            let desc = verdict
                .findings
                .first()
                .map_or("", |f| f.description.as_str());
            Some(crate::Error::Forbidden {
                code: -32002,
                status: 403,
                message: format!("Relay detection blocked: {desc}"),
            })
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (who, audit, server, tool, egress);
            None
        }
    }
}

impl MetaMcp {
    /// Relay detection is on: a delivery owner opens a receipt collector and
    /// a result is worth staging only then.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(crate) fn relay_active(&self) -> bool {
        #[cfg(feature = "firewall")]
        {
            self.firewall.as_ref().is_some_and(|f| f.relay_active())
        }
        #[cfg(not(feature = "firewall"))]
        {
            false
        }
    }
}

impl MetaMcp {
    /// Site 1 (§13.3): refuse a relaying call before it is marked dispatched,
    /// releasing its idempotency reservation, since nothing ran.
    pub(super) fn refuse_relay(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        target: (&str, &str),
        egress: &Egress<'_>,
        reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    ) -> crate::Result<()> {
        let audit = (
            session_id.unwrap_or_default(),
            caller.api_key_name.unwrap_or("anonymous"),
        );
        let who = caller.relay_caller(session_id);
        let Some(refused) = self.relay_refusal(who, audit, target, egress) else {
            return Ok(());
        };
        if let Some(reservation) = reservation {
            reservation.release();
        }
        Err(refused)
    }

    /// The caller's channel, recording every bridged prompt it carries.
    pub(super) fn recording_channel<'a>(
        &'a self,
        caller: &'a MetaMcpCallerContext<'_>,
        session_id: Option<&'a str>,
        target: (&'a str, &'a str),
        trace_id: &'a str,
    ) -> RecordingChannel<'a> {
        RecordingChannel {
            inner: caller.channel,
            meta: self,
            who: caller.relay_caller(session_id),
            target,
            api_key_name: caller.api_key_name,
            trace_id,
        }
    }
}

impl super::BridgeDispatcher<'_> {
    /// Site 2 (§13.3): a bridged round carrying a relay is refused before
    /// it is armed. The refusal waits in `relay_refused`, which the call site
    /// reads before any other arm; the bridge sees `NotAdmitted`.
    pub(super) fn refuse_relaying_round(
        &self,
        retry: &OutboundRetry,
    ) -> Result<(), crate::gateway::input_bridge::BridgeError> {
        let egress = Egress {
            arguments: self.arguments,
            inbound_meta: self.inbound_meta,
            prompt_cache_key: self.prompt_cache_key,
            retry,
        };
        let audit = (
            self.session_id.unwrap_or_default(),
            self.api_key_name.unwrap_or("anonymous"),
        );
        let target = (self.server, self.tool);
        let Some(refused) = self.meta.relay_refusal(self.relay, audit, target, &egress) else {
            return Ok(());
        };
        let message = refused.to_string();
        *self.relay_refused.lock() = Some(refused);
        Err(crate::gateway::input_bridge::BridgeError::NotAdmitted { message })
    }
}

/// One result staged for recording, committed only once it is delivered.
/// It holds the capped recording text, never the whole result.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
struct Receipt {
    key: String,
    keyed: bool,
    server: String,
    tool: String,
    #[cfg(feature = "firewall")]
    digest: crate::security::firewall::DeliveryDigest,
}

tokio::task_local! {
    /// The receipts of the delivery this task owns (§13.3 "Recording").
    static RELAY_RECEIPTS: RefCell<Vec<Receipt>>;
}

/// Run `delivery` with a receipt collector: the HTTP and stdio dispatches
/// (finalize included) and a task's execution. Dropping the scope discards
/// what was staged; only [`MetaMcp::commit_relay_receipts`] records.
pub(crate) async fn collecting<F: std::future::Future>(delivery: F) -> F::Output {
    RELAY_RECEIPTS
        .scope(RefCell::new(Vec::new()), delivery)
        .await
}

/// Receipts staged by one delivery whose recording waits for the frame's
/// verdict: the stdio route judges the answer after the dispatch that staged
/// them (COLLUDE.1 x MIN.2). Dropped uncommitted, they record nothing.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct StagedReceipts {
    #[cfg(feature = "firewall")]
    fw: Option<std::sync::Arc<crate::security::firewall::Firewall>>,
    receipts: Vec<Receipt>,
}

impl StagedReceipts {
    /// Nothing staged: relay detection was off for the delivery.
    pub(crate) const fn none() -> Self {
        Self {
            #[cfg(feature = "firewall")]
            fw: None,
            receipts: Vec::new(),
        }
    }

    /// Record what was staged when the answer that was written `delivered` a
    /// result; drop it otherwise.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::needless_pass_by_value))]
    pub(crate) fn commit(self, delivered: bool) {
        #[cfg(feature = "firewall")]
        if delivered && let Some(fw) = self.fw.as_deref() {
            for r in self.receipts {
                let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
                fw.record_digest(caller, &r.server, &r.tool, &r.digest);
            }
        }
        #[cfg(not(feature = "firewall"))]
        let _ = delivered;
    }
}

impl MetaMcp {
    /// [`collecting`], handing the staged receipts back instead of dropping
    /// them, for a caller that records them after the verdict.
    pub(crate) async fn collecting_staged<F: std::future::Future>(
        &self,
        delivery: F,
    ) -> (F::Output, StagedReceipts) {
        let (output, receipts) = RELAY_RECEIPTS
            .scope(RefCell::new(Vec::new()), async {
                let output = delivery.await;
                let staged = RELAY_RECEIPTS.with(|r| std::mem::take(&mut *r.borrow_mut()));
                (output, staged)
            })
            .await;
        let staged = StagedReceipts {
            #[cfg(feature = "firewall")]
            fw: self.firewall.clone(),
            receipts,
        };
        (output, staged)
    }
}

/// [`collecting`] when `on`. Off, nothing is staged (`receipt` yields none
/// without a detector) and a commit outside a collector records nothing, so
/// the scope and its allocation buy nothing.
pub(crate) async fn collecting_if<F: std::future::Future>(on: bool, delivery: F) -> F::Output {
    if on {
        collecting(delivery).await
    } else {
        delivery.await
    }
}

impl MetaMcp {
    /// Stage `value`, the result `server:tool` answered `who` with, as gated.
    /// A no-op outside a collector or with relay detection off.
    pub(crate) fn stage_relay_receipt(
        &self,
        who: RelayKey<'_>,
        target: (&str, &str),
        value: &Value,
    ) {
        if let Some(receipt) = self.receipt(who, target, value) {
            let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().push(receipt));
        }
    }

    /// An upstream task's gated result, staged for `who` at settlement: it
    /// replaces the `working` stub its dispatch staged under `server:tool`,
    /// or is added when gates refused that stub.
    pub(crate) fn stage_upstream_result(
        &self,
        who: RelayKey<'_>,
        target: (&str, &str),
        value: &Value,
    ) {
        let Some(receipt) = self.receipt(who, target, value) else {
            return;
        };
        let _ = RELAY_RECEIPTS.try_with(|receipts| {
            let mut receipts = receipts.borrow_mut();
            let stub = receipts.iter().rposition(|r| {
                (r.server.as_str(), r.tool.as_str()) == target && r.key == receipt.key
            });
            match stub {
                Some(at) => receipts[at] = receipt,
                None => receipts.push(receipt),
            }
        });
    }

    /// `value` reduced to a receipt for `who`; `None` with relay detection
    /// off or outside a collector.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    fn receipt(&self, who: RelayKey<'_>, target: (&str, &str), value: &Value) -> Option<Receipt> {
        #[cfg(feature = "firewall")]
        {
            receipt_with(self.firewall.as_deref()?, who, target, value)
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (who, target, value);
            None
        }
    }

    /// Record every staged receipt, when `response` is a delivered result
    /// rather than an error or a delivery refusal.
    pub(crate) fn commit_relay_receipts(&self, response: &crate::protocol::JsonRpcResponse) {
        self.commit_staged_relay(response.error.is_none() && !response.delivery_refusal);
    }

    /// Record every staged receipt when `delivered`; drop them either way.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(crate) fn commit_staged_relay(&self, delivered: bool) {
        #[cfg(feature = "firewall")]
        if let Some(fw) = self.firewall.as_deref() {
            commit_with(fw, delivered);
            return;
        }
        let _ = delivered;
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
    }

    /// A copy of `result` to compare after a final check, when receipts are
    /// pending; see [`discard_if_changed`].
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) fn relay_snapshot(&self, result: &Value) -> Option<Value> {
        let pending = RELAY_RECEIPTS
            .try_with(|receipts| !receipts.borrow().is_empty())
            .unwrap_or(false);
        (pending && self.relay_active()).then(|| result.clone())
    }

    /// A replayed single-target call (`gateway_invoke`, a surfaced tool) is
    /// delivered again: stage the delivered value under its own target, so
    /// the replay renews the caller's receipt. Multi-step calls renew nothing.
    pub(super) fn stage_replay(
        &self,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        replay: &crate::protocol::JsonRpcResponse,
    ) {
        let field = |name: &str| arguments.get(name).and_then(Value::as_str);
        let target = if tool_name == "gateway_invoke" {
            field("server").zip(field("tool"))
        } else {
            self.surfaced_tool_server(tool_name)
                .map(|server| (server, tool_name))
        };
        let Some(result) = replay.result.as_ref() else {
            return;
        };
        // A `gateway_invoke` answer wraps the tool's value as JSON text: stage
        // that value, verdict slot included, as a live call stages it.
        let unwrapped = if tool_name == "gateway_invoke" {
            super::audit::invoke_value(result)
        } else {
            None
        };
        if let Some(target) = target {
            let value = unwrapped.as_ref().unwrap_or(result);
            self.stage_relay_receipt(caller.relay_caller(session_id), target, value);
        }
    }

    /// Record `value` as delivered to `who` from `server:tool`, now.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn record_relay_delivery(
        &self,
        who: RelayKey<'_>,
        (server, tool): (&str, &str),
        value: &Value,
    ) {
        #[cfg(feature = "firewall")]
        if let Some(fw) = self.firewall.as_ref() {
            let caller = crate::security::firewall::RelayCaller::new(who.key, who.keyed);
            fw.record_delivery(caller, server, tool, value);
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (who, server, tool, value);
    }
}

impl MetaMcp {
    /// A prompt handed to a client, as it is recorded: its own text, since
    /// that is what the client receives, plus the context-integrity verdict
    /// read from a classified copy (an enforcing gate may have rewritten or
    /// withheld that copy, so it is never the recorded text).
    pub(crate) fn recorded_prompt(
        &self,
        (server, tool): (&str, &str),
        api_key_name: Option<&str>,
        trace_id: &str,
        prompt: &Value,
    ) -> Value {
        let (classified, _) =
            self.apply_context_integrity(server, tool, api_key_name, trace_id, prompt.clone());
        let mut recorded = prompt.clone();
        if let (Some(map), Some(verdict)) = (
            recorded.as_object_mut(),
            classified.get("_context_integrity"),
        ) {
            map.insert("_context_integrity".to_owned(), verdict.clone());
        }
        recorded
    }
}

/// `value` as a receipt for `who` under `fw`; `None` with relay detection off
/// or outside a collector.
#[cfg(feature = "firewall")]
fn receipt_with(
    fw: &crate::security::firewall::Firewall,
    who: RelayKey<'_>,
    (server, tool): (&str, &str),
    value: &Value,
) -> Option<Receipt> {
    RELAY_RECEIPTS.try_with(|_| ()).ok()?;
    let digest = fw.delivery_digest(server, tool, value)?;
    Some(Receipt {
        key: who.key.to_owned(),
        keyed: who.keyed,
        server: server.to_owned(),
        tool: tool.to_owned(),
        digest,
    })
}

/// Stage `value` under `fw`, for a route that holds the firewall but not a
/// Meta-MCP (the direct route). A no-op outside a collector.
#[cfg(feature = "firewall")]
pub(crate) fn stage_with(
    fw: &crate::security::firewall::Firewall,
    who: RelayKey<'_>,
    target: (&str, &str),
    value: &Value,
) {
    if let Some(receipt) = receipt_with(fw, who, target, value) {
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().push(receipt));
    }
}

/// Record every staged receipt into `fw` when `delivered`; drop them either way.
#[cfg(feature = "firewall")]
pub(crate) fn commit_with(fw: &crate::security::firewall::Firewall, delivered: bool) {
    let receipts = RELAY_RECEIPTS
        .try_with(|receipts| std::mem::take(&mut *receipts.borrow_mut()))
        .unwrap_or_default();
    if !delivered {
        return;
    }
    for r in receipts {
        let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
        fw.record_digest(caller, &r.server, &r.tool, &r.digest);
    }
}

/// Drop every staged receipt: what was staged was never delivered (a
/// state-only round the gateway answered for itself).
pub(crate) fn discard_staged() {
    let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
}

/// A final check that changed the delivered result (a redaction) leaves the
/// staged receipts describing text the caller never got: drop them all.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) fn discard_if_changed(snapshot: Option<Value>, result: Option<&Value>) {
    if snapshot.is_some_and(|before| Some(&before) != result) {
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
    }
}

/// A bridged prompt is content delivered to the caller (§13.3): recorded
/// when it is handed to the client, before the reply is awaited. The text
/// recorded is the text sent; only the classification verdict comes from a
/// copy, as a tool result's does.
pub(super) struct RecordingChannel<'a> {
    pub(super) inner: &'a dyn crate::gateway::input_bridge::ClientChannel,
    pub(super) meta: &'a MetaMcp,
    pub(super) who: RelayKey<'a>,
    pub(super) target: (&'a str, &'a str),
    pub(super) api_key_name: Option<&'a str>,
    pub(super) trace_id: &'a str,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for RecordingChannel<'_> {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        if let Some(prompt) = params.as_ref().filter(|_| self.meta.relay_active()) {
            let recorded =
                self.meta
                    .recorded_prompt(self.target, self.api_key_name, self.trace_id, prompt);
            self.meta
                .record_relay_delivery(self.who, self.target, &recorded);
        }
        self.inner
            .send_request(session_id, id, method, params)
            .await
    }
}

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_tests.rs"]
mod tests;
