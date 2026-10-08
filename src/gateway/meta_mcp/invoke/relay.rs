// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection (COLLUDE.1, OWASP ASI10) on the meta route, design
//! `2026-09-28-asi10-verbatim-relay.md` §13.3: the egress check on what a
//! backend receives, and the per-call receipts committed at delivery.

use std::cell::{Cell, RefCell};

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

#[cfg(feature = "firewall")]
impl<'a> RelayKey<'a> {
    /// A caller's key, and whether it is a real identity.
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
            use crate::security::firewall::RelayCaller;
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
            fw.relay_block_message(caller, (server, tool), &params, audit)
                .map(|message| crate::Error::Forbidden {
                    code: -32002,
                    status: 403,
                    message,
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
    /// Staged by a plan step (`gateway_run_playbook`, `gateway_execute`): the
    /// plan's answer is not this step's text, so it is never rebuilt from it
    /// (MIK-7887.RECEIPT.2).
    in_plan: bool,
    /// A plan receipt whose answer changed and has not yet been kept to the
    /// final answer: never committed so (MIK-7887.RECEIPT.2).
    pending_retain: bool,
    /// The plan step that staged it, as the plan labels its steps (a
    /// playbook's step index, a chain's execution index): which answer
    /// members it may own (`MIK-8113`). `None` outside a labelled step.
    step: Option<u32>,
    /// What it records.
    kind: Kind,
}

/// What a staged receipt records.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
enum Kind {
    /// A result as delivered (or a plan step's, kept to the plan's answer).
    Delivered,
    /// The seam fingerprints of a plan's answer, rebuilt each time the step
    /// receipts are kept to it (`MIK-8113`).
    Seam,
}

tokio::task_local! {
    /// The receipts of the delivery this task owns (§13.3 "Recording").
    static RELAY_RECEIPTS: RefCell<Vec<Receipt>>;
    static RELAY_STAGED: Cell<usize>; // What it staged so far (MIK-7992).
    /// Set while one step of a plan dispatches, with the step's label.
    static PLAN_STEP: Option<u32>;
}

/// Run one plan step's dispatch: the receipts it stages are a plan's, under
/// `label`, the step as the plan's answer names it (`MIK-8113`). A plan run
/// inside a step keeps the outer step's label: the outer answer names that
/// step, and the inner plan's own labels mean nothing there.
pub(crate) async fn plan_step<F: std::future::Future>(label: Option<u32>, step: F) -> F::Output {
    let label = PLAN_STEP.try_with(|outer| *outer).unwrap_or(label);
    PLAN_STEP.scope(label, step).await
}

/// Run `delivery` with a receipt collector: the HTTP and stdio dispatches
/// (finalize included) and a task's execution. Dropping the scope discards
/// what was staged; only a commit records.
pub(crate) async fn collecting<F: std::future::Future>(delivery: F) -> F::Output {
    RELAY_RECEIPTS
        .scope(
            RefCell::new(Vec::new()),
            RELAY_STAGED.scope(
                Cell::new(0),
                super::gateway_writes::scope(seams::scope(delivery)),
            ),
        )
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
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::needless_pass_by_value, clippy::unused_self)
    )]
    pub(crate) fn commit(self, delivered: bool) {
        #[cfg(feature = "firewall")]
        if delivered && let Some(fw) = self.fw.as_deref() {
            for r in self.receipts.into_iter().filter(|r| !r.pending_retain) {
                let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
                fw.record_digest(caller, &r.server, &r.tool, &r.digest);
            }
        }
        #[cfg(not(feature = "firewall"))]
        let _ = delivered;
    }
}

tokio::task_local! {
    /// Whether the HTTP answer being built delivers a result.
    static RELAY_DELIVERS: std::cell::Cell<bool>;
}

/// Run an HTTP `delivery` inside a receipt collector and hand what it staged to
/// the response as [`DeferredReceipts`]: `emit_http`, the last step that can
/// replace the answer, records them. With relay detection off nothing is
/// collected.
pub(crate) async fn collecting_http<F, R>(
    meta: std::sync::Arc<MetaMcp>,
    delivery: F,
) -> axum::response::Response
where
    F: std::future::Future<Output = R>,
    R: axum::response::IntoResponse,
{
    if !meta.relay_active() {
        return delivery.await.into_response();
    }
    let ((mut response, answered), staged) = meta
        .collecting_staged(RELAY_DELIVERS.scope(std::cell::Cell::new(false), async {
            let response = delivery.await.into_response();
            (response, RELAY_DELIVERS.with(std::cell::Cell::get))
        }))
        .await;
    response
        .extensions_mut()
        .insert(DeferredReceipts::new(staged, answered));
    response
}

/// Receipts an HTTP answer carries to the last step that can still replace it
/// (the grant slot, the read record): `emit_http` records them only when the
/// answer goes out as built. A replacement is a new response and carries
/// none, so a replaced answer records nothing. `eligible`: the answer
/// delivers a result.
#[derive(Clone)]
pub(crate) struct DeferredReceipts {
    staged: std::sync::Arc<parking_lot::Mutex<Option<StagedReceipts>>>,
    eligible: bool,
}

impl DeferredReceipts {
    pub(crate) fn new(staged: StagedReceipts, eligible: bool) -> Self {
        Self {
            staged: std::sync::Arc::new(parking_lot::Mutex::new(Some(staged))),
            eligible,
        }
    }

    /// Record what was staged when the answer went out as built.
    pub(crate) fn commit(&self, written: bool) {
        if let Some(staged) = self.staged.lock().take() {
            staged.commit(written && self.eligible);
        }
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
                let writes = super::gateway_writes::scope(seams::scope(delivery));
                let output = RELAY_STAGED.scope(Cell::new(0), writes).await;
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

    /// Mark whether the answer being built delivers a result (no error, no
    /// delivery refusal): what [`collecting_http`] hands `emit_http`.
    #[allow(
        clippy::unused_self,
        reason = "the call sits beside the other relay steps on the Meta-MCP"
    )]
    pub(crate) fn settle_relay_receipts(&self, response: &crate::protocol::JsonRpcResponse) {
        let delivers = response.error.is_none() && !response.delivery_refusal;
        let _ = RELAY_DELIVERS.try_with(|flag| flag.set(delivers));
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
    /// pending; see [`MetaMcp::restage_if_changed`].
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
            // MIK-7991: the stored record was restored on decode; the replay
            // wrote nothing else, so the delivery's record is exactly it.
            let record = super::gateway_writes::recorded();
            let value = super::gateway_writes::without(value, &record);
            self.stage_relay_receipt(caller.relay_caller(session_id), target, &value);
        }
    }
}

impl MetaMcp {
    /// A prompt handed to a client, as it is recorded: its own text, since
    /// that is what the client receives, plus the context-integrity verdict
    /// read from a classified copy (an enforcing gate may have rewritten or
    /// withheld that copy, so it is never the recorded text). Both are the
    /// form the caller is handed, so text delivery strips (the chain member,
    /// a clamped scope) sets no verdict and no audit class (MIK-7942).
    pub(crate) fn recorded_prompt(
        &self,
        (server, tool): (&str, &str),
        api_key_name: Option<&str>,
        trace_id: &str,
        prompt: &Value,
    ) -> Value {
        let mut recorded = prompt.clone();
        delivered_form(&mut recorded);
        let (classified, _) =
            self.apply_context_integrity(server, tool, api_key_name, trace_id, recorded.clone());
        let Some(verdict) = classified.get("_context_integrity") else {
            return recorded;
        };
        // A string or array result has no member to carry the verdict: wrap it
        // rather than drop it.
        if !recorded.is_object() {
            recorded = serde_json::json!({ "value": recorded });
        }
        if let Some(map) = recorded.as_object_mut() {
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
    RELAY_STAGED.try_with(|_| ()).ok()?;
    // MIK-7994: without this call's gateway members; plan receipts are never rebuilt.
    let mut value = value.clone();
    super::gateway_writes::strip(&mut value, super::gateway_writes::Layer::Value);
    let plan = PLAN_STEP.try_with(|label| *label);
    let in_plan = plan.is_ok();
    let digest =
        RELAY_STAGED.with(|s| fw.receipt_digest(server, tool, &value, in_plan.then_some(s)))?;
    Some(Receipt {
        key: who.key.to_owned(),
        keyed: who.keyed,
        server: server.to_owned(),
        tool: tool.to_owned(),
        digest,
        in_plan,
        pending_retain: false,
        step: plan.ok().flatten(),
        kind: Kind::Delivered,
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
        // Only a value a receipt was built from, so a row that sees nothing
        // staged also catches receipt construction switched off.
        #[cfg(test)]
        STAGED_FOR_TEST.with(|staged| staged.borrow_mut().push(value.clone()));
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().push(receipt));
    }
}

#[cfg(all(test, feature = "firewall"))]
thread_local! {
    /// Every value the direct route staged on this thread, so a route-level
    /// row can read what a receipt was built from (MIK-8022.FOLLOW.1).
    static STAGED_FOR_TEST: std::cell::RefCell<Vec<Value>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Take what [`stage_with`] staged on this thread since the last take.
#[cfg(all(test, feature = "firewall"))]
pub(crate) fn take_staged_for_test() -> Vec<Value> {
    STAGED_FOR_TEST.with(|staged| std::mem::take(&mut *staged.borrow_mut()))
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
    for r in receipts.into_iter().filter(|r| !r.pending_retain) {
        let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
        fw.record_digest(caller, &r.server, &r.tool, &r.digest);
    }
}

/// Drop every staged receipt: what was staged was never delivered (a
/// state-only round the gateway answered for itself).
pub(crate) fn discard_staged() {
    let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
}

/// A bridged prompt is content delivered to the caller (§13.3): recorded
/// once the channel confirms delivery (MIK-7887.RECEIPT.3), which is before
/// the reply is awaited, so no second caller can relay it during the wait. The text
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

/// The form a caller is handed: a backend's copy of the reserved chain member
/// is dropped and the cache scope clamped (MIK-7910). A delivery and its record
/// both pass through here, so the receipt describes the bytes that were sent.
pub(crate) fn delivered_form(value: &mut Value) {
    crate::security::signature_chain::strip_chain(value);
    crate::protocol::cacheable::clamp_delivered_scope(value);
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
        let params = params.map(|mut prompt| {
            delivered_form(&mut prompt);
            prompt
        });
        // MIK-7887.RECEIPT.3: the receipt commits where the channel confirms
        // delivery, not here; no session or a send cancelled first leaves none.
        let commit = params
            .as_ref()
            .filter(|_| self.meta.relay_active())
            .and_then(|prompt| {
                let recorded = self.meta.recorded_prompt(
                    self.target,
                    self.api_key_name,
                    self.trace_id,
                    prompt,
                );
                self.meta.delivery_commit(self.who, self.target, &recorded)
            });
        self.inner
            .send_request_committing(session_id, id, method, params, commit)
            .await
    }
}

#[path = "relay_catalogue.rs"]
mod catalogue;
#[path = "relay_delivered.rs"]
mod delivered;
#[path = "relay_seams.rs"]
mod seams;
#[cfg(test)]
pub(crate) use seams::noting_plan_members;
pub(crate) use seams::{note_plan_member, pointer_token};

pub(crate) use catalogue::{CatalogueCaller, as_caller};
#[cfg(feature = "firewall")]
pub(crate) use delivered::strip_gateway_stamps;
pub(crate) use delivered::{AnswerShape, GatewayStamps};

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_tests.rs"]
mod tests;
