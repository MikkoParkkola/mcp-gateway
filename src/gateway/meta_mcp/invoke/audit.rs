// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1: one invocation record per `gateway_invoke`, written around
//! `invoke_tool_traced` so refusals and failures are recorded too.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::capability::ProcessNote;
use crate::context_integrity::ContextIntegrityEvaluation;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationTarget,
};
use crate::security::transparency_log::CorrelationKey;
use crate::{Error, Result};

impl AuditWho {
    /// The caller of an invocation. The only constructor the invoke path uses:
    /// `who` comes from the request's credential and verified subject, never
    /// from a label or an email.
    pub(crate) fn from_caller(caller: &MetaMcpCallerContext<'_>) -> Self {
        Self::from_parts(
            caller.credential_kind,
            caller.record_principal.clone(),
            caller.api_key_name,
            caller.grant_subject.as_ref(),
        )
    }
}

/// The recovered task a settlement record is about.
#[derive(Clone, Copy)]
pub(crate) struct SettledTask<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    /// The gateway task id.
    pub id: &'a str,
}

/// What a composite task's settlement record joins by, written as
/// `joined_by` on composite records only; a single-target record keeps its
/// dispatch-trace join and has no such member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SettlementJoin {
    /// `trace_id` is the record trace of the step the plan ended on: the
    /// record of the check that refused.
    StepTrace,
    /// `trace_id` is the task id: the plan ended with no usable trace from
    /// the step it ended on. Usually no step ran; when a later step's
    /// arguments were refused, the earlier steps' records still exist.
    TaskId,
}

/// What one call's gates saw, handed out of [`with_dispatch_scope`] as an
/// owned value: the scope ends before the invocation record is written.
#[derive(Debug, Default)]
pub(crate) struct DispatchNotes {
    /// The code of a backend dispatch failure that `invoke_tool_traced`
    /// turned into an `isError` tool result.
    failure: Option<i32>,
    /// MIK-7116.MIN.1: tenants the raw backend response named, noted before
    /// any response gate could refuse or rewrite it.
    response_tenants: BTreeSet<String>,
    /// The context-integrity kernel's data classes for that response, as
    /// their snake-case names.
    data_classes: BTreeSet<String>,
    /// Served from a store past every gate, and which store: the delivered
    /// value is attributed, and the record says which it was.
    cached: Option<Answered>,
    /// What the web UI's counters need from the gates.
    counting: counting::CountNotes,
    /// MIN.1: the response held text over the attribution parse bound, so its
    /// tenants were not read.
    uninspected: bool,
    /// MIN.2: a backend answered this call (its raw response reached the
    /// response gates); a gateway refusal returned as a result did not.
    responded: bool,
    /// This call's dispatch missed a backend its gate also found
    /// unregistered: recorded `not_found` and denied with -32001, for this
    /// call only.
    not_found: bool,
    /// Whether this call's last step was a refusal before its backend.
    pre_send: crate::gateway::meta_mcp::dispatch_log::PreSend,
    /// MIN.1 gap 1: the gateway task whose raw upstream handle this dispatch
    /// captured. The submission record carries it as the join key to the
    /// task's settlement record.
    upstream_task: Option<String>,
    /// MIN.1 gap 1: how `audit_invocation` would class the refusal of a
    /// recovered result, which recovery commits as a plain `-32603` failure.
    refusal: Option<AuditOutcome>,
    /// MIK-7926.FIX.2: the children this call started, the first
    /// [`MAX_PROCESS_NOTES`], and how many there were.
    process: Vec<ProcessNote>,
    process_total: usize,
    /// This call's backend send time, summed over its rounds, and
    /// how its last round ended. `None`: no send began.
    backend: Option<(std::time::Duration, crate::counters::End)>,
    /// MIK-8914.API2A.1: which check decided this call.
    decision: crate::security::decision_record::Noted,
}

/// A backend send of this call took `elapsed` and ended `end`. A
/// bridged retry's rounds add up; the last round's end is the call's.
pub(crate) fn note_backend(elapsed: std::time::Duration, end: crate::counters::End) {
    note(|notes| {
        let total = notes
            .backend
            .map_or(elapsed, |(sum, _)| sum.saturating_add(elapsed));
        notes.backend = Some((total, end));
    });
}

impl DispatchNotes {
    /// The latency sample this call's count carries, if a send began.
    pub(crate) const fn backend_sample(
        &self,
    ) -> Option<(std::time::Duration, crate::counters::End)> {
        self.backend
    }
}

#[path = "audit_decision.rs"]
mod decision;
#[path = "audit_replay.rs"]
mod replay;
#[cfg(test)]
pub(crate) use decision::take_refusal_kind;
pub(crate) use decision::{
    after_upstream_401, collect_allow, note_allowed_by, note_declared_effect, note_refused_by,
    note_send_refusal, noted, take_refusal, take_route_noted, with_route_scope,
};

/// Most process notes one record carries (a playbook may run many).
const MAX_PROCESS_NOTES: usize = 16;

/// MIK-7926.FIX.2: note a child this call started.
pub(crate) fn note_process(process: ProcessNote) {
    note(|notes| {
        notes.process_total += 1;
        if notes.process.len() < MAX_PROCESS_NOTES {
            notes.process.push(process);
        }
    });
}

#[path = "audit_counting.rs"]
pub(crate) mod counting;

#[cfg(test)]
#[path = "audit_settlement_tests.rs"]
mod settlement_tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "audit_delivered_value_tests.rs"]
mod delivered_value_tests;

mod settlement;

tokio::task_local! {
    /// The notes of the call running in this scope, for this call only.
    static NOTES: RefCell<DispatchNotes>;
}

/// Outside [`with_dispatch_scope`] (upstream task recovery) this does nothing.
fn note(f: impl FnOnce(&mut DispatchNotes)) {
    let _ = NOTES.try_with(|notes| f(&mut notes.borrow_mut()));
}

/// Note that this call's dispatch missed a backend its gate found absent.
pub(super) fn note_not_found() {
    note(|notes| notes.not_found = true);
}

/// Note what this call's last pre-send step decided: a refusal before its
/// backend, or a send or served answer that clears an earlier refusal.
pub(super) fn note_pre_send(pre_send: crate::gateway::meta_mcp::dispatch_log::PreSend) {
    note(|notes| notes.pre_send = pre_send);
}

/// Whether this call has so far been refused before its backend; `Clear`
/// outside a call's scope.
pub(super) fn pre_send_now() -> crate::gateway::meta_mcp::dispatch_log::PreSend {
    NOTES
        .try_with(|notes| notes.borrow().pre_send)
        .unwrap_or_default()
}

/// Note that the backend dispatch failed with `error`, though the caller will
/// get a tool result.
pub(super) fn note_dispatch_failure(error: &Error) {
    note(|notes| notes.failure = Some(error.to_rpc_code()));
}

/// MIK-7116.MIN.1: note the tenants a raw backend `result` names, and hand it
/// on unchanged. Called first in the response gates, on both routes.
///
/// Also returns, inside a MIN.2 read scope, the same reading as a read
/// attribution: the caller notes it into the scope once the call's gates have
/// passed, so only a delivered dispatch counts (design §4.4).
pub(in crate::gateway::meta_mcp) fn noted_response(
    meta: &MetaMcp,
    result: Value,
) -> (
    Value,
    Option<crate::security::tenant_reads::ReadAttribution>,
) {
    let (tenants, uninspected) = meta.response_reading(&result);
    let read = crate::security::tenant_reads::in_read_scope()
        .then(|| crate::security::tenant_reads::ReadAttribution::of(tenants.clone(), uninspected));
    note(|notes| notes.responded = true);
    if !tenants.is_empty() {
        note(|notes| notes.response_tenants.extend(tenants));
    }
    if uninspected {
        note(|notes| notes.uninspected = true);
    }
    (result, read)
}

/// MIN.1: this call's response was refused before its tenants could be read
/// (a signature-chain refusal at raw receipt). Only when attribution is on.
pub(crate) fn note_uninspected(meta: &MetaMcp) {
    if meta.attributes_tenants() {
        note(|notes| notes.uninspected = true);
    }
}

/// MIK-7116.MIN.1: note the kernel's data classes, and hand the evaluation on.
pub(super) fn noted_classes(evaluation: ContextIntegrityEvaluation) -> ContextIntegrityEvaluation {
    let classes = &evaluation.classification.data_classes;
    let names = classes
        .iter()
        .filter_map(|class| match serde_json::to_value(class) {
            Ok(Value::String(name)) => Some(name),
            _ => None,
        });
    let names: Vec<String> = names.collect();
    note(|notes| notes.data_classes.extend(names));
    evaluation
}

/// MIN.1 gap 1: this dispatch captured the raw upstream handle of task `id`.
pub(crate) fn note_upstream_task(id: &str) {
    note(|notes| notes.upstream_task = Some(id.to_owned()));
}

/// MIN.1 gap 1: note how a refused recovered `result` is classed, so its
/// settlement record says `denied` where a live call's record would.
pub(crate) fn note_refusal(result: &Result<Value>) {
    if result.is_err()
        && let Some(outcome) = AuditOutcome::from_result(result)
    {
        note(|notes| notes.refusal = Some(outcome));
    }
}

/// What answered a call past every gate. A response-cache hit stands in only
/// for a call the slot declared read-only; a replay may stand in for a stored
/// write, so its record must not read as a cache hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answered {
    /// The response cache.
    CacheHit,
    /// An idempotency key's stored answer.
    Replay,
}

/// Whether `answered` answered this call; false outside a dispatch scope.
pub(crate) fn answered_by(answered: Answered) -> bool {
    NOTES
        .try_with(|notes| notes.borrow().cached == Some(answered))
        .unwrap_or(false)
}

/// MIK-7116.MIN.1: this call is answered from a store, past every gate. The
/// answer is not this request's, so its delivery states no effect or findings.
pub(crate) fn note_cached(answered: Answered) {
    note(|notes| notes.cached = Some(answered));
    crate::gateway::delivery_facts::unvouched();
}

/// MIK-7636: the member a stored failure carries when its call was noted
/// uninspected. Never on the wire: a replay answers `code`, `message` and
/// `data` only.
const UNINSPECTED_MARKER: &str = "_gatewayUninspected";

/// MIK-7636: `failure` as an idempotency key stores it, marked when this call
/// was noted uninspected so its replay records the same.
pub(crate) fn stored_failure(mut failure: Value) -> Value {
    let uninspected = NOTES
        .try_with(|notes| notes.borrow().uninspected)
        .unwrap_or(false);
    if uninspected && let Some(object) = failure.as_object_mut() {
        object.insert(UNINSPECTED_MARKER.to_owned(), Value::Bool(true));
    }
    failure
}

/// MIK-7636: a keyed replay of the stored `failure`, noted as cached and, when
/// its first call was, uninspected.
pub(crate) fn note_cached_failure(failure: &Value) {
    note_cached(Answered::Replay);
    if failure.get(UNINSPECTED_MARKER).and_then(Value::as_bool) == Some(true) {
        note(|notes| notes.uninspected = true);
    }
}

/// Whether a call's dispatch scope is open here, for a test hook that must
/// act only inside it.
#[cfg(test)]
pub(crate) fn in_dispatch_scope_for_test() -> bool {
    NOTES.try_with(|_| ()).is_ok()
}

/// Note `allow` into this call's notes directly, as another check of the
/// same invocation would have, for a row that preloads an attribution.
#[cfg(test)]
pub(crate) fn preload_allow_for_test(allow: crate::security::decision_record::Allow) {
    note(|notes| notes.decision.allowed(allow));
}

impl DispatchNotes {
    /// What this call's gates noted about its decision, for a row to compare.
    #[cfg(test)]
    pub(crate) const fn decision_for_test(&self) -> &crate::security::decision_record::Noted {
        &self.decision
    }
}

/// Run one invocation, returning its output and what its gates noted.
pub(crate) async fn with_dispatch_scope<F: std::future::Future>(
    future: F,
) -> (F::Output, DispatchNotes) {
    NOTES
        .scope(RefCell::new(DispatchNotes::default()), async {
            let output = future.await;
            (output, NOTES.with(RefCell::take))
        })
        .await
}

impl DispatchNotes {
    /// [`note_not_found`] for notes built outside a dispatch scope.
    pub(super) fn mark_not_found(&mut self) {
        self.not_found = true;
    }

    /// MIN.2: whether a backend answered this call.
    pub(crate) const fn responded(&self) -> bool {
        self.responded
    }

    /// Whether this call was refused before its backend.
    pub(crate) const fn pre_send(&self) -> crate::gateway::meta_mcp::dispatch_log::PreSend {
        self.pre_send
    }

    /// The outcome of a call whose result read as `outcome`: a backend failure
    /// delivered as a tool result is still an `error`.
    pub(crate) fn outcome(&self, outcome: AuditOutcome) -> AuditOutcome {
        match (outcome, self.failure) {
            (AuditOutcome::ToolError, Some(code)) => AuditOutcome::Error(code),
            (outcome, _) => outcome,
        }
    }

    /// MIK-7116.MIN.1: the attribution fields of one invocation record, given
    /// the request's tenants and the `delivered` value (attributed instead of
    /// the raw response on a cache hit). Empty when the call named no tenant,
    /// so a deployment without `arg_keys` keeps its record schema.
    pub(crate) fn attribution(
        &self,
        meta: &MetaMcp,
        mut tenants: BTreeSet<String>,
        delivered: Option<&Value>,
    ) -> Map<String, Value> {
        let mut uninspected = self.uninspected;
        if self.cached.is_some() {
            if let Some(value) = delivered {
                tenants.extend(meta.response_tenants(value));
                uninspected |= meta.response_uninspected(value);
            }
        } else {
            tenants.extend(self.response_tenants.iter().cloned());
        }
        let mut fields = Map::new();
        if !self.process.is_empty() {
            let process: Vec<Value> = self.process.iter().map(|p| p.to_json()).collect();
            fields.insert("process".into(), process.into());
            if self.process_total > self.process.len() {
                fields.insert("process_total".into(), self.process_total.into());
            }
        }
        if tenants.is_empty() && !uninspected {
            return fields;
        }
        if !tenants.is_empty() {
            let hashed: BTreeSet<String> = tenants
                .into_iter()
                .map(|id| crate::security::hash_argument(&Value::String(id)))
                .collect();
            fields.insert(
                "tenants".into(),
                hashed.into_iter().collect::<Vec<_>>().into(),
            );
        }
        if !self.data_classes.is_empty() {
            let classes: Vec<Value> = self
                .data_classes
                .iter()
                .cloned()
                .map(Value::String)
                .collect();
            fields.insert("data_classes".into(), classes.into());
        }
        // One value names how far the attribution can be trusted: past the
        // gates (a cache or replay), unread (text over the parse bound), or both.
        let marker = match (self.cached.is_some(), uninspected) {
            (true, true) => Some("cached_delivery_uninspected"),
            (true, false) => Some("cached_delivery"),
            (false, true) => Some("uninspected"),
            (false, false) => None,
        };
        if let Some(marker) = marker {
            fields.insert("attribution".into(), marker.into());
        }
        fields
    }
}

impl MetaMcp {
    /// MIK-7116.MIN.1: the tenants a tool's own `arguments` name, under the
    /// firewall's `tenant_guard.arg_keys`. Empty without a firewall.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(clippy::unused_self, reason = "the tenant keys live on the firewall")
    )]
    pub(crate) fn request_tenants(&self, arguments: &Value) -> BTreeSet<String> {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall.request_tenants(arguments);
        }
        let _ = arguments;
        BTreeSet::new()
    }

    /// MIK-7116.MIN.1: the tenants a tool result names. Empty without a firewall.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(clippy::unused_self, reason = "the tenant keys live on the firewall")
    )]
    pub(crate) fn response_tenants(&self, result: &Value) -> BTreeSet<String> {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall.response_tenants(result);
        }
        let _ = result;
        BTreeSet::new()
    }

    /// The tenants a tool result names and whether part of it went unread, in
    /// one walk. Empty without a firewall.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(clippy::unused_self, reason = "the tenant keys live on the firewall")
    )]
    pub(crate) fn response_reading(&self, result: &Value) -> (BTreeSet<String>, bool) {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall.tenant_guard().response_reading(result);
        }
        let _ = result;
        (BTreeSet::new(), false)
    }

    /// MIN.1: whether tenant attribution is configured (a firewall with
    /// `arg_keys`). False without a firewall.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(clippy::unused_self, reason = "the tenant keys live on the firewall")
    )]
    pub(crate) fn attributes_tenants(&self) -> bool {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall.tenant_guard().attributes();
        }
        false
    }

    /// MIN.1: whether `result` holds text the attribution could not read.
    /// False without a firewall, like [`Self::response_tenants`].
    #[cfg_attr(
        not(feature = "firewall"),
        expect(clippy::unused_self, reason = "the tenant keys live on the firewall")
    )]
    pub(crate) fn response_uninspected(&self, result: &Value) -> bool {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            return firewall.tenant_guard().response_uninspected(result);
        }
        let _ = result;
        false
    }
}

/// A delivered result as a receipt reads it. A `gateway_invoke` answer wraps
/// the backend value as one pretty-printed text block, whose escapes (`\n` as
/// two characters) are not the text the caller reads: it is read decoded, as
/// the receipt was staged from the backend value, whatever its JSON type
/// (MIK-7939). Only a block that is exactly that printing is decoded; any
/// other text, JSON or not, is read as delivered (decoding it would drop a
/// number written in the text).
#[cfg(feature = "firewall")]
pub(super) fn delivered_value(delivered: &Value) -> std::borrow::Cow<'_, Value> {
    let one_block = delivered.get("structuredContent").is_none()
        && delivered
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|content| content.len() == 1);
    let text = delivered.pointer("/content/0/text").and_then(Value::as_str);
    let wrapped = (one_block
        .then(|| crate::protocol::tool_result_payload(delivered))
        .flatten())
    .filter(|decoded| text == serde_json::to_string_pretty(decoded).ok().as_deref());
    wrapped.map_or(
        std::borrow::Cow::Borrowed(delivered),
        std::borrow::Cow::Owned,
    )
}

/// The text of a `gateway_invoke` answer whose block is not the gateway's own
/// printing (MIK-7998): only the wrapper's members, one text block that is not
/// exactly the pretty printing of what it parses to, or not JSON. The gateway
/// prints every wrapper, so such a block was rewritten by its final pass.
/// `None` for an answer [`delivered_value`] reads decoded.
#[cfg(feature = "firewall")]
pub(super) fn rewritten_text(delivered: &Value) -> Option<&str> {
    // Only the wrapper's own members and the gateway's final stamps (the
    // modern `resultType: complete`, a signature): a native answer passed
    // through, such as an interim one with `inputRequests`, is read as
    // delivered, its other members included.
    let wrapper = delivered
        .as_object()?
        .iter()
        .all(|(key, value)| match key.as_str() {
            "content" | "isError" | "_meta" | "_signature" => true,
            "resultType" => value == "complete",
            _ => false,
        });
    if !wrapper {
        return None;
    }
    let [block] = delivered.get("content")?.as_array()?.as_slice() else {
        return None;
    };
    let text = block.get("text")?.as_str()?;
    let printed = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok());
    (printed.as_deref() != Some(text)).then_some(text)
}

fn sha256_of(value: &Value) -> String {
    format!(
        "sha256:{}",
        crate::hashing::sha256_hex(crate::hashing::canonical_json(value).as_bytes())
    )
}

impl MetaMcp {
    /// Record `result` and hand it on, or withhold it when the record cannot be
    /// written under [`AuditFailurePolicy::FailClosed`] (D1-f).
    ///
    /// `request_hash` covers `args` as the caller sent them, gateway directives
    /// included; `response_hash` covers the value returned to the caller
    /// (D1-d.1). A failed call has no response hash. `notes` carries
    /// the backend failure code a call converted to a tool result, and the
    /// tenant attribution its gates saw.
    pub(super) async fn audit_invocation(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        trace_id: &str,
        result: Result<Value>,
        mut notes: DispatchNotes,
    ) -> Result<Value> {
        // D4: counted before the log check, so auth off still counts.
        let withheld = super::denial::count_meta_denial(args, &result, notes.not_found);
        self.count_invocation(args, caller, &result, &notes, withheld);
        let Some(log) = self.transparency_logger.as_ref() else {
            return result;
        };
        let Some(outcome) = withheld.or_else(|| AuditOutcome::from_result(&result)) else {
            return result;
        };
        let outcome = notes.outcome(outcome);
        // A withheld target's record carries the memo's code, so its check.
        if withheld.is_some()
            && let Some(refusal) = args
                .get("server")
                .and_then(Value::as_str)
                .zip(args.get("tool").and_then(Value::as_str))
                .and_then(|(server, tool)| {
                    crate::gateway::meta_mcp::visible::memo::denial(server, tool)
                })
        {
            notes.refused_by_memo(refusal);
        }
        // Boxed: held across the write, it would grow every dispatch future.
        let decision = Box::new(notes.decided(self, outcome));
        // MIK-7116.MIN.1: the tool's own arguments, as the firewall walks them.
        let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(args);
        let tenants = self.request_tenants(arguments.as_ref().unwrap_or(&Value::Null));
        let mut attribution = notes.attribution(self, tenants, result.as_ref().ok());
        if let Some(id) = notes.upstream_task {
            attribution.insert("task_id".into(), id.into());
        }
        let facts =
            super::super::admission::ReplayAudit::new(outcome, result.as_ref().ok().map(sha256_of))
                .with_request_hash(sha256_of(args));
        let written = self
            .write_invocation(
                log,
                args,
                session_id,
                caller,
                trace_id,
                &facts,
                attribution,
                decision,
            )
            .await;
        // #2472: a replay of this execution is recorded with these facts, but
        // only once they describe what was delivered (#2521): a failed write
        // withholds the value, so a replay must not record it as delivered.
        if written.is_ok()
            && let Some(lease) = caller.execution
        {
            lease.note_audit(facts);
        }
        written.and(result)
    }

    /// Write one meta invocation record with `facts` (outcome and response
    /// hash) and `attribution`. `Err` only when the write failed under
    /// [`AuditFailurePolicy::FailClosed`] (D1-f).
    #[allow(clippy::too_many_arguments)]
    #[expect(
        clippy::too_many_arguments,
        reason = "the record's parts, each owned by a different stage of the call"
    )]
    async fn write_invocation(
        &self,
        log: &std::sync::Arc<crate::security::TransparencyLogger>,
        args: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        trace_id: &str,
        facts: &super::super::admission::ReplayAudit,
        attribution: Map<String, Value>,
        decision: Box<crate::security::decision_record::Decision>,
    ) -> Result<()> {
        let server = args
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let tool = args.get("tool").and_then(Value::as_str).unwrap_or_default();
        let outcome = facts.outcome();
        let response_hash = facts.response_hash().map(str::to_string);
        // MIK-7215.CONTROL.3/.3a: see `CorrelationKey::ladder`.
        let otel_trace_id = args
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        let key = CorrelationKey::ladder(otel_trace_id.as_deref(), session_id, trace_id);
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.to_string()),
            otel_trace_id: otel_trace_id.clone(),
            outcome,
            who: AuditWho::from_caller(caller),
        };
        // F20: on the blocking pool, bounded; a stalled disk answers 503
        // instead of pinning a runtime worker.
        let (key_id, key_source) = (key.id.to_string(), key.source);
        // MIK-7641: a replay records the hash its first execution's record
        // carried; only facts with none are hashed from `args` here.
        let request_hash = facts
            .request_hash()
            .map_or_else(|| sha256_of(args), str::to_owned);
        let (srv, tl) = (server.to_string(), tool.to_string());
        // The open slot's set, taken here: the blocking op below has no task-locals.
        let recorded = super::super::grant_audit::open_slot_recorded();
        let call_trace = trace_id.to_string();
        let written = log
            .append_bounded(move |log| {
                let landed = log.log_invocation_attributed(
                    CorrelationKey {
                        id: &key_id,
                        source: key_source,
                    },
                    &envelope,
                    InvocationTarget::meta(&srv, &tl),
                    &request_hash,
                    response_hash.as_deref(),
                    attribution,
                    Some(decision.as_ref()),
                );
                // Inside the op, after the write returned Ok: a caller timeout
                // cannot skip it, and a failed write never adds the id. The
                // call's grant decisions read this set in their own later append.
                if landed.is_ok()
                    && let Some(recorded) = &recorded
                {
                    recorded.add(&call_trace);
                }
                landed
            })
            .await;
        match written {
            Ok(()) => Ok(()),
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(server, tool, trace_id, %error, "invocation audit write failed; result withheld");
                Err(Error::AuditUnavailable)
            }
            Err(error) => {
                tracing::warn!(server, tool, trace_id, %error, "Transparency log write failed (non-fatal)");
                Ok(())
            }
        }
    }

    /// Record an `idp_refuse`. The request is refused on identity-propagation
    /// grounds either way, so a failed write is logged, never dropped.
    pub(super) async fn audit_refused_credential(
        audit_logger: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
        subject_id: &str,
        server: &str,
        audience: &str,
        msg: &str,
    ) {
        if let Err(audit_err) = crate::identity_propagation::audit_identity_propagation(
            audit_logger,
            "idp_refuse",
            subject_id,
            server,
            Some(audience),
            Some(msg),
        )
        .await
        {
            tracing::warn!(
                server,
                error = %audit_err,
                "identity-propagation refuse audit write failed"
            );
        }
    }
}
