// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1: one invocation record per `gateway_invoke`, written around
//! `invoke_tool_traced` so refusals and failures are recorded too.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::context_integrity::ContextIntegrityEvaluation;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::JsonRpcResponse;
use crate::protocol::tasks::TaskTransition;
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
            caller.credential_principal,
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
    /// Served from a cache: no gate ran, so the delivered value is attributed.
    cached: bool,
    /// MIN.1: the response held text over the attribution parse bound, so its
    /// tenants were not read.
    uninspected: bool,
    /// MIN.2: a backend answered this call (its raw response reached the
    /// response gates); a gateway refusal returned as a result did not.
    responded: bool,
    /// MIN.1 gap 1: the gateway task whose raw upstream handle this dispatch
    /// captured. The submission record carries it as the join key to the
    /// task's settlement record.
    upstream_task: Option<String>,
    /// MIN.1 gap 1: how `audit_invocation` would class the refusal of a
    /// recovered result, which recovery commits as a plain `-32603` failure.
    refusal: Option<AuditOutcome>,
}

#[cfg(test)]
#[path = "audit_settlement_tests.rs"]
mod settlement_tests;

tokio::task_local! {
    /// The notes of the call running in this scope, for this call only.
    static NOTES: RefCell<DispatchNotes>;
}

/// Outside [`with_dispatch_scope`] (upstream task recovery) this does nothing.
fn note(f: impl FnOnce(&mut DispatchNotes)) {
    let _ = NOTES.try_with(|notes| f(&mut notes.borrow_mut()));
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

/// MIK-7116.MIN.1: this call is answered from a cache, past every gate.
pub(crate) fn note_cached() {
    note(|notes| notes.cached = true);
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
    note_cached();
    if failure.get(UNINSPECTED_MARKER).and_then(Value::as_bool) == Some(true) {
        note(|notes| notes.uninspected = true);
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
    /// MIN.2: whether a backend answered this call.
    pub(crate) const fn responded(&self) -> bool {
        self.responded
    }

    /// The outcome of a call whose result read as `outcome`: a backend failure
    /// delivered as a tool result is still an `error`.
    pub(crate) fn outcome(&self, outcome: AuditOutcome) -> AuditOutcome {
        match (outcome, self.failure) {
            (AuditOutcome::ToolError, Some(code)) => AuditOutcome::Error(code),
            (outcome, _) => outcome,
        }
    }

    /// MIN.1 gap 1: a settlement's outcome. A gate refusal keeps the class a
    /// live call's record gives it, with the code the task commits. The
    /// settlement result is built from a committed code alone, so a bare
    /// `-32001`/`-32004` reads as `denied` in `from_result`: without a refusal
    /// a gate noted it is the peer's own answer, an `error` (MIK-7735). The
    /// same holds for a bare `-32602`, which `from_result` reads as `invalid`
    /// (MIK-7960).
    fn settled_outcome(&self, outcome: AuditOutcome) -> AuditOutcome {
        match (self.outcome(outcome), self.refusal) {
            (AuditOutcome::Denied(code) | AuditOutcome::Invalid(code), None) => {
                AuditOutcome::Error(code)
            }
            (AuditOutcome::Error(code), Some(AuditOutcome::Denied(_))) => {
                AuditOutcome::Denied(code)
            }
            (AuditOutcome::Error(code), Some(AuditOutcome::Invalid(_))) => {
                AuditOutcome::Invalid(code)
            }
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
        if self.cached {
            if let Some(value) = delivered {
                tenants.extend(meta.response_tenants(value));
                uninspected |= meta.response_uninspected(value);
            }
        } else {
            tenants.extend(self.response_tenants.iter().cloned());
        }
        let mut fields = Map::new();
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
        let marker = match (self.cached, uninspected) {
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
    let wrapped = (one_block.then(|| invoke_value(delivered)).flatten())
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

/// The tool value a `gateway_invoke` result carries: its `structuredContent`,
/// else its first text block parsed as JSON.
pub(super) fn invoke_value(result: &Value) -> Option<Value> {
    result.get("structuredContent").cloned().or_else(|| {
        let text = result.pointer("/content/0/text")?.as_str()?;
        serde_json::from_str(text).ok()
    })
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
        notes: DispatchNotes,
    ) -> Result<Value> {
        // D4: counted before the log check, so auth off still counts.
        if let Some(reason) = crate::security::security_metrics::meta_denial(&result) {
            use crate::security::security_metrics::{DenialRoute, denied};
            denied(DenialRoute::Meta, reason);
        }
        let Some(log) = self.transparency_logger.as_ref() else {
            return result;
        };
        let Some(outcome) = AuditOutcome::from_result(&result) else {
            return result;
        };
        let outcome = notes.outcome(outcome);
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
            .write_invocation(log, args, session_id, caller, trace_id, &facts, attribution)
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
    async fn write_invocation(
        &self,
        log: &std::sync::Arc<crate::security::TransparencyLogger>,
        args: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        trace_id: &str,
        facts: &super::super::admission::ReplayAudit,
        attribution: Map<String, Value>,
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
        let written = log
            .append_bounded(move |log| {
                log.log_invocation_attributed(
                    CorrelationKey {
                        id: &key_id,
                        source: key_source,
                    },
                    &envelope,
                    InvocationTarget::meta(&srv, &tl),
                    &request_hash,
                    response_hash.as_deref(),
                    attribution,
                )
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

    /// The tests' shorthand: the transition to commit alone.
    #[cfg(test)]
    pub(crate) async fn audit_settlement(
        &self,
        task: SettledTask<'_>,
        proposed: TaskTransition,
        notes: &DispatchNotes,
        principal: &str,
    ) -> TaskTransition {
        self.audit_settlement_kept(task, proposed, notes, principal)
            .await
            .0
    }

    /// MIN.1 gap 1: write the settlement record of a recovered upstream task,
    /// before `proposed` is committed, and return the transition to commit.
    ///
    /// `proposed` and `notes` come from `recover_task_result` or
    /// `recover_task_error` run in [`with_dispatch_scope`]; the outcome and
    /// hash mapping is `audit_invocation`'s. `who` is the principal the task
    /// was admitted under and nothing more. A failed write under
    /// [`AuditFailurePolicy::FailClosed`] commits `-32005` instead, with no
    /// backend content, as a live call withholds its result (D1-f).
    ///
    /// Also says whether the transition it returns is the one proposed
    /// (`true`) or that fail-closed replacement (`false`), so a caller never
    /// infers it from the outcome (MIK-7887.RECEIPT.1).
    pub(crate) async fn audit_settlement_kept(
        &self,
        task: SettledTask<'_>,
        proposed: TaskTransition,
        notes: &DispatchNotes,
        principal: &str,
    ) -> (TaskTransition, bool) {
        let Some(log) = self.transparency_logger.as_ref() else {
            return (proposed, true);
        };
        let result = match &proposed {
            TaskTransition::Complete(value) => Ok(value.clone()),
            TaskTransition::Fail(error) => Err(Error::json_rpc(error.code, error.message.clone())),
            _ => return (proposed, true),
        };
        // Total here: only `Error::AuditUnavailable` maps to `None`, and the
        // mapping above builds `Ok` or `Error::JsonRpc` alone.
        let Some(outcome) = AuditOutcome::from_result(&result) else {
            return (proposed, true);
        };
        let attribution = notes.attribution(self, BTreeSet::new(), result.as_ref().ok());
        let envelope = AuditEnvelope {
            trace_id: Some(task.id.to_string()),
            otel_trace_id: None,
            outcome: notes.settled_outcome(outcome),
            who: AuditWho::from_actor_id(principal),
        };
        let response_hash = result.as_ref().ok().map(sha256_of);
        let request_hash = sha256_of(&serde_json::json!({ "task_id": task.id }));
        let (id, server, tool) = (
            task.id.to_owned(),
            task.server.to_owned(),
            task.tool.to_owned(),
        );
        let written = log
            .append_bounded(move |log| {
                log.log_task_settlement(
                    &id,
                    &envelope,
                    &server,
                    &tool,
                    &request_hash,
                    response_hash.as_deref(),
                    attribution,
                )
            })
            .await;
        let (server, tool, task_id) = (task.server, task.tool, task.id);
        match written {
            Ok(()) => (proposed, true),
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(server, tool, task_id, %error, "settlement audit write failed; result withheld");
                let withheld = Error::AuditUnavailable;
                let replaced = TaskTransition::Fail(crate::protocol::JsonRpcError {
                    code: withheld.to_rpc_code(),
                    message: withheld.to_string(),
                    data: None,
                });
                (replaced, false)
            }
            Err(error) => {
                tracing::warn!(server, tool, task_id, %error, "settlement audit write failed (non-fatal)");
                telemetry_metrics::counter!("mcp_audit_settlement_write_failures_total")
                    .increment(1);
                (proposed, true)
            }
        }
    }

    /// #2472: record a replay of a completed execution, which is a delivered
    /// call like any other (D1-d). Only an invocation is recorded, over the
    /// envelope its first execution hashed, and with that execution's
    /// outcome and response hash (`audit`), so it reads as the original
    /// record did. A meta tool that wrote no invocation record the first
    /// time writes none on replay. Under `FailClosed` a failed write
    /// withholds the replay (D1-f).
    pub(crate) async fn audit_replay(
        &self,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        replay: JsonRpcResponse,
        audit: Option<super::super::admission::ReplayAudit>,
    ) -> JsonRpcResponse {
        self.stage_replay(tool_name, arguments, session_id, caller, &replay);
        let Some(log) = self.transparency_logger.as_ref() else {
            return replay;
        };
        let envelope = if tool_name == "gateway_invoke" {
            arguments.clone()
        } else if let Some(server) = self.surfaced_tool_server(tool_name) {
            super::super::admission::named_tool_envelope(server, tool_name, arguments, caller)
        } else {
            return replay;
        };
        // The store is process memory, so this build wrote every entry; facts
        // are absent only when the first run wrote no record. Derive them from
        // the replayed response then, where a wrapped tool error reads as `ok`.
        let facts = if let Some(facts) = audit {
            facts
        } else {
            let result = match (&replay.result, &replay.error) {
                (Some(value), _) => Ok(value.clone()),
                (None, Some(error)) => Err(Error::json_rpc(error.code, error.message.clone())),
                (None, None) => return replay,
            };
            let Some(outcome) = AuditOutcome::from_result(&result) else {
                return replay;
            };
            // A delivered error carries a code and no provenance, and `from_result`
            // reads a bare `-32001`/`-32004` as a gateway refusal: with no stored
            // class, that is a peer's answer as likely as a refusal (MIK-7735).
            let outcome = match outcome {
                AuditOutcome::Denied(code) => AuditOutcome::Error(code),
                other => other,
            };
            super::super::admission::ReplayAudit::new(outcome, result.as_ref().ok().map(sha256_of))
        };
        let trace_id =
            crate::gateway::trace::current().unwrap_or_else(crate::gateway::trace::generate);
        // MIK-7116.MIN.1: a replay is answered past every gate, so it is
        // attributed like a cached delivery, from the value it delivers. A
        // `gateway_invoke` result wraps the tool's value as JSON text
        // (`wrap_tool_success`); attribute that value, as a live call does.
        let unwrapped = match (tool_name, replay.result.as_ref()) {
            ("gateway_invoke", Some(result)) => invoke_value(result),
            _ => None,
        };
        let delivered = unwrapped.as_ref().or(replay.result.as_ref());
        let arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments(&envelope);
        let tenants = self.request_tenants(arguments.as_ref().unwrap_or(&Value::Null));
        let attribution = DispatchNotes {
            cached: true,
            ..DispatchNotes::default()
        }
        .attribution(self, tenants, delivered);
        match self
            .write_invocation(
                log,
                &envelope,
                session_id,
                caller,
                &trace_id,
                &facts,
                attribution,
            )
            .await
        {
            Ok(()) => replay,
            Err(error) => replay.id.clone().map_or_else(
                || JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string()),
                |id| super::super::error_response_preserving_status(id, &error),
            ),
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
