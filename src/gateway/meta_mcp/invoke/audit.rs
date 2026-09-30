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
use crate::security::audit::{
    AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho, InvocationTarget,
};
use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
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
}

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
pub(super) fn noted_response(meta: &MetaMcp, result: Value) -> Value {
    let tenants = meta.response_tenants(&result);
    if !tenants.is_empty() {
        note(|notes| notes.response_tenants.extend(tenants));
    }
    result
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

/// MIK-7116.MIN.1: this call is answered from a cache, past every gate.
pub(crate) fn note_cached() {
    note(|notes| notes.cached = true);
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
        if self.cached {
            if let Some(value) = delivered {
                tenants.extend(meta.response_tenants(value));
            }
        } else {
            tenants.extend(self.response_tenants.iter().cloned());
        }
        let mut fields = Map::new();
        if tenants.is_empty() {
            return fields;
        }
        let hashed: BTreeSet<String> = tenants
            .into_iter()
            .map(|id| crate::security::hash_argument(&Value::String(id)))
            .collect();
        fields.insert(
            "tenants".into(),
            hashed.into_iter().collect::<Vec<_>>().into(),
        );
        if !self.data_classes.is_empty() {
            let classes: Vec<Value> = self
                .data_classes
                .iter()
                .cloned()
                .map(Value::String)
                .collect();
            fields.insert("data_classes".into(), classes.into());
        }
        if self.cached {
            fields.insert("attribution".into(), "cached_delivery".into());
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
        let attribution = notes.attribution(self, tenants, result.as_ref().ok());
        let facts =
            super::super::admission::ReplayAudit::new(outcome, result.as_ref().ok().map(sha256_of));
        // #2472: a replay of this execution is recorded with these facts.
        if let Some(lease) = caller.execution {
            lease.note_audit(facts.clone());
        }
        self.write_invocation(log, args, session_id, caller, trace_id, &facts, attribution)
            .await
            .and(result)
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
        // MIK-7215.CONTROL.3/.3a: the caller's W3C trace id spans the whole
        // call, the session id is the legacy fallback, and the id minted for
        // this invocation keys the case where neither exists.
        let otel_trace_id = args
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
        // The modern HTTP route carries "no session" as `Some("")`; an empty
        // id is no key, or every stateless call would correlate as one.
        let session_id = session_id.filter(|session| !session.is_empty());
        let key = match (otel_trace_id.as_deref(), session_id) {
            (Some(otel), _) => CorrelationKey {
                id: otel,
                source: CorrelationSource::OtelTraceId,
            },
            (None, Some(session)) => CorrelationKey {
                id: session,
                source: CorrelationSource::SessionId,
            },
            (None, None) => CorrelationKey {
                id: trace_id,
                source: CorrelationSource::TraceId,
            },
        };
        let envelope = AuditEnvelope {
            trace_id: Some(trace_id.to_string()),
            otel_trace_id: otel_trace_id.clone(),
            outcome,
            who: AuditWho::from_caller(caller),
        };
        // F20: on the blocking pool, bounded; a stalled disk answers 503
        // instead of pinning a runtime worker.
        let (key_id, key_source) = (key.id.to_string(), key.source);
        let (srv, tl, request_hash) = (server.to_string(), tool.to_string(), sha256_of(args));
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
            super::super::admission::ReplayAudit::new(outcome, result.as_ref().ok().map(sha256_of))
        };
        let trace_id =
            crate::gateway::trace::current().unwrap_or_else(crate::gateway::trace::generate);
        // MIK-7116.MIN.1: a replay is answered past every gate, so it is
        // attributed like a cached delivery, from the value it delivers.
        let delivered = replay.result.as_ref();
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
