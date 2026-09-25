// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1: one invocation record per `gateway_invoke`, written around
//! `invoke_tool_traced` so refusals and failures are recorded too.

use serde_json::Value;

use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho};
use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
use crate::{Error, Result};

impl AuditWho {
    /// The caller of an invocation. The only constructor the invoke path uses:
    /// `who` comes from the request's credential and verified subject, never
    /// from a label or an email.
    pub(crate) fn from_caller(caller: &MetaMcpCallerContext<'_>) -> Self {
        Self {
            credential_kind: Some(caller.credential_kind),
            principal: caller.credential_principal.unwrap_or_default().to_string(),
            account: caller.api_key_name.unwrap_or("anonymous").to_string(),
            authority: caller.grant_subject.as_ref().map(|g| g.authority.clone()),
            subject: caller.grant_subject.as_ref().map(|g| g.subject.clone()),
        }
    }
}

tokio::task_local! {
    /// The code of a backend dispatch failure that `invoke_tool_traced`
    /// turned into an `isError` tool result, for this call only.
    static DISPATCH_FAILURE: std::cell::Cell<Option<i32>>;
}

/// Note that the backend dispatch failed with `error`, though the caller will
/// get a tool result. Outside [`with_dispatch_scope`] this does nothing.
pub(super) fn note_dispatch_failure(error: &Error) {
    let _ = DISPATCH_FAILURE.try_with(|cell| cell.set(Some(error.to_rpc_code())));
}

/// Run one invocation, returning its output and any dispatch failure noted in it.
pub(super) async fn with_dispatch_scope<F: std::future::Future>(
    future: F,
) -> (F::Output, Option<i32>) {
    DISPATCH_FAILURE
        .scope(std::cell::Cell::new(None), async {
            let output = future.await;
            (output, DISPATCH_FAILURE.with(std::cell::Cell::get))
        })
        .await
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
    /// (D1-d.1). A failed call has no response hash. `dispatch_failure` is
    /// the code of a backend failure the call converted to a tool result.
    pub(super) fn audit_invocation(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        trace_id: &str,
        result: Result<Value>,
        dispatch_failure: Option<i32>,
    ) -> Result<Value> {
        let Some(log) = self.transparency_logger.as_ref() else {
            return result;
        };
        if result.is_err() {
            return result;
        }
        let Some(outcome) = AuditOutcome::from_result(&result) else {
            return result;
        };
        // A backend failure delivered as a tool result is still an `error`.
        let outcome = match (outcome, dispatch_failure) {
            (AuditOutcome::ToolError, Some(code)) => AuditOutcome::Error(code),
            (outcome, _) => outcome,
        };
        let server = args
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let tool = args.get("tool").and_then(Value::as_str).unwrap_or_default();
        let response_hash = result.as_ref().ok().map(sha256_of);
        // MIK-7215.CONTROL.3/.3a: the caller's W3C trace id spans the whole
        // call, the session id is the legacy fallback, and the id minted for
        // this invocation keys the case where neither exists.
        let otel_trace_id = args
            .get("_meta")
            .and_then(crate::protocol::trace::TraceContext::from_meta)
            .and_then(|tc| tc.trace_id().map(str::to_string));
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
        let written = log.log_invocation_correlated(
            key,
            &envelope,
            server,
            tool,
            &sha256_of(args),
            response_hash.as_deref(),
        );
        match written {
            Ok(()) => result,
            Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
                tracing::error!(server, tool, trace_id, %error, "invocation audit write failed; result withheld");
                Err(Error::AuditUnavailable)
            }
            Err(error) => {
                tracing::warn!(server, tool, trace_id, %error, "Transparency log write failed (non-fatal)");
                result
            }
        }
    }
}
