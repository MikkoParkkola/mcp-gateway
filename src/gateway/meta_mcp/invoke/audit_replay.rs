// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record of a replayed execution (#2472): answered past every gate, so
//! it says it was not decided again.

use serde_json::Value;

use super::{DispatchNotes, sha256_of};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::JsonRpcResponse;
use crate::security::audit::AuditOutcome;

impl MetaMcp {
    /// #2472: record a replay of a completed execution, which is a delivered
    /// call like any other (D1-d). Only an invocation is recorded, over the
    /// envelope its first execution hashed, and with that execution's
    /// outcome and response hash, under the server it was admitted for
    /// (`facts`), so it reads as the original record did. A meta tool that wrote no invocation record the first
    /// time writes none on replay. Under `FailClosed` a failed write
    /// withholds the replay (D1-f).
    pub(crate) async fn audit_replay(
        &self,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        replay: JsonRpcResponse,
        facts: crate::gateway::meta_mcp::admission::ReplayFacts,
    ) -> JsonRpcResponse {
        // A replay delivers a first run's answer: not this request's to state.
        crate::gateway::delivery_facts::unvouched();
        let server = facts.server.as_deref();
        self.stage_replay((tool_name, server), arguments, session_id, caller, &replay);
        let Some(log) = self.transparency_logger.as_ref() else {
            return replay;
        };
        let envelope = if tool_name == "gateway_invoke" {
            arguments.clone()
        } else if let Some(server) = server {
            crate::gateway::meta_mcp::admission::named_tool_envelope(
                server, tool_name, arguments, caller,
            )
        } else {
            return replay;
        };
        // The store is process memory, so this build wrote every entry; facts
        // are absent only when the first run wrote no record. Derive them from
        // the replayed response then, where a wrapped tool error reads as `ok`.
        let facts = if let Some(facts) = facts.audit {
            facts
        } else {
            let result = match (&replay.result, &replay.error) {
                (Some(value), _) => Ok(value.clone()),
                (None, Some(error)) => {
                    Err(crate::Error::json_rpc(error.code, error.message.clone()))
                }
                (None, None) => return replay,
            };
            let Some(outcome) = AuditOutcome::from_result(&result) else {
                return replay;
            };
            // A delivered error carries a code and no provenance, and `from_result`
            // reads a bare `-32001`/`-32004` as a gateway refusal: with no stored
            // class, that is a peer's answer as likely as a refusal.
            let outcome = match outcome {
                AuditOutcome::Denied(code) => AuditOutcome::Error(code),
                other => other,
            };
            crate::gateway::meta_mcp::admission::ReplayAudit::new(
                outcome,
                result.as_ref().ok().map(sha256_of),
            )
        };
        let trace_id =
            crate::gateway::trace::current().unwrap_or_else(crate::gateway::trace::generate);
        // MIK-7116.MIN.1: a replay is answered past every gate, so it is
        // attributed like a cached delivery, from the value it delivers. A
        // `gateway_invoke` result wraps the tool's value as JSON text
        // (`wrap_tool_success`); attribute that value, as a live call does.
        let unwrapped = match (tool_name, replay.result.as_ref()) {
            ("gateway_invoke", Some(result)) => crate::protocol::tool_result_payload(result),
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
        // Answered past every gate: nothing decided it again.
        let decision = Box::new(
            crate::security::decision_record::Noted::not_redecided().decision(
                crate::security::decision_record::Decided::Replayed,
                crate::security::decision_record::Refused::No,
                self.live_config().as_deref(),
            ),
        );
        match self
            .write_invocation(
                log,
                &envelope,
                session_id,
                caller,
                &trace_id,
                &facts,
                attribution,
                decision,
            )
            .await
        {
            // The replay's delivery joins this record.
            Ok(()) => replay.with_invocation_trace(trace_id.as_str().into()),
            Err(error) => replay.id.clone().map_or_else(
                || JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string()),
                |id| crate::gateway::meta_mcp::error_response_preserving_status(id, &error),
            ),
        }
    }
}
