// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stdio entry points and single-request dispatch (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tracing::warn;

use super::Gateway;
#[cfg(test)]
use super::{STDIO_CREDENTIAL_PRINCIPAL, StdioNonce};
use super::{StdioTelemetry, stdio_delivery, stdio_tasks};
use crate::Result;
use crate::gateway::meta_mcp::MetaMcp;
#[cfg(test)]
use crate::gateway::meta_mcp::MetaMcpCallerContext;

/// Who the stdio dispatcher is serving: the session's id, the channel that
/// reaches that client, and what its handshake said it can be asked for.
///
/// Passed as one value because the three are only ever read as a set, and
/// because a caller context built from two of them plus a default for the
/// third is precisely the defect this path had twice over — a
/// `NoClientChannel` for a client that could be asked, then
/// `Declared::NONE` for one that had declared on the handshake.
#[derive(Clone, Copy)]
pub(super) struct StdioClient<'a> {
    pub(super) session_id: &'a str,
    pub(super) channel: &'a dyn crate::gateway::input_bridge::ClientChannel,
    pub(super) handshake_capabilities: crate::protocol::meta::Declared,
    /// The session's task store; `None` serves no `tasks/*` (MIK-7272.OWNER.2).
    pub(super) tasks: Option<&'a stdio_tasks::StdioTasks>,
    /// `server.modern_protocol` at stdio start: whether `server/discover`
    /// lists 2026-07-28 (MIK-7217.STDIO.1, design D7).
    pub(super) modern: bool,
}

/// Copy only the fields backend target mapping routes on.
///
/// `gateway_invoke` routes on `server` and `tool`, `gateway_execute` on
/// each `chain` step's `tool` or a single top-level `tool`, and a
/// surfaced tool routes on its own name. Everything else in the tree is
/// the payload, which the mapping copies into a target and the response
/// contract then never reads. A malformed key is left out exactly as
/// the mapping would have ignored it, so the servers and tools derived
/// from this projection are the ones derived from the whole tree.
pub(super) fn stdio_routing_keys_only(arguments: &serde_json::Value) -> serde_json::Value {
    let mut routing = serde_json::Map::new();
    for key in ["server", "tool"] {
        if let Some(value) = arguments.get(key).filter(|value| value.is_string()) {
            routing.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(chain) = arguments.get("chain").and_then(serde_json::Value::as_array) {
        let steps = chain
            .iter()
            .map(|step| {
                let mut routing = serde_json::Map::new();
                if let Some(tool) = step.get("tool").filter(|tool| tool.is_string()) {
                    routing.insert("tool".to_owned(), tool.clone());
                }
                serde_json::Value::Object(routing)
            })
            .collect();
        routing.insert("chain".to_owned(), serde_json::Value::Array(steps));
    }
    serde_json::Value::Object(routing)
}

/// Move the client's `params._meta` into the call's `arguments`.
///
/// The borrowed merge can only insert into a copy, because it holds a
/// view of someone else's tree. This dispatcher owns the request, so
/// the same insertion is a move: `arguments` and `_meta` are taken out
/// of the request — which nothing reads after the dispatch below — and
/// handed to the merge's own insertion step. Neither subtree is copied,
/// so an unbounded payload and an unbounded `_meta` both cost the same
/// as a small one.
///
/// Called only where `client_meta_insert_required` has just answered
/// yes, so the fallbacks here are the shapes that predicate already
/// excluded; each returns what the merge returns for it. An absent
/// `arguments` becomes the `{}` the borrowed path substitutes, and
/// still receives the metadata.
pub(super) fn stdio_take_merged_client_meta(request: &mut serde_json::Value) -> serde_json::Value {
    let empty = || serde_json::Value::Object(serde_json::Map::new());
    let Some(params) = request
        .get_mut("params")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return empty();
    };
    let Some(meta) = params.remove("_meta") else {
        return empty();
    };
    let arguments = params
        .get_mut("arguments")
        .map_or_else(empty, serde_json::Value::take);
    super::super::router::helpers::insert_client_meta(arguments, meta)
}

/// A test fixture approximating the caller context a stdio `tools/call`
/// runs under -- why stdio is admin, why it has no channel and no asker --
/// in one named place instead of forty lines per test.
///
/// NOT the production path. `dispatch_tools_call` builds its own context
/// inline (via `build_stdio_caller_context`, `stdio_dispatch.rs`) and carries the negotiated `protocol_revision`,
/// which this fixture hardcodes to `None`. An earlier doc comment here
/// claimed the helper had been extracted from `dispatch_single_with_sink`;
/// it never was, and no production arm calls it. Assert production stdio
/// behaviour against the dispatcher, not against this.
#[cfg(test)]
pub(super) fn stdio_caller_context<'a>(
    authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
    era: crate::protocol::meta::Era,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        // stdio has no task route: the extension's handle is read back over
        // `tasks/get`, which only the HTTP surface serves.
        task: None,
        execution: None,
        signing: None,
        is_modern: era == crate::protocol::meta::Era::Modern,
        protocol_revision: None,
        credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::LocalTransport,
        authorizer,
        // Stdio has no port and no network surface: the
        // client SPAWNED this process, so it already holds
        // whatever the operator holds — it could edit the
        // config file just as easily. Withholding admin
        // here would take the management tools away from
        // exactly the single-user setup the origin gate
        // exists to protect, and protect nothing.
        //
        // Explicit since the admin gate moved to the
        // dispatcher: it previously lived on the HTTP path
        // alone, so stdio was never checked and the default
        // non-admin context went unnoticed.
        is_admin: true,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        // stdio carries no per-request capability
        // declaration to read, and absent means absent.
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        // Same `shape` the `initialize` arm advertises
        // against, two arms up.
        era,
        // No `ProxyManager` in this scope -- it is HTTP-only
        // -- so there is no session to put a request on.
        channel: &crate::gateway::input_bridge::NoClientChannel,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        verified_identity: None,
        stdio_nonce: Some(StdioNonce::process()),
        caller_key: None,
        // stdio speaks to one process over two pipes and has no elicitation channel:
        // there is no operator this transport can reach, so a destructive call it
        // cannot confirm is refused rather than asked about. Not "found no session"
        // -- no asker can exist here at all.
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

impl Gateway {
    /// Run the gateway in stdio mode.
    ///
    /// Reads newline-delimited JSON-RPC from stdin and writes responses to stdout.
    /// Reuses the same `MetaMcp` dispatch logic as the HTTP server so all meta-tools
    /// (`gateway_search_tools`, `gateway_invoke`, etc.) work identically.
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration or `MetaMcp` initialisation fails.
    ///
    /// # Panics
    ///
    /// Panics if RSA key pair generation fails on all retry attempts.
    pub async fn run_stdio(self) -> Result<()> {
        let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
        self.run_stdio_on(
            stdin,
            stdout,
            #[cfg(test)]
            None,
        )
        .await
    }

    /// Dispatch a single JSON-RPC request through `MetaMcp`.
    ///
    /// Returns `None` for notifications (no response expected per JSON-RPC spec).
    #[cfg(test)]
    pub(super) async fn dispatch_single(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: &serde_json::Value,
        session_id: &str,
    ) -> Option<serde_json::Value> {
        Self::dispatch_single_with_sink(
            meta_mcp,
            tool_policy,
            mtls_policy,
            request.clone(),
            StdioClient {
                session_id,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: crate::protocol::meta::Declared::NONE,
                tasks: None,
                modern: false,
            },
            &StdioTelemetry::default(),
        )
        .await
    }

    /// Dispatch one stdio request, durably recording its inbound observation
    /// before any handler can await, fail, or terminate the process.
    /// NFR.OBS.1's stdio half: record one inbound observation and flush it.
    ///
    /// Its own function so the dispatcher below reads as dispatch; the two
    /// calls are the same either way.
    pub(super) fn observe_stdio_inbound(
        request: &serde_json::Value,
        params: Option<&serde_json::Value>,
        method: &str,
        session_id: &str,
        sink: Option<&mut crate::protocol_revision_telemetry::DurableTelemetrySink>,
    ) {
        crate::protocol_revision_telemetry::observe_inbound_request(
            request,
            params,
            method,
            None,
            Some(session_id),
            crate::protocol_revision_telemetry::Transport::Stdio,
        );
        if let Some(sink) = sink
            && let Err(error) = sink.persist_global()
        {
            warn!(
                %error,
                "failed to persist inbound stdio protocol-revision observation; measurement window is incomplete"
            );
        }
    }

    /// [`Self::dispatch_single_staged`] recording the receipts straight away,
    /// for a caller that judges no frame (a test).
    #[cfg(test)]
    pub(super) async fn dispatch_single_with_sink(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: serde_json::Value,
        client: StdioClient<'_>,
        sink: &StdioTelemetry,
    ) -> Option<serde_json::Value> {
        let session_id = client.session_id;
        let (answer, staged) =
            Self::dispatch_single_staged(meta_mcp, tool_policy, mtls_policy, request, client, sink)
                .await;
        // No frame is judged here: recorded and settled as built, and the
        // receipts follow the frame as `judge_and_commit` has them follow it.
        let Some(answer) = answer else {
            staged.commit(false);
            return None;
        };
        let frame = answer.delivered_unjudged(meta_mcp, session_id).await;
        staged.commit(frame.delivers_result());
        frame.stdio_value().map(std::borrow::Cow::into_owned)
    }

    /// [`Self::dispatch_relay_scoped`] inside one relay-receipt collector,
    /// which spans dispatch and finalize (COLLUDE.1 §13.3), returning what it
    /// staged: the caller records it after the answer's read verdict. With
    /// relay detection off there is nothing to collect, and no box to allocate.
    #[allow(
        clippy::large_futures,
        reason = "the unboxed arm is the dispatch as it ran before the collector"
    )]
    pub(super) async fn dispatch_single_staged(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: serde_json::Value,
        client: StdioClient<'_>,
        sink: &StdioTelemetry,
    ) -> (
        Option<stdio_delivery::StdioAnswer>,
        crate::gateway::meta_mcp::invoke::relay::StagedReceipts,
    ) {
        let dispatch =
            Self::dispatch_relay_scoped(meta_mcp, tool_policy, mtls_policy, request, client, sink);
        if meta_mcp.relay_active() {
            return meta_mcp.collecting_staged(Box::pin(dispatch)).await;
        }
        (
            dispatch.await,
            crate::gateway::meta_mcp::invoke::relay::StagedReceipts::none(),
        )
    }

    /// Dispatch a JSON-RPC batch request.
    #[cfg(test)]
    pub(super) async fn dispatch_batch(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
    ) -> Vec<serde_json::Value> {
        Self::dispatch_batch_with_sink(
            meta_mcp,
            tool_policy,
            mtls_policy,
            batch,
            session_id,
            &StdioTelemetry::default(),
        )
        .await
    }
}
