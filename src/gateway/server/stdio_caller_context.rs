// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio caller context, moved unchanged out of `stdio_dispatch.rs` to
//! keep that file under the line ceiling.

use super::{Gateway, STDIO_CREDENTIAL_PRINCIPAL, StdioClient, StdioNonce};
use crate::gateway::meta_mcp::MetaMcpCallerContext;

impl Gateway {
    /// Handle `tools/call`: policy, signing, admission/replay, then dispatch.
    ///
    /// Ownership of `arguments` is taken only past every refusal — signing,
    /// nonce, admission, replay — because only an executing call needs to
    /// own its payload. `params` is re-derived from `request` here (already
    /// validated by the caller) so the immutable borrow it needs can end
    /// before the one branch below that needs `request` mutably.
    /// Build the stdio-path `MetaMcpCallerContext`, split out of
    /// [`Self::dispatch_tools_call`] purely to keep that function under the
    /// line budget — every field and its rationale are unchanged.
    pub(super) fn build_stdio_caller_context<'a>(
        is_modern: bool,
        protocol_revision: Option<&'a str>,
        stdio_authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
        retry: &'a crate::protocol::mrtr::RetryFields,
        request_shape: &crate::protocol::meta::RequestShape,
        client: StdioClient<'a>,
        // The record key, and the generation this message is judged by.
        (record_key, generation): (
            &crate::gateway::record_principal::RecordPrincipalKey,
            Option<&'a crate::config_reload::Generation>,
        ),
    ) -> MetaMcpCallerContext<'a> {
        MetaMcpCallerContext {
            // Filled after the route stage, by the task intent, when the
            // session serves `tasks/*` (its store is open) and the call asked
            // for a task; X14 has decided a destructive one before that.
            task: None,
            execution: None,
            signing: None,
            is_modern,
            protocol_revision,
            credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL),
            // The stdio constant, keyed like any principal (§16.11).
            record_principal: super::stdio_record_principal(record_key),
            authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
            credential_kind: crate::security::audit::CredentialKind::LocalTransport,
            authorizer: stdio_authorizer,
            // Stdio has no network surface: the client SPAWNED
            // this process and holds what the operator holds.
            // Withholding admin would disarm the single-user setup
            // the origin gate protects, and protect nothing.
            //
            // Explicit since the admin gate moved to the
            // dispatcher: it previously lived on the HTTP path
            // alone, so stdio was never checked and the default
            // non-admin context went unnoticed.
            admin: crate::gateway::authz::AdminStanding::Gateway,
            surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
            // MRTR.9 declares capabilities per request, in the same `_meta`
            // this shape was classified from, so a modern call is read there.
            //
            // A legacy or malformed shape carries no `_meta` to read, and on a
            // session transport that does not mean the client declared
            // nothing — it declared once, on the handshake. Falling back to it
            // is what lets a legacy stdio client be asked for the input it
            // announced; the bridge still refuses anything the handshake did
            // not name.
            input_capabilities: if is_modern {
                request_shape.declared_capabilities()
            } else {
                client.handshake_capabilities
            },
            retry,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            verified_identity: None,
            // The one client this process serves, for binding continuations.
            stdio_nonce: Some(StdioNonce::process()),
            caller_key: None,
            // Same `RequestShape` the `initialize` arm advertises against.
            era: request_shape.era(),
            // The serve loop's own channel: a stdio client reads the same
            // pipe an outbound request is written to, so it can be asked.
            // Non-serve-loop callers still pass `NoClientChannel`.
            channel: client.channel,
            // stdio speaks to one process over two pipes and
            // has no elicitation channel: there is no operator
            // this transport can reach, so a destructive call
            // it cannot confirm is refused rather than asked
            // about. Not "found no session" -- no asker can
            // exist here at all.
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            generation,
        }
    }
}
