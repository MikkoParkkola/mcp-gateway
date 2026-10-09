// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The MRTR.9 gate on a backend's interim result, shared by the dispatch and the
//! bridge's refusal of an undeclared last round.

use tracing::warn;

use super::undeclared_input_request;
use crate::Result;

/// MRTR.9, applied wherever a backend's interim first reaches the client: at
/// the dispatch, and again at a bridged exchange's last round (#569). One
/// helper so the two applications of one policy cannot drift.
pub(super) fn refuse_undeclared(
    interim: Option<&crate::protocol::mrtr::InputRequired>,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    server: &str,
    tool: &str,
    trace_id: &str,
) -> Result<()> {
    let Some(refused) = interim.and_then(|i| i.undeclared(caller.input_capabilities)) else {
        return Ok(());
    };
    // The backend stopped to ask, so this dispatch acted on nothing: the outer
    // lease does not keep the refusal as the call's outcome, or a keyed retry
    // that now declares the capability is served it instead of running
    // (MIK-8191). An earlier step of the same execution that did act keeps
    // its protection (`withdraw_dispatch`).
    if let Some(execution) = caller.execution {
        execution.withdraw_dispatch();
    }
    Err(refusal(&refused, server, tool, trace_id))
}

/// MRTR.9's refusal of one entry, logged once. Shared with the bridge's own
/// refusal of an undeclared last round, so both answer the client alike.
pub(super) fn refusal(
    refused: &crate::protocol::mrtr::Undeclared<'_>,
    server: &str,
    tool: &str,
    trace_id: &str,
) -> crate::Error {
    warn!(
        server,
        tool,
        trace_id,
        request_key = refused.key,
        method = refused.method,
        "Backend asked for input of a type the client did not declare"
    );
    undeclared_input_request(server, tool, refused)
}

/// The bridge's `Undeclared` refusal as the client sees it (#2173).
pub(super) fn bridge_refusal(
    key: &str,
    method: &str,
    reason: crate::protocol::mrtr::Refusal,
    server: &str,
    tool: &str,
    trace_id: &str,
) -> crate::Error {
    refusal(
        &crate::protocol::mrtr::Undeclared {
            key,
            method,
            reason,
        },
        server,
        tool,
        trace_id,
    )
}
