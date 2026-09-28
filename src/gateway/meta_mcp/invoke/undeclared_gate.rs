// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The MRTR.9 gate on a backend's interim result, shared by the dispatch and a
//! bridged exchange's last round.

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
    warn!(
        server,
        tool,
        trace_id,
        request_key = refused.key,
        method = refused.method,
        "Backend asked for input of a type the client did not declare"
    );
    Err(undeclared_input_request(server, tool, &refused))
}
