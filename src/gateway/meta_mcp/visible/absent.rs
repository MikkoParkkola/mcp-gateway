// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The answer and the memo entry for a name the caller cannot see.

use crate::error::rpc_codes::METHOD_NOT_FOUND;

/// The answer to a name that matches no tool (-32601). A tool withheld from
/// this caller answers with exactly this, so the two cannot be told apart.
pub(crate) fn absent_name(tool_name: &str) -> crate::Error {
    crate::Error::json_rpc(METHOD_NOT_FOUND, format!("Unknown tool: {tool_name}"))
}
