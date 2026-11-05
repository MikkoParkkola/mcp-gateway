// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The answer and the memo entry for a name the caller cannot see.

use crate::error::rpc_codes::METHOD_NOT_FOUND;

/// The answer to a name that matches no tool (-32601). A tool withheld from
/// this caller answers with exactly this, so the two cannot be told apart.
pub(crate) fn absent_name(tool_name: &str) -> crate::Error {
    crate::Error::json_rpc(METHOD_NOT_FOUND, format!("Unknown tool: {tool_name}"))
}

/// The absent answer for a withheld `judged`, with the withholding's pair and
/// no note: the record names the real reason; the caller sees an absent name.
pub(crate) fn absent_if_withheld_explained(
    judged: Option<super::Visibility>,
    tool: &str,
) -> crate::security::decision_record::Explained {
    match judged {
        Some(super::Visibility::Withheld(reason)) => {
            Err((absent_name(tool), (reason.kind(), None)))
        }
        _ => Ok(()),
    }
}

/// [`super::memo::refuse_withheld`], with the withholding's pair and no note.
pub(crate) fn refuse_withheld_explained(
    server: &str,
    tool: &str,
) -> crate::security::decision_record::Explained {
    absent_if_withheld_explained(super::memo::recorded_visibility(server, tool), tool)
}
