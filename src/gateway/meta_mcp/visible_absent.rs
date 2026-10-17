// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The answer and the memo entry for a name the caller cannot see.

use super::{VISIBILITY_MEMO, Visibility, Withholding};

/// The answer to a name that matches no tool (-32601). A tool withheld from
/// this caller answers with exactly this, so the two cannot be told apart.
pub(crate) fn absent_name(tool_name: &str) -> crate::Error {
    crate::Error::json_rpc(-32601, format!("Unknown tool: {tool_name}"))
}

/// Record `(server, tool)` absent for the rest of the request (MIK-8387).
/// Upgrade-only, unlike the first-judgement-wins record: an absence that lets
/// the call take the early path (past signing and admission) must hold even
/// over an earlier `Visible`, or a backend restored before the per-target
/// gate would be dispatched unadmitted. Nothing ever writes `Visible` over it.
pub(crate) fn record_absent(server: &str, tool: &str) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        let mut judged = memo.visibility.lock();
        let entry = judged
            .entry((server.to_owned(), tool.to_owned()))
            .or_insert(Visibility::Visible);
        if *entry == Visibility::Visible {
            *entry = Visibility::Withheld(Withholding::Absent);
        }
    });
}
