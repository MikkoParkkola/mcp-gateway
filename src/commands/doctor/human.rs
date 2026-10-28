// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Doctor's terminal text for one result: client-reachable text escaped.

use mcp_gateway::cli_support::shown;

use super::CheckResult;

/// One result's terminal lines. Its label, detail and hint can carry a
/// discovered server's name or a configured backend's: JSON keeps them raw,
/// the terminal gets them escaped, once, here.
pub(super) fn human_lines(badge: &str, result: &CheckResult) -> String {
    use std::fmt::Write as _;

    let mut lines = String::new();
    // Line by line: a detail's own breaks (the `--show-stderr` section)
    // stay, and every line's text is escaped, captured stderr included.
    let detail: Vec<String> = result
        .detail
        .split('\n')
        .map(|line| shown(line).to_string())
        .collect();
    let _ = writeln!(
        lines,
        "{badge} {}: {}",
        shown(&result.label),
        detail.join("\n")
    );
    if let Some(hint) = &result.hint {
        let _ = writeln!(lines, "       Hint: {}", shown(hint));
    }
    lines
}
