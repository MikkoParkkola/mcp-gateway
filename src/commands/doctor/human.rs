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
    // The detail is one line whatever it holds (its own breaks are escaped);
    // only the gateway's own lines, such as the stderr tail, start a line.
    let _ = writeln!(
        lines,
        "{badge} {}: {}",
        shown(&result.label),
        shown(&result.detail)
    );
    for line in &result.detail_lines {
        let _ = writeln!(lines, "{}", shown(line));
    }
    if let Some(hint) = &result.hint {
        let _ = writeln!(lines, "       Hint: {}", shown(hint));
    }
    lines
}

impl CheckResult {
    /// The detail with the gateway's own lines under it, as `--format json`
    /// emits it: raw, one text.
    pub(super) fn full_detail(&self) -> String {
        let mut text = self.detail.clone();
        for line in &self.detail_lines {
            text.push('\n');
            text.push_str(line);
        }
        text
    }
}
