// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Doctor's terminal text for one result: client-reachable text escaped.

use mcp_gateway::cli_support::shown;

use super::CheckResult;

/// The `--show-stderr` banner: masking is best effort.
const STDERR_BANNER: &str =
    "  stderr tail (may contain secrets: masking is best effort, review before sharing):";
const NO_STDERR: &str = "  (no stderr captured)";
/// In front of each captured stderr line on the terminal: gateway text, so a
/// backend line never starts where a result line starts.
const STDERR_MARKER: &str = "  stderr | ";

/// One result's terminal lines. Its label, detail and hint can carry a
/// discovered server's name or a configured backend's: JSON keeps them raw,
/// the terminal gets them escaped, once, here.
pub(super) fn human_lines(badge: &str, result: &CheckResult) -> String {
    use std::fmt::Write as _;

    let mut lines = String::new();
    // The detail is one line whatever it holds (its own breaks are escaped).
    // Every line after it starts with gateway text: the stderr banner, or the
    // marker in front of each captured line, so no backend line can pass for
    // a result line.
    let _ = writeln!(
        lines,
        "{badge} {}: {}",
        shown(&result.label),
        shown(&result.detail)
    );
    if let Some(tail) = &result.stderr_tail {
        if tail.is_empty() {
            let _ = writeln!(lines, "{NO_STDERR}");
        } else {
            let _ = writeln!(lines, "{STDERR_BANNER}");
            for line in tail {
                let _ = writeln!(lines, "{STDERR_MARKER}{}", shown(line));
            }
        }
    }
    if let Some(hint) = &result.hint {
        let _ = writeln!(lines, "       Hint: {}", shown(hint));
    }
    lines
}

impl CheckResult {
    /// The detail with the stderr tail under it, as `--format json` emits
    /// it: raw, one text, unchanged from before the tail had its own field.
    pub(super) fn full_detail(&self) -> String {
        let mut text = self.detail.clone();
        match &self.stderr_tail {
            None => {}
            Some(tail) if tail.is_empty() => {
                text.push('\n');
                text.push_str(NO_STDERR);
            }
            Some(tail) => {
                text.push('\n');
                text.push_str(STDERR_BANNER);
                for line in tail {
                    text.push_str("\n    ");
                    text.push_str(line);
                }
            }
        }
        text
    }
}
