// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source scan: no log line is written while a tool-cache lock is held.
//!
//! `commit_verdicts` runs under the descriptor gate's own locks and, on a
//! store, inside the tools cache's write guard. Status readers take both, so a
//! log sink that stops reading would stall them. The macros belong after the
//! guards are released, in the caller that emits the returned lines.

const GATE: &str = include_str!("descriptor_gate.rs");
const KEYS: &str = include_str!("input_keys.rs");
const MACROS: [&str; 5] = ["info!(", "warn!(", "debug!(", "error!(", "trace!("];

/// The text from `start` to the first `end` after it.
fn span<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source.find(start).expect("the scanned code moved");
    let rest = &source[from..];
    let to = rest[start.len()..]
        .find(end)
        .expect("the scanned span has no end");
    &rest[..start.len() + to]
}

fn logging_in(text: &str) -> Vec<&'static str> {
    MACROS.into_iter().filter(|m| text.contains(m)).collect()
}

#[test]
fn commit_verdicts_logs_nothing_while_it_holds_the_gate_locks() {
    let body = span(GATE, "pub(crate) fn commit_verdicts", "\n    }\n");
    assert_eq!(logging_in(body), Vec::<&str>::new());
}

#[test]
fn the_store_closure_that_commits_verdicts_logs_nothing_under_the_cache_guard() {
    let closure = span(
        KEYS,
        "entry.tools_cache.replace(parsed, || {",
        "\n        });",
    );
    assert_eq!(logging_in(closure), Vec::<&str>::new());
}
