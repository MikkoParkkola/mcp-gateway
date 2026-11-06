// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! [`shown`] against the per-backslash version it replaced, kept here as the
//! reference: the same output for every input, in linear time.

use std::sync::mpsc;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use super::{is_hidden_char, shown};
use crate::test_wait::HANG_BOUND;

/// The version [`shown`] replaced, verbatim: each backslash rescans the rest
/// of its run, so a run of n backslashes costs O(n²).
fn reference(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (at, c) in text.char_indices() {
        if is_hidden_char(c) {
            out.extend(c.escape_unicode());
        } else if c == '\\' && reference_ends_in_escape(&text[at..]) {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
}

fn reference_ends_in_escape(rest: &str) -> bool {
    let after = rest.trim_start_matches('\\');
    after.starts_with("u{") || after.chars().next().is_some_and(is_hidden_char)
}

/// What may follow a backslash run: an escape opener, a hidden character, a
/// plain or multi-byte one, literal escape text, or nothing.
const AFTER: &[&str] = &[
    "u{", "u{202e}", "\u{1b}", "\r", "\n", "\u{7f}", "\u{85}", "\u{202e}", "\u{200b}", "\u{feff}",
    "\u{2066}", "\u{2028}", "a", "u", "{", "}", "é", "漢", "🦀", " ", "\\u{1b}", "",
];

/// One generated input: up to six pieces, each a run of 0-64 backslashes
/// and what follows it.
fn generated(rng: &mut StdRng) -> String {
    let mut text = String::new();
    for _ in 0..rng.random_range(1..=6) {
        text.push_str(&"\\".repeat(rng.random_range(0..=64)));
        text.push_str(AFTER[rng.random_range(0..AFTER.len())]);
    }
    text
}

#[test]
fn shown_matches_the_per_backslash_reference_on_generated_input() {
    // GIVEN: a fixed seed, so every run checks the same inputs
    let mut rng = StdRng::seed_from_u64(9318);
    for case in 0..5_000 {
        let text = generated(&mut rng);
        // WHEN / THEN: the same output as the version it replaced
        assert_eq!(
            shown(&text).to_string(),
            reference(&text),
            "case {case}: {text:?}"
        );
    }
    // And the fixed shapes: a Windows path, and runs at the end of the text.
    for text in ["C:\\Users\\me", "end\\", "end\\\\\\", "\\", ""] {
        assert_eq!(shown(text).to_string(), reference(text), "{text:?}");
    }
}

/// Backslashes before `u{` in the hang-guard row, sized from one measurement
/// of the reference and of [`shown`] on Spark's debug test build (2026-11-06):
/// the reference took 0.88 s at 10 000 backslashes, 3.5 s at 20 000, 13.9 s
/// at 40 000 and 53.9 s at 80 000, quadratic as expected; [`shown`] took
/// 0.4 ms at 20 000 and 4.0 ms at 200 000. So it passes 1 s near 10 700,
/// where [`shown`] is far under 50 ms, and at this size the reference would
/// need about 340 s, ten times [`HANG_BOUND`]: the bound fails it, never a
/// slow but linear run.
const HUGE: usize = 200_000;

#[test]
fn a_long_backslash_run_renders_within_the_hang_bound() {
    // GIVEN: one long run of backslashes before `u{`
    let text = "\\".repeat(HUGE) + "u{";

    // WHEN: it is shown on its own thread
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(shown(&text).to_string().len());
    });

    // THEN: it finishes within the bound, every backslash doubled
    let len = finished
        .recv_timeout(HANG_BOUND)
        .unwrap_or_else(|_| panic!("shown did not finish within {HANG_BOUND:?}"));
    assert_eq!(len, 2 * HUGE + 2);
}
