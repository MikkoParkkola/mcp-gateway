// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Line endings for a spliced `gateway.yaml` (MIK-8029).
//!
//! Every splice path says, for each line it writes, where the line came
//! from ([`Line`]), and [`render`] turns that into text. Nothing is inferred
//! from equal text afterwards, so a file that mixes `\n` and `\r\n`, repeats
//! a line, or ends without a line break keeps every line the splice did not
//! write byte for byte.

/// One line of a splice's result.
pub(super) enum Line {
    /// Source line `.0`, untouched: written byte for byte.
    Kept(usize),
    /// Source line `.0` rewritten as `.1`: it keeps the source line's ending.
    Replaced(usize, String),
    /// A line with no source line: it ends like its nearest neighbour.
    New(String),
}

/// The text `out` describes, over the lines of `original`.
///
/// A rewritten line keeps its source line's ending; a new line ends like the
/// line before it, or else the line after it, or else `\n`. The last line has
/// a break exactly when `original`'s last line had one, and a line that had
/// none but gains a successor takes its neighbour's.
pub(super) fn render(original: &str, out: &[Line]) -> String {
    let source: Vec<(&str, &str)> = original.split_inclusive('\n').map(split_ending).collect();
    let rows: Vec<(&str, &str)> = out
        .iter()
        .map(|line| match line {
            Line::Kept(at) => source[*at],
            Line::Replaced(at, text) => (text.as_str(), source[*at].1),
            Line::New(text) => (text.as_str(), ""),
        })
        .collect();
    let unbroken_end = !original.is_empty() && !original.ends_with('\n');
    // The nearest ending after each row, for a row with none of its own and
    // nothing before it: one backward pass, so lookups stay linear.
    let mut after = vec!["\n"; rows.len()];
    for at in (0..rows.len().saturating_sub(1)).rev() {
        let next = rows[at + 1].1;
        after[at] = if next.is_empty() { after[at + 1] } else { next };
    }
    let mut before: Option<&str> = None;
    let mut text = String::with_capacity(original.len() + 64);
    for (at, &(line, ending)) in rows.iter().enumerate() {
        text.push_str(line);
        if at + 1 == rows.len() && unbroken_end {
            break;
        }
        let ending = if ending.is_empty() {
            before.unwrap_or(after[at])
        } else {
            ending
        };
        text.push_str(ending);
        before = Some(ending);
    }
    text
}

/// A line split into its text and its ending (`\r\n`, `\n`, or none). A lone
/// `\r` is text, as the YAML splice sees it.
fn split_ending(line: &str) -> (&str, &str) {
    if let Some(text) = line.strip_suffix("\r\n") {
        (text, "\r\n")
    } else if let Some(text) = line.strip_suffix('\n') {
        (text, "\n")
    } else {
        (line, "")
    }
}
