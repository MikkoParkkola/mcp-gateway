// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Line endings for a spliced `gateway.yaml` (MIK-8029).
//!
//! The splice edits work on lines and join them with `\n`. Written back as
//! is, a file that mixes `\n` and `\r\n`, or ends without a line break,
//! would have every untouched line's ending rewritten. [`with_original_endings`]
//! gives each line outside the changed region its own ending back, byte for
//! byte; a written line takes the ending of the line it replaces, or of the
//! line it follows.

/// `edited` (joined with `\n`) with `original`'s line endings.
pub(super) fn with_original_endings(original: &str, edited: &str) -> String {
    let old: Vec<(&str, &str)> = original.split_inclusive('\n').map(split_ending).collect();
    let new: Vec<&str> = edited
        .split_inclusive('\n')
        .map(|line| split_ending(line).0)
        .collect();
    let head = old
        .iter()
        .zip(&new)
        .take_while(|((old, _), new)| old == *new)
        .count();
    let tail = old[head..]
        .iter()
        .rev()
        .zip(new[head..].iter().rev())
        .take_while(|((old, _), new)| old == *new)
        .count();
    // A written line ends like the first line it replaces, else like the
    // line before it; a file with no line break at all gets `\n`.
    let fill = old
        .get(head)
        .map(|&(_, ending)| ending)
        .filter(|ending| !ending.is_empty())
        .or_else(|| head.checked_sub(1).map(|before| old[before].1))
        .filter(|ending| !ending.is_empty())
        .unwrap_or("\n");
    let mut out = String::with_capacity(edited.len() + new.len());
    for &(line, ending) in &old[..head] {
        out.push_str(line);
        out.push_str(ending);
    }
    for line in &new[head..new.len() - tail] {
        out.push_str(line);
        out.push_str(fill);
    }
    for &(line, ending) in &old[old.len() - tail..] {
        out.push_str(line);
        out.push_str(ending);
    }
    // No final line break in the file: none after the edit either.
    if !original.is_empty() && !original.ends_with('\n') {
        let (kept, _) = split_ending(&out);
        out.truncate(kept.len());
    }
    out
}

/// A line split into its text and its ending (`\r\n`, `\n`, or none).
fn split_ending(line: &str) -> (&str, &str) {
    if let Some(text) = line.strip_suffix("\r\n") {
        (text, "\r\n")
    } else if let Some(text) = line.strip_suffix('\n') {
        (text, "\n")
    } else {
        (line, "")
    }
}
