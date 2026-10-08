// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Line endings for a spliced `gateway.yaml` (MIK-8029).
//!
//! The splice edits work on lines and join them with `\n`. Written back as
//! is, a file that mixes `\n` and `\r\n`, or ends without a line break,
//! would have every untouched line's ending rewritten. [`with_original_endings`]
//! gives each untouched line its own ending back, byte for byte; a written
//! line ends like the line it replaces, or else like the line before it.

/// `edited` (joined with `\n`) with `original`'s line endings.
pub(super) fn with_original_endings(original: &str, edited: &str) -> String {
    let old: Vec<(&str, &str)> = original.split_inclusive('\n').map(split_ending).collect();
    // The edits end lines with `\n` only, so a `\r` before it is the line's
    // own text (a file ending in a lone `\r` keeps it).
    let new: Vec<&str> = edited
        .split_inclusive('\n')
        .map(|line| line.strip_suffix('\n').unwrap_or(line))
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
    let changed_end = old.len() - tail;
    let mut lines: Vec<(&str, &str)> = old[..head].to_vec();
    // Between the first and last edit, a line the edits left alone is found
    // in order and keeps its ending; a written line ends like the line it
    // replaces, or else like the line before it.
    let mut next = head;
    for &text in &new[head..new.len() - tail] {
        let kept = old[next..changed_end]
            .iter()
            .position(|&(old, _)| old == text);
        let ending = if let Some(at) = kept {
            next += at + 1;
            old[next - 1].1
        } else {
            old[next..changed_end]
                .first()
                .map(|&(_, ending)| ending)
                .filter(|ending| !ending.is_empty())
                .or_else(|| lines.last().map(|&(_, ending)| ending))
                .unwrap_or("\n")
        };
        lines.push((text, ending));
    }
    lines.extend_from_slice(&old[changed_end..]);

    let unterminated = !original.is_empty() && !original.ends_with('\n');
    let mut out = String::with_capacity(edited.len() + lines.len());
    let mut before = "\n";
    for (at, &(text, ending)) in lines.iter().enumerate() {
        out.push_str(text);
        // Every line but the last needs a break, so a last line that gains a
        // successor gets the one before it; the file's last line keeps having
        // none if it had none.
        let ending = if ending.is_empty() { before } else { ending };
        if at + 1 < lines.len() || !unterminated {
            out.push_str(ending);
        }
        before = ending;
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
