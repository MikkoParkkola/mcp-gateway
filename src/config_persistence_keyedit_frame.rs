// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The frame of a file's one YAML document: the directives, comments and
//! `---` line before it, and the `...` line and comments after it. The key
//! editor keeps every frame line byte for byte and edits only inside it.

/// A blank line, or one holding only a comment.
pub(super) fn blank_or_comment(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with('#')
}

/// Where the one document of a file sits, by 0-based line, line endings
/// aside: the head before it (directives, comments and blank lines, then one
/// `---` line) and the tail after it (one `...` line, then comments and blank
/// lines) are its frame.
pub(super) struct Frame {
    /// The document's lines. A `---` line that also holds document content
    /// is the head's last line and the body's first.
    pub(super) body: std::ops::Range<usize>,
}

/// The rest of `line` after the marker `mark` (`---` or `...`), trimmed,
/// when the marker ends the line or a space or a tab follows it.
fn marker<'a>(line: &'a str, mark: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(mark)?;
    (rest.is_empty() || rest.starts_with([' ', '\t'])).then(|| rest.trim())
}

/// The frame of `text` (which holds no byte order mark), or `None` when a
/// marker or directive sits anywhere else.
pub(super) fn frame(text: &str) -> Option<Frame> {
    let lines: Vec<&str> = text.lines().collect();
    let (mut start, mut shared_start, mut directive) = (0, None, false);
    for (n, line) in lines.iter().enumerate() {
        if let Some(rest) = marker(line, "---") {
            start = if rest.is_empty() || rest.starts_with('#') {
                n + 1
            } else {
                n
            };
            shared_start = (start == n).then_some(n);
            directive = false;
            break;
        }
        if line.starts_with('%') {
            directive = true;
        } else if !blank_or_comment(line) {
            break;
        }
    }
    let mut end = lines.len();
    for (n, line) in lines.iter().enumerate().rev() {
        if let Some(rest) = marker(line, "...") {
            if !(rest.is_empty() || rest.starts_with('#')) {
                return None;
            }
            end = n;
            break;
        }
        if !blank_or_comment(line) {
            break;
        }
    }
    let inside = lines.get(start.max(shared_start.map_or(0, |n| n + 1))..end.max(start))?;
    let stray = inside
        .iter()
        .any(|l| l.starts_with("---") || l.starts_with("...") || l.starts_with('%'));
    (!directive && !stray && start <= end).then_some(Frame { body: start..end })
}
