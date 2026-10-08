// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which comment lines a config write dropped, for the note a CLI command or
//! the web UI shows (MIK-8051). Line numbers only: a `#` inside a quoted
//! value can be a secret, so comment text is never quoted back.

/// The lines of `before` whose comment `after` no longer has, as `line N`.
/// Only the changed region is compared (the lines between the common head
/// and tail), so a repeated line elsewhere cannot stand in for a removed one,
/// and an edited line that keeps its comment does not count. Line numbers
/// only: a `#` inside a quoted value can be a secret.
pub(crate) fn dropped_comment_lines(before: &str, after: &str) -> Vec<String> {
    let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let head = b.iter().zip(&a).take_while(|(x, y)| x == y).count();
    let tail = b[head..]
        .iter()
        .rev()
        .zip(a[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (cb, ca) = (comments(&b), comments(&a));
    let mut kept: Vec<String> = ca[head..a.len() - tail].iter().flatten().cloned().collect();
    (head..b.len() - tail)
        .filter(|&i| {
            cb[i]
                .as_ref()
                .is_some_and(|c| match kept.iter().position(|k| k == c) {
                    Some(at) => {
                        kept.swap_remove(at);
                        false
                    }
                    None => true,
                })
        })
        .map(|i| format!("line {}", i + 1))
        .collect()
}

/// Each line's comment, if it has one. A candidate the line scanner finds
/// counts only when the YAML parser agrees: removing it leaves the document
/// unchanged. So a `#` inside a quoted, tagged or block scalar's text, or a
/// URL fragment, is never named.
fn comments(lines: &[&str]) -> Vec<Option<String>> {
    (0..lines.len())
        .map(|i| {
            let comment = super::splice::inline_comment(lines[i])?;
            super::splice::parsed_as_comment(lines, i, comment).then(|| comment.trim().to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::dropped_comment_lines;
    #[test]
    fn a_removed_entry_names_its_own_line_not_a_repeat_of_it() {
        let before = "backends:\n  a:\n    command: y  # why\n  b:\n    command: y  # why\n";
        let after = "backends:\n  a:\n    command: y  # why\n";
        assert_eq!(dropped_comment_lines(before, after), ["line 5"]);
    }

    #[test]
    fn an_edited_line_that_keeps_its_comment_is_not_reported() {
        let before = "backends:\n  a:\n    command: x  # pinned\n";
        let after = "backends:\n  a:\n    command: z  # pinned\n";
        assert!(dropped_comment_lines(before, after).is_empty());
    }

    #[test]
    fn every_comment_inside_a_removed_entry_is_named() {
        let before =
            "# top\nbackends:\n  a:\n    # note\n    command: x  # why\n  b:\n    command: y\n";
        let after = "# top\nbackends:\n  b:\n    command: y\n";
        assert_eq!(dropped_comment_lines(before, after), ["line 4", "line 5"]);
    }

    #[test]
    fn a_hash_inside_a_value_is_not_a_comment() {
        let before = "backends:\n  a:\n    http_url: \"http://h/#q\"\n    command: x#y\n  b:\n    command: y\n";
        let after = "backends:\n  b:\n    command: y\n";
        assert!(dropped_comment_lines(before, after).is_empty());
    }

    #[test]
    fn a_hash_inside_a_block_scalar_is_not_a_comment() {
        let before = "backends:\n  a:\n    description: |\n      step # one\n      # not a comment\n    command: x  # why\n  b:\n    command: y\n";
        let after = "backends:\n  b:\n    command: y\n";
        assert_eq!(dropped_comment_lines(before, after), ["line 6"]);
    }

    #[test]
    fn a_hash_inside_a_tagged_or_multiline_quoted_value_is_not_a_comment() {
        let before = "backends:\n  a:\n    description: !!str \"old # x\"\n    note: \"one\n      # two\"\n    command: x  # why\n  b:\n    command: y\n";
        let after = "backends:\n  b:\n    command: y\n";
        assert_eq!(dropped_comment_lines(before, after), ["line 6"]);
    }
}
