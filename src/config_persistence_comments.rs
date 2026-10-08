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
    // Only the changed region is classified: each candidate costs two parses
    // of the whole file, so classifying every line would be quadratic.
    let (cb, ca) = (
        comments(&b, head..b.len() - tail),
        comments(&a, head..a.len() - tail),
    );
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

/// Each line's comment, if it has one. A candidate `#` counts only when
/// the YAML parser agrees: removing it leaves the document
/// unchanged. So a `#` inside a quoted, tagged or block scalar's text, or a
/// URL fragment, is never named.
/// Lines outside `region` are not classified (`None`).
fn comments(lines: &[&str], region: std::ops::Range<usize>) -> Vec<Option<String>> {
    (0..lines.len())
        .map(|i| {
            if !region.contains(&i) {
                return None;
            }
            // Each `#` after a blank (or at the start) is a candidate, tried in
            // order: one inside a value is rejected and the next is tried.
            let line = lines[i];
            line.match_indices('#')
                .filter(|&(at, _)| at == 0 || line[..at].ends_with([' ', '\t']))
                .map(|(at, _)| &line[line[..at].trim_end_matches([' ', '\t']).len()..])
                .find(|comment| {
                    #[cfg(test)]
                    PARSE_CHECKS.with(|n| n.set(n.get() + 1));
                    super::splice::parsed_as_comment(lines, i, comment)
                })
                .map(|comment| comment.trim().to_owned())
        })
        .collect()
}

#[cfg(test)]
thread_local! {
    /// Parser checks made on this thread, for the bound test.
    static PARSE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::{PARSE_CHECKS, dropped_comment_lines};
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

    #[test]
    fn a_real_comment_after_a_hash_inside_a_value_is_named() {
        let before =
            "backends:\n  a:\n    description: !!str \"old # x\" # real\n  b:\n    command: y\n";
        let after = "backends:\n  b:\n    command: y\n";
        assert_eq!(dropped_comment_lines(before, after), ["line 3"]);
    }

    /// Removing one entry from a 2,000-entry file checks only that entry's
    /// comment with the parser, not every comment in the file.
    #[test]
    fn only_the_changed_region_is_parsed() {
        let entry = |n: usize| format!("  b{n}:\n    command: x  # c{n}\n");
        let before: String = std::iter::once("backends:\n".to_owned())
            .chain((0..2000).map(entry))
            .collect();
        let after = before.replacen(&entry(1000), "", 1);
        PARSE_CHECKS.with(|n| n.set(0));
        assert_eq!(dropped_comment_lines(&before, &after), ["line 2003"]);
        let checks = PARSE_CHECKS.with(std::cell::Cell::get);
        assert!(checks <= 2, "{checks} parser checks for one removed entry");
    }
}
