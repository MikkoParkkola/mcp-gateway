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
    let comment = |line: &str| line.find('#').map(|at| line[at..].trim_end().to_owned());
    let mut kept: Vec<String> = a[head..a.len() - tail]
        .iter()
        .copied()
        .filter_map(comment)
        .collect();
    (head..b.len() - tail)
        .filter(|&i| {
            comment(b[i]).is_some_and(|c| match kept.iter().position(|k| *k == c) {
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
}
