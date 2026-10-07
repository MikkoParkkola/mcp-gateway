// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::path::Path;

use mcp_gateway::config::Config;
use mcp_gateway::config_persistence::{CommentLoss, Unwritten, write_config_with};

/// `--force` rewrites a file whose comments cannot be kept; without it that
/// write is refused and nothing is written.
pub fn comment_loss(force: bool) -> CommentLoss {
    if force {
        CommentLoss::Rewrite
    } else {
        CommentLoss::Refuse
    }
}

/// Write `config` to `path`; the error is a message ready to print.
///
/// Every write is tried as a refusing one first, so `--force` still names
/// the comment lines it drops before it rewrites the file. A write that
/// keeps the file's comments but removes an entry names the comment lines
/// that went with that entry.
pub fn write(path: &Path, config: &Config, mode: CommentLoss) -> Result<(), String> {
    let message = |e: Unwritten| match e {
        Unwritten::CommentLoss(message) => message,
        Unwritten::Failed(message) => format!("Failed to write {}: {message}", path.display()),
    };
    let before = std::fs::read_to_string(path).unwrap_or_default();
    match write_config_with(path, config, CommentLoss::Refuse) {
        Err(Unwritten::CommentLoss(refusal)) if mode == CommentLoss::Rewrite => {
            eprintln!(
                "Warning: --force rewrites {} in full. Without it this write is refused:\n  {refusal}",
                path.display()
            );
            write_config_with(path, config, CommentLoss::Rewrite).map_err(message)
        }
        result => {
            result.map_err(message)?;
            let after = std::fs::read_to_string(path).unwrap_or_default();
            let gone = dropped_comments(&before, &after);
            if !gone.is_empty() {
                // A removed entry takes its own comments with it; say so.
                eprintln!(
                    "Note: comments inside the changed entry went with it ({}): {}",
                    path.display(),
                    gone.join("; ")
                );
            }
            Ok(())
        }
    }
}

/// The lines of `before` whose comment `after` no longer has, as `line N`.
/// Only the changed region is compared (the lines between the common head
/// and tail), so a repeated line elsewhere cannot stand in for a removed one,
/// and an edited line that keeps its comment does not count. Line numbers
/// only: a `#` inside a quoted value can be a secret.
fn dropped_comments(before: &str, after: &str) -> Vec<String> {
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
    use super::dropped_comments;

    #[test]
    fn a_removed_entry_names_its_own_line_not_a_repeat_of_it() {
        let before = "backends:\n  a:\n    command: y  # why\n  b:\n    command: y  # why\n";
        let after = "backends:\n  a:\n    command: y  # why\n";
        assert_eq!(dropped_comments(before, after), ["line 5"]);
    }

    #[test]
    fn an_edited_line_that_keeps_its_comment_is_not_reported() {
        let before = "backends:\n  a:\n    command: x  # pinned\n";
        let after = "backends:\n  a:\n    command: z  # pinned\n";
        assert!(dropped_comments(before, after).is_empty());
    }

    #[test]
    fn every_comment_inside_a_removed_entry_is_named() {
        let before =
            "# top\nbackends:\n  a:\n    # note\n    command: x  # why\n  b:\n    command: y\n";
        let after = "# top\nbackends:\n  b:\n    command: y\n";
        assert_eq!(dropped_comments(before, after), ["line 4", "line 5"]);
    }
}
