// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::path::Path;

use mcp_gateway::config::Config;
use mcp_gateway::config_persistence::{write_config, write_config_preserving, write_config_text};

use super::backend_url_keys::{UrlRewrite, rewrite_url_aliases};

/// What a CLI write does when it cannot keep the file's comments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentLoss {
    /// Rewrite the whole file (`--force`).
    Rewrite,
    /// Write nothing and say which comment lines would be lost.
    Refuse,
}

/// `--force` rewrites a file whose comments cannot be kept; without it that
/// write is refused and nothing is written.
pub fn comment_loss(force: bool) -> CommentLoss {
    if force {
        CommentLoss::Rewrite
    } else {
        CommentLoss::Refuse
    }
}

/// How [`write_config_preserving`] starts a comment-loss refusal. A lock
/// refusal also starts "Not saved:", and `--force` must not override that one.
const REFUSAL: &str = "Not saved: this edit cannot be written into";

/// Write `config` to `path`; the error is a message ready to print.
///
/// Every write is tried as a refusing one first, so `--force` still names
/// the comment lines it drops before it rewrites the file. A write that
/// keeps the file's comments but removes an entry names the comment lines
/// that went with that entry.
pub fn write(path: &Path, config: &Config, mode: CommentLoss) -> Result<(), String> {
    let before = std::fs::read_to_string(path).unwrap_or_default();
    if let Err(refusal) = write_config_preserving(path, config) {
        // `--force` overrides only the comment check; a validation or I/O
        // failure is reported as itself, never as a comment warning.
        if mode == CommentLoss::Refuse || !is_comment_refusal(&refusal) {
            return Err(refusal);
        }
        write_config(path, config)
            .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
        eprintln!(
            "Warning: --force rewrites {} in full. Without it this write is refused:\n  {refusal}",
            path.display()
        );
        return Ok(());
    }
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

/// Whether a rewrite saves the file or only reports what it would change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RewriteMode {
    /// Save the rewritten file when a line changed.
    Apply,
    /// Report only (`upgrade --dry-run`).
    DryRun,
}

/// Rewrite every backend's `http_url` or `ws_url` in the config at `path` as
/// `url`, saving only when a line changed and `mode` applies. The error is a
/// message ready to print.
pub(crate) fn rewrite_url_aliases_in(path: &Path, mode: RewriteMode) -> Result<UrlRewrite, String> {
    let text = super::regular_file::read_regular_text(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let rewrite = rewrite_url_aliases(&text, None);
    if mode == RewriteMode::Apply && !rewrite.changed.is_empty() {
        write_config_text(path, &rewrite.text)?;
    }
    Ok(rewrite)
}

/// Whether `refusal` is the comment check, the only refusal `--force`
/// overrides. A busy or untakeable lock, a validation or an I/O failure is
/// reported as itself.
fn is_comment_refusal(refusal: &str) -> bool {
    refusal.starts_with(REFUSAL)
}

/// The lines of `before` whose comment `after` no longer has, as `line N`.
/// Only the changed region is compared (the lines between the common head
/// and tail), so a repeated line elsewhere cannot stand in for a removed one,
/// and an edited line that keeps its comment does not count. Line numbers
/// only: a `#` inside a quoted value can be a secret.
// ponytail: a copy of the library's `config_persistence::comments`, which the
// binary cannot call (crate-private). Delete it when MIK-8042's API change
// lands: the library then returns this note from the locked write itself.
fn dropped_comments(before: &str, after: &str) -> Vec<String> {
    let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let head = b.iter().zip(&a).take_while(|(x, y)| x == y).count();
    let tail = b[head..]
        .iter()
        .rev()
        .zip(a[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    // Only the changed region is classified: each candidate costs two parses.
    let (cb, ca) = (
        comments(&b, head..b.len() - tail),
        comments(&a, head..a.len() - tail),
    );
    let mut kept: Vec<String> = ca.into_iter().flatten().collect();
    (head..b.len() - tail)
        .filter(|&i| {
            cb[i - head]
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

/// The comment of each line in `region`, if it has one. A candidate `#`
/// counts only when the YAML parser agrees (removing it leaves the document
/// unchanged), so a `#` inside a quoted, tagged or block scalar, or a URL
/// fragment, is never named.
fn comments(lines: &[&str], region: std::ops::Range<usize>) -> Vec<Option<String>> {
    region
        .map(|i| {
            let line = lines[i];
            line.match_indices('#')
                .filter(|&(at, _)| at == 0 || line[..at].ends_with([' ', '\t']))
                .map(|(at, _)| &line[line[..at].trim_end_matches([' ', '\t']).len()..])
                .find(|comment| parsed_as_comment(lines, i, comment))
                .map(|comment| comment.trim().to_owned())
        })
        .collect()
}

/// Whether the parser reads `comment`, the tail of `lines[line]`, as a
/// comment: the document parses the same with and without it.
fn parsed_as_comment(lines: &[&str], line: usize, comment: &str) -> bool {
    let parse = |text: &[&str]| serde_yaml::from_str::<serde_yaml::Value>(&text.join("\n")).ok();
    let mut cut = lines.to_vec();
    cut[line] = &lines[line][..lines[line].len() - comment.len()];
    matches!((parse(lines), parse(&cut)), (Some(with), Some(without)) if with == without)
}

#[cfg(test)]
mod tests {
    use super::dropped_comments;

    /// A lock refusal under `--force` is reported as itself: `--force`
    /// overrides only the comment check, never another writer's lock (a
    /// directory where the lock file goes makes the lock fail at once).
    #[test]
    fn a_lock_refusal_under_force_is_not_overridden() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        std::fs::write(&path, "backends: {}\n").expect("write");
        std::fs::create_dir(dir.path().join(".gateway.yaml.lock")).expect("dir in the way");
        let config = mcp_gateway::config::Config::default();
        let error = super::write(&path, &config, super::CommentLoss::Rewrite).expect_err("fails");
        assert!(error.starts_with("Not saved: cannot lock"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "backends: {}\n"
        );
    }

    /// A failure under `--force` comes back as that failure, not as a comment
    /// warning over a rewrite (a directory where the file goes fails the
    /// load under the lock on every platform).
    #[test]
    fn an_io_failure_under_force_is_reported_as_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        std::fs::create_dir(&path).expect("dir in the way");
        let config = mcp_gateway::config::Config::default();
        let error = super::write(&path, &config, super::CommentLoss::Rewrite).expect_err("fails");
        assert!(
            error.starts_with("Failed to load") && !error.contains(super::REFUSAL),
            "{error}"
        );
    }

    /// MIK-8051: a `#` the parser keeps as text (a URL fragment, a block
    /// scalar line, a tagged or multi-line quoted value) is never named; a
    /// real comment after one is.
    #[test]
    fn a_hash_the_parser_keeps_as_text_is_not_a_comment() {
        let after = "backends:\n  b:\n    command: y\n";
        let rows = [
            (
                "backends:\n  a:\n    http_url: \"http://h/#q\"\n    command: x#y\n  b:\n    command: y\n",
                vec![],
            ),
            (
                "backends:\n  a:\n    description: |\n      step # one\n      # not a comment\n    command: x  # why\n  b:\n    command: y\n",
                vec!["line 6"],
            ),
            (
                "backends:\n  a:\n    description: !!str \"old # x\"\n    note: \"one\n      # two\"\n    command: x  # why\n  b:\n    command: y\n",
                vec!["line 6"],
            ),
            (
                "backends:\n  a:\n    description: !!str \"old # x\" # real\n  b:\n    command: y\n",
                vec!["line 3"],
            ),
        ];
        for (before, want) in rows {
            assert_eq!(dropped_comments(before, after), want, "{before}");
        }
    }

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
