// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::collections::BTreeSet;
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

/// How [`write_config_preserving`] starts a comment-loss refusal.
const REFUSAL: &str = "Not saved:";

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
        if mode == CommentLoss::Refuse || !refusal.starts_with(REFUSAL) {
            return Err(refusal);
        }
        write_config(path, config)
            .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
        eprintln!(
            "Warning: --force rewrites {} in full. Without it this write is refused:\n  {refusal}",
            path.display()
        );
        let after = std::fs::read_to_string(path).unwrap_or_default();
        return write_new_backends_as_url(path, &before, &after, config);
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
    write_new_backends_as_url(path, &before, &after, config)
}

/// A backend this write added, or one the file already gave a `url`, is saved
/// with `url`, not the older `http_url` or `ws_url` the serialiser emits.
/// Other backends are left as the operator wrote them; `mcp-gateway upgrade`
/// rewrites those.
fn write_new_backends_as_url(
    path: &Path,
    before: &str,
    after: &str,
    config: &Config,
) -> Result<(), String> {
    let (existing, with_url) = backend_names(before);
    let as_url: BTreeSet<String> = config
        .backends
        .keys()
        .filter(|name| !existing.contains(*name) || with_url.contains(*name))
        .cloned()
        .collect();
    if as_url.is_empty() {
        return Ok(());
    }
    let rewrite = rewrite_url_aliases(after, Some(&as_url));
    if rewrite.changed.is_empty() {
        return Ok(());
    }
    write_config_text(path, &rewrite.text)
}

/// The backend names a config text declares, and those of them written with
/// `url`; both empty when the text does not parse.
fn backend_names(text: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let backends = serde_yaml::from_str::<serde_yaml::Value>(text)
        .ok()
        .and_then(|v| {
            v.get("backends")
                .and_then(serde_yaml::Value::as_mapping)
                .cloned()
        })
        .unwrap_or_default();
    let mut names = BTreeSet::new();
    let mut with_url = BTreeSet::new();
    for (key, fields) in &backends {
        if let Some(name) = key.as_str() {
            names.insert(name.to_string());
            if fields.get("url").is_some() {
                with_url.insert(name.to_string());
            }
        }
    }
    (names, with_url)
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
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let rewrite = rewrite_url_aliases(&text, None);
    if mode == RewriteMode::Apply && !rewrite.changed.is_empty() {
        write_config_text(path, &rewrite.text)?;
    }
    Ok(rewrite)
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

    /// An I/O failure under `--force` comes back as that failure, not as a
    /// comment warning over a rewrite (a directory where the file goes makes
    /// the rename fail on every platform).
    #[test]
    fn an_io_failure_under_force_is_reported_as_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        std::fs::create_dir(&path).expect("dir in the way");
        let config = mcp_gateway::config::Config::default();
        let error = super::write(&path, &config, super::CommentLoss::Rewrite).expect_err("fails");
        assert!(
            error.starts_with("Failed to write") && !error.contains(super::REFUSAL),
            "{error}"
        );
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
