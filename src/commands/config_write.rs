// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::path::Path;

use mcp_gateway::config::Config;
use mcp_gateway::config_persistence::{edit_config, write_config, write_config_text};

use super::backend_url_keys::{UrlRewrite, rewrite_url_aliases};
use super::retired_config_keys::Retired;

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

/// How [`edit_config`] starts a comment-loss refusal. A lock
/// refusal also starts "Not saved:", and `--force` must not override that one.
const REFUSAL: &str = "Not saved: this edit cannot be written into";

/// Load `path`, apply `edit`, and write the result; the error is a message
/// ready to print. The load, `edit` and the write share one hold of the
/// config lock, so another writer's change is never overwritten.
///
/// Every write is tried as a refusing one first, so `--force` still names
/// the comment lines it drops before it rewrites the file. A write that
/// keeps the file's comments but removes an entry names the comment lines
/// that went with that entry.
///
/// `--force` alone rewrites from the config the refused try edited, under a
/// second hold of the lock: a write landing between the two is overwritten
/// (last writer wins). It is the CLI's one write from a snapshot.
pub fn write<F>(path: &Path, mode: CommentLoss, edit: F) -> Result<(), String>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    let mut edited = None;
    let tried = edit_config(path, |config| {
        edit(config)?;
        edited = Some(config.clone());
        Ok(())
    });
    match tried {
        Ok(gone) if !gone.is_empty() => {
            // A removed entry takes its own comments with it; say so.
            eprintln!(
                "Note: comments inside the changed entry went with it ({}): {}",
                path.display(),
                gone.join("; ")
            );
            Ok(())
        }
        Ok(_) => Ok(()),
        // `--force` overrides only the comment check; a validation or I/O
        // failure is reported as itself, never as a comment warning.
        Err(refusal) if mode == CommentLoss::Refuse || !is_comment_refusal(&refusal) => {
            Err(refusal)
        }
        Err(refusal) => {
            let config = edited.ok_or_else(|| refusal.clone())?;
            #[allow(deprecated)] // `--force`: the documented snapshot rewrite.
            write_config(path, &config)
                .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
            eprintln!(
                "Warning: --force rewrites {} in full. Without it this write is refused:\n  {refusal}",
                path.display()
            );
            Ok(())
        }
    }
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
///
/// The text is read before the config lock is taken, so a write landing
/// between the read and the save is overwritten (MIK-8042).
pub(crate) fn rewrite_url_aliases_in(path: &Path, mode: RewriteMode) -> Result<UrlRewrite, String> {
    let text = super::regular_file::read_regular_text(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let mut rewrite = rewrite_url_aliases(&text, None);
    // The retired key goes in the same pass, so the file is written once.
    let (dropped, retired) = super::retired_config_keys::drop_cache_tools(&rewrite.text);
    rewrite.retired = retired;
    if let Some(text) = dropped {
        rewrite.text = text;
    }
    if mode == RewriteMode::Apply
        && (!rewrite.changed.is_empty() || matches!(retired, Retired::Removed { .. }))
    {
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

#[cfg(test)]
mod tests {
    /// A lock refusal under `--force` is reported as itself: `--force`
    /// overrides only the comment check, never another writer's lock (a
    /// directory where the lock file goes makes the lock fail at once).
    #[test]
    fn a_lock_refusal_under_force_is_not_overridden() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, "backends: {}\n")
            .expect("write");
        std::fs::create_dir(dir.path().join(".gateway.yaml.lock")).expect("dir in the way");
        let error =
            super::write(&path, super::CommentLoss::Rewrite, |_| Ok(())).expect_err("fails");
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
        let error =
            super::write(&path, super::CommentLoss::Rewrite, |_| Ok(())).expect_err("fails");
        assert!(
            error.starts_with("Failed to load") && !error.contains(super::REFUSAL),
            "{error}"
        );
    }

    /// MIK-8042: the CLI's only writes outside one hold of the config lock
    /// are `--force`'s snapshot rewrite, `init`'s create and `upgrade`'s
    /// text rewrite. A new one has to be added here, on purpose.
    #[test]
    fn the_cli_writes_outside_the_locked_edit_are_the_known_three() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = Vec::new();
        for dir in ["src/commands", "src/cli"] {
            for entry in std::fs::read_dir(root.join(dir)).expect("dir") {
                let path = entry.expect("entry").path();
                let name = path
                    .file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned();
                if name.ends_with("_tests.rs") || path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path)
                    .expect("read")
                    .replace("\r\n", "\n");
                // Production code only: a file's own test module comes last.
                let code = text.split("#[cfg(test)]\nmod ").next().unwrap_or_default();
                for call in ["write_config(", "write_config_text("] {
                    let calls = code
                        .match_indices(call)
                        .filter(|(at, _)| {
                            !code[..*at].ends_with(|c: char| c == '_' || c.is_alphanumeric())
                        })
                        .filter(|(at, _)| !code[..*at].ends_with("fn "))
                        .count();
                    found.extend(std::iter::repeat_n(format!("{name}:{call}"), calls));
                }
            }
        }
        found.sort();
        assert_eq!(
            found,
            [
                "config_write.rs:write_config(",
                "config_write.rs:write_config_text(",
                "mod.rs:write_config_text(",
            ]
        );
    }
}
