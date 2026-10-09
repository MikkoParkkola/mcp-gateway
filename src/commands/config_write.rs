// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::path::Path;

use mcp_gateway::config::Config;
pub use mcp_gateway::config_persistence::CommentLoss;
use mcp_gateway::config_persistence::{edit_config, edit_config_text};

use super::backend_url_keys::{UrlRewrite, rewrite_url_aliases};
use super::retired_config_keys::Retired;

/// `--force` rewrites a file whose comments cannot be kept; without it that
/// write is refused and nothing is written.
pub fn comment_loss(force: bool) -> CommentLoss {
    if force {
        CommentLoss::Rewrite
    } else {
        CommentLoss::Refuse
    }
}

/// Load `path`, apply `edit`, and write the result; the error is a message
/// ready to print. The load, `edit` and the write share one hold of the
/// config lock, so another writer's change is never overwritten.
///
/// A write that keeps the file's comments but removes an entry names the
/// comment lines that went with that entry. A write that cannot keep them
/// is refused, naming the lines, or under `--force` rewrites the file in
/// full and names the lines it dropped.
pub fn write<F>(path: &Path, mode: CommentLoss, edit: F) -> Result<(), String>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    let dropped = edit_config(path, mode, edit)?;
    if !dropped.is_empty() {
        // A removed entry, or a `--force` full rewrite, takes comments with
        // it; say which lines, never their text.
        eprintln!(
            "Note: comments dropped by this write ({}): {}",
            path.display(),
            dropped.join("; ")
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
///
/// The saved text is read under the config lock, so a write landing before
/// the save is kept (MIK-8042).
pub(crate) fn rewrite_url_aliases_in(path: &Path, mode: RewriteMode) -> Result<UrlRewrite, String> {
    // Refuses a FIFO or a device at once, before waiting for the lock.
    let text = super::regular_file::read_regular_text(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if mode == RewriteMode::DryRun {
        return Ok(rewrite_of(&text));
    }
    let mut done = None;
    edit_config_text(path, |current| {
        let text =
            current.ok_or_else(|| format!("Failed to read {}: it was removed", path.display()))?;
        let rewrite = rewrite_of(text);
        let save =
            !rewrite.changed.is_empty() || matches!(rewrite.retired, Retired::Removed { .. });
        let saved = save.then(|| rewrite.text.clone());
        done = Some(rewrite);
        Ok(saved)
    })?;
    Ok(done.expect("edit_config_text ran the edit"))
}

/// The URL alias rewrite of `text`, with the retired key dropped in the same
/// pass, so the file is written once.
fn rewrite_of(text: &str) -> UrlRewrite {
    let mut rewrite = rewrite_url_aliases(text, None);
    let (dropped, retired) = super::retired_config_keys::drop_cache_tools(&rewrite.text);
    rewrite.retired = retired;
    if let Some(text) = dropped {
        rewrite.text = text;
    }
    rewrite
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
        assert!(error.starts_with("Failed to load"), "{error}");
    }

    /// MIK-8042: the CLI writes gateway.yaml only through the locked editors
    /// (`edit_config`, `edit_config_text`), never from a snapshot.
    #[test]
    fn the_cli_writes_only_through_the_locked_editors() {
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
        assert!(found.is_empty(), "{found:?}");
    }

    /// MIK-8042: `upgrade`'s text rewrite overlapping a gateway's locked
    /// mutation reads the file under the lock, so both changes survive.
    #[tokio::test]
    async fn upgrade_racing_a_gateway_mutation_keeps_both_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &path,
            "backends:\n  a:\n    http_url: \"https://a.example.test/mcp\"\n",
        )
        .expect("write");
        let at = path.clone();
        let mutated = mcp_gateway::config_reload::mutate_config_and_reload(&path, None, |config| {
            let queued = mcp_gateway::gateway::test_helpers::when_waiting_for_config_lock(&at);
            let upgrade = at.clone();
            let cli = std::thread::spawn(move || {
                super::rewrite_url_aliases_in(&upgrade, super::RewriteMode::Apply).map(drop)
            });
            assert!(
                queued
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .is_ok(),
                "upgrade never waited for the config lock"
            );
            let x = serde_yaml::from_str("command: x\n").expect("backend");
            config.backends.insert("x".into(), x);
            Ok::<_, String>(cli)
        })
        .await;
        let Ok(mcp_gateway::config_reload::ConfigMutation::Applied(cli, _)) = mutated else {
            panic!("mutation not applied");
        };
        cli.join().expect("upgrade thread").expect("upgrade wrote");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            !text.contains("http_url"),
            "upgrade's rewrite was lost: {text}"
        );
        let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
        assert!(
            config.backends.contains_key("x"),
            "the mutation was lost: {text}"
        );
    }
}
