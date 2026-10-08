// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::path::Path;

use mcp_gateway::config::Config;
pub use mcp_gateway::config_persistence::CommentLoss;
use mcp_gateway::config_persistence::write_config_preserving;

/// `--force` rewrites a file whose comments cannot be kept; without it that
/// write is refused and nothing is written.
pub fn comment_loss(force: bool) -> CommentLoss {
    if force {
        CommentLoss::Rewrite
    } else {
        CommentLoss::Refuse
    }
}

/// Edit the config at `path` with `edit` and write it, as one transaction
/// under the config lock; the error is a message ready to print. The note the
/// library returns (the lines a `--force` rewrite dropped, or the comment
/// lines that went with a removed entry) goes to stderr.
pub fn write<T>(
    path: &Path,
    mode: CommentLoss,
    edit: impl FnOnce(&mut Config) -> Result<T, String>,
) -> Result<T, String> {
    let (value, note) = write_config_preserving(path, mode, edit)?;
    if let Some(note) = note {
        eprintln!("{note}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    /// A failure under `--force` comes back as that failure, not as a
    /// comment warning over a rewrite (a directory where the file goes fails
    /// on every platform).
    #[test]
    fn an_io_failure_under_force_is_reported_as_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        std::fs::create_dir(&path).expect("dir in the way");
        let error =
            super::write(&path, super::CommentLoss::Rewrite, |_| Ok(())).expect_err("fails");
        assert!(
            error.starts_with("Failed to") && !error.contains("Not saved:"),
            "{error}"
        );
    }
}
