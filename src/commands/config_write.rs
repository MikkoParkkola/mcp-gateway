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
pub fn write(path: &Path, config: &Config, mode: CommentLoss) -> Result<(), String> {
    write_config_with(path, config, mode).map_err(|e| match e {
        Unwritten::CommentLoss(message) => message,
        Unwritten::Failed(message) => format!("Failed to write {}: {message}", path.display()),
    })
}
