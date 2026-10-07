// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a CLI command writes gateway.yaml: through the comment-keeping splice,
//! refusing a write that would drop comments unless `--force` is given
//! (MIK-8017).

use std::collections::HashMap;
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

/// The lines of `before` holding a `#` that `after` no longer has, as
/// `line N`. Line numbers only: a `#` inside a quoted value can be a secret.
fn dropped_comments(before: &str, after: &str) -> Vec<String> {
    let mut kept: HashMap<&str, usize> = HashMap::new();
    for line in after.lines().filter(|l| l.contains('#')) {
        *kept.entry(line.trim()).or_default() += 1;
    }
    before
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains('#'))
        .filter_map(|(n, l)| match kept.get_mut(l.trim()) {
            Some(left) if *left > 0 => {
                *left -= 1;
                None
            }
            _ => Some(format!("line {}", n + 1)),
        })
        .collect()
}
