// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` rewrites each backend's `http_url` or `ws_url` as
//! `url` in the operator's config, keeping every comment, and says which
//! lines it changed. A second run changes nothing and says so.
//!
//! This whole-file write does not take a config file lock; it runs only when
//! the operator runs `upgrade`. It joins a lock only if that lock's write API
//! gains a way to replace an existing file.

use std::path::Path;
use std::process::ExitCode;

use super::super::backend_url_keys::UrlRewrite;
use super::super::config_write::{RewriteMode, rewrite_url_aliases_in};
use super::super::retired_config_keys::Retired;

/// `mcp-gateway upgrade`: rewrite the backend URL keys in the config at
/// `config` (or the one found in the working directory), then run the
/// version migrations.
pub fn run_upgrade_with_config(
    dry_run: bool,
    quiet: bool,
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> ExitCode {
    // A named file that is missing is a typo, not "no config": going on would
    // stamp the version and report success with nothing migrated.
    if let Some(named) = config.filter(|p| !p.exists()) {
        eprintln!(
            "Error: {} not found; nothing was upgraded.",
            named.display()
        );
        return ExitCode::FAILURE;
    }
    if let Some(path) = super::super::doctor::resolve_config_path(config).filter(|p| p.exists()) {
        let mode = if dry_run {
            RewriteMode::DryRun
        } else {
            RewriteMode::Apply
        };
        match rewrite_url_aliases_in(&path, mode) {
            Ok(rewrite) if !quiet => {
                for line in url_report(&path, &rewrite, mode) {
                    println!("{line}");
                }
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    super::run_upgrade_command(dry_run, quiet, data_dir)
}

/// What a rewrite did, one line per fact, naming line numbers and backend
/// names only: a URL can carry a credential, so none is printed.
pub(super) fn url_report(path: &Path, rewrite: &UrlRewrite, mode: RewriteMode) -> Vec<String> {
    let at = path.display();
    let mut out = Vec::new();
    match rewrite.retired {
        Retired::Removed(line) => {
            let verb = match mode {
                RewriteMode::Apply => "removed",
                RewriteMode::DryRun => "upgrade would remove",
            };
            out.push(format!(
                "{at}: {verb} `meta_mcp.cache_tools` (line {line}); nothing ever read it."
            ));
        }
        Retired::Left => out.push(format!(
            "{at}: kept `meta_mcp.cache_tools`: upgrade removes it only as its own line under a \
             `meta_mcp:` block that holds other keys. Nothing reads it; delete it by hand."
        )),
        Retired::Absent => {}
    }
    if rewrite.changed.is_empty() {
        if rewrite.skipped.is_empty()
            && rewrite.kept.is_empty()
            && rewrite.retired == Retired::Absent
        {
            out.push(format!(
                "{at}: no `http_url` or `ws_url` to rewrite; nothing changed."
            ));
        }
    } else {
        let lines: Vec<String> = rewrite
            .changed
            .iter()
            .map(|n| format!("line {n}"))
            .collect();
        let verb = match mode {
            RewriteMode::Apply => "rewrote",
            RewriteMode::DryRun => "upgrade would rewrite",
        };
        out.push(format!(
            "{at}: {verb} `http_url`/`ws_url` as `url` on {}.",
            lines.join(", ")
        ));
    }
    if !rewrite.skipped.is_empty() {
        out.push(format!(
            "{at}: not rewritten, change these to `url` by hand (written in flow style, \
             holding both `http_url` and `ws_url`, or beside text the rewrite could not edit \
             safely): backends {}.",
            rewrite.skipped.join(", ")
        ));
    }
    if !rewrite.kept.is_empty() {
        out.push(format!(
            "{at}: kept `http_url`/`ws_url` for backends {}: their value is not an \
             http(s):// address under `http_url` or a ws(s):// address under `ws_url`, \
             so `url` would change what they do.",
            rewrite.kept.join(", ")
        ));
    }
    out
}

#[cfg(test)]
#[path = "upgrade_url_keys_tests.rs"]
mod tests;
