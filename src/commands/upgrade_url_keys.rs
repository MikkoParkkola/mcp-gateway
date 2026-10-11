// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` rewrites each backend's `http_url` or `ws_url` as
//! `url` in the operator's config, keeping every comment, and says which
//! lines it changed. A second run changes nothing and says so.
//!
//! The rewrite reads and writes the file under one hold of the config lock
//! (`edit_config_text`), so a change another writer saved first is kept.

use std::path::Path;
use std::process::ExitCode;

use super::super::api_key_rewrite::{KeyLeft, KeyRewrite};
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
    let mut blocking = 0;
    if let Some(path) = super::super::doctor::resolve_config_path(config).filter(|p| p.exists()) {
        let mode = if dry_run {
            RewriteMode::DryRun
        } else {
            RewriteMode::Apply
        };
        match rewrite_url_aliases_in(&path, mode) {
            Ok(rewrite) => {
                if !quiet {
                    for line in url_report(&path, &rewrite, mode) {
                        println!("{line}");
                    }
                }
                blocking = rewrite.blocking();
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    // The stamp and data migrations run either way, so a rerun after the hand
    // fix has nothing left to do; the exit status still says the config will
    // not load (MIK-8044).
    let code = super::run_upgrade_command(dry_run, quiet, data_dir);
    if blocking == 0 {
        return code;
    }
    if quiet {
        eprintln!(
            "Error: {blocking} key(s) could not be removed and the config will not load until \
             they are; run `mcp-gateway upgrade` without --quiet to see them."
        );
    }
    ExitCode::FAILURE
}

/// What a rewrite did, one line per fact, naming line numbers and backend
/// names only: a URL can carry a credential, so none is printed.
pub(super) fn url_report(path: &Path, rewrite: &UrlRewrite, mode: RewriteMode) -> Vec<String> {
    let at = path.display();
    let mut out = Vec::new();
    for removal in &rewrite.removed {
        let key = &removal.key;
        match removal.outcome {
            Retired::Removed { line, block } => {
                let verb = match mode {
                    RewriteMode::Apply => "removed",
                    RewriteMode::DryRun => "upgrade would remove",
                };
                // The section is the key's parent: `meta_mcp` for `meta_mcp.cache_tools`.
                let section = key.rsplit_once('.').map_or("", |(parent, _)| {
                    parent.rsplit_once('.').map_or(parent, |(_, name)| name)
                });
                let block = block
                    .map(|h| format!(" and the `{section}:` (line {h}) it was alone under"))
                    .unwrap_or_default();
                out.push(format!(
                    "{at}: {verb} `{key}` (line {line}){block}; it never had an effect."
                ));
            }
            Retired::Left if removal.blocks_load() => out.push(format!(
                "{at}: kept `{key}`: upgrade removes it only from block-style YAML it can edit \
                 without touching anything else. It never had an effect; the config will not \
                 load until it is deleted by hand."
            )),
            Retired::Left => out.push(format!(
                "{at}: kept `{key}`: upgrade removes it only as its own line under a \
                 block-style section. Nothing reads it; delete it by hand."
            )),
            Retired::Absent => {}
        }
    }
    out.extend(
        rewrite
            .api_keys
            .iter()
            .map(|key| api_key_line(&at, key, mode)),
    );
    if rewrite.changed.is_empty() {
        if rewrite.skipped.is_empty()
            && rewrite.kept.is_empty()
            && rewrite.removed.is_empty()
            && rewrite.api_keys.is_empty()
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

/// The report line for one plaintext API key. It names the entry and line,
/// never the key or its digest.
fn api_key_line(at: &std::path::Display<'_>, key: &KeyRewrite, mode: RewriteMode) -> String {
    match key {
        KeyRewrite::Hashed { name, line } => format!(
            "{at}: {} the plaintext key of auth.api_keys `{name}` (line {line}) as its \
                 key_sha256 digest; the same key still authenticates.",
            match mode {
                RewriteMode::Apply => "replaced",
                RewriteMode::DryRun => "upgrade would replace",
            }
        ),
        KeyRewrite::Dropped { name, line } => format!(
            "{at}: {} the plaintext key of auth.api_keys `{name}` (line {line}); its \
                 key_sha256 already matches.",
            match mode {
                RewriteMode::Apply => "removed",
                RewriteMode::DryRun => "upgrade would remove",
            }
        ),
        KeyRewrite::Left { name, why } => format!(
            "{at}: kept the plaintext key of auth.api_keys `{name}`: {}. Run \
                 `mcp-gateway hash-key`, set key_sha256 and delete key; the config will not \
                 load until then.",
            match why {
                KeyLeft::Reference => "it names a secret held elsewhere, which upgrade never reads",
                KeyLeft::Conflict => "key_sha256 is set too and is not this key's digest",
                KeyLeft::Unprovable => "upgrade could not change that line alone",
            }
        ),
    }
}

#[cfg(test)]
#[path = "upgrade_url_keys_tests.rs"]
mod tests;
