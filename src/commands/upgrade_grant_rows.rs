// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` checks the identity-grants file the gateway would
//! load and names every rule in it that names no one. It edits nothing: a
//! rewrite of a security file that could widen access needs proof a hand
//! deletion does not. The report is the loader's own refusal, so `upgrade`
//! and startup name the same rows.

use std::path::Path;

/// The grants file the gateway would load from `config` (found as startup
/// finds it when `None`), with environment overrides applied and `~`
/// expanded; `Ok(None)` when grants are off.
fn grants_path(config: Option<&Path>) -> Result<Option<std::path::PathBuf>, String> {
    let loaded = mcp_gateway::config::Config::load(config).map_err(|e| {
        format!("the config does not load, so its identity grants were not checked: {e}")
    })?;
    let grants = &loaded.security.identity_grants;
    Ok(grants
        .enabled
        .then(|| super::super::identity::expand_home_path(Path::new(&grants.path))))
}

/// Read the grants file through the loader, on its own thread so this runs
/// inside or outside an async runtime. `false`, with the loader's refusal
/// printed, when the file would not load.
pub(super) fn check_grant_rows(config: Option<&Path>) -> bool {
    let path = match grants_path(config) {
        Ok(Some(path)) => path,
        Ok(None) => return true,
        Err(refusal) => {
            eprintln!("Error: {refusal}");
            return false;
        }
    };
    // A missing file is the loader's to judge, as at startup.
    let read = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(mcp_gateway::identity_grants::read_identity_grants_file(
                &path,
            ))
            .map(drop)
    })
    .join()
    .unwrap_or_else(|_| Err("the identity grants check panicked".to_string()));
    match read {
        Ok(()) => true,
        Err(refusal) => {
            eprintln!("Error: {refusal}");
            false
        }
    }
}

#[cfg(test)]
#[path = "upgrade_grant_rows_tests.rs"]
mod tests;
