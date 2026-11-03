// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` removes the identity-grant rows that name no one
//! from the grants file the config names. Such a row grants nothing and is
//! refused at load; this step runs on every `upgrade`, whatever the version
//! stamp says, so the load refusal's advice always works. A second run finds
//! nothing and says nothing.

use std::path::{Path, PathBuf};

use mcp_gateway::cli_support::{GrantCleanup, remove_nameless_grant_rows};

/// The grants file `config` names, or the default one; `~` expanded.
fn grants_path(config: Option<&Path>) -> PathBuf {
    let named = config
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| crate::yaml::from_str::<crate::yaml::Value>(&text).ok())
        .and_then(|yaml| {
            yaml.get("security")?
                .get("identity_grants")?
                .get("path")?
                .as_str()
                .map(str::to_owned)
        });
    let path = named.unwrap_or_else(|| mcp_gateway::config::IdentityGrantsConfig::default().path);
    super::super::identity::expand_home_path(Path::new(&path))
}

/// Run the cleanup and print one line per row, naming the rule id and the
/// field only. `false` when it refused or failed, with the reason printed.
pub(super) fn clean_grant_rows(config: Option<&Path>, mode: GrantCleanup) -> bool {
    let path = grants_path(config);
    match remove_nameless_grant_rows(&path, mode) {
        Ok(rows) => {
            let verb = match mode {
                GrantCleanup::Apply => "removed",
                GrantCleanup::DryRun => "upgrade would remove",
            };
            for (grant_id, field) in rows {
                eprintln!(
                    "{}: {verb} grant '{grant_id}': its {field} names no one, so it grants nothing",
                    path.display()
                );
            }
            true
        }
        Err(error) => {
            eprintln!("Error: {error}");
            false
        }
    }
}

#[cfg(test)]
#[path = "upgrade_grant_rows_tests.rs"]
mod tests;
