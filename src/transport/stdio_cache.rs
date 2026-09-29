// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-backend package-manager cache directories for stdio children (#2258).

use std::collections::HashMap;

/// A per-backend package cache, so backends sharing a command cannot tear one
/// tree. Each runner reads its own variable; `npm_config_cache` alone does
/// nothing for bunx or yarn (#2258).
#[must_use]
pub fn isolated_package_manager_env<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    mut backend_env: HashMap<String, String, S>,
) -> HashMap<String, String, S> {
    let vars = cache_vars_for(command);
    if vars.is_empty() {
        return backend_env;
    }
    let dir = crate::config_persistence::gateway_data_dir()
        .join("pkg-cache")
        .join(cache_component(backend_name))
        .to_string_lossy()
        .into_owned();
    for var in vars {
        // An operator-set value wins.
        backend_env
            .entry((*var).to_string())
            .or_insert_with(|| dir.clone());
    }
    backend_env
}

/// The variables a runner reads for its cache directory. pnpm keeps installs
/// in its content store, which `store_dir` relocates; its separate metadata
/// cache stays shared. Current pnpm (12.x) reads only `pnpm_config_*` and
/// prints `undefined` for `npm_config_store_dir`; older pnpm reads
/// `npm_config_*`. Both are set so either generation is isolated.
fn cache_vars_for(command: &str) -> &'static [&'static str] {
    let Some(program) = command.split_whitespace().next() else {
        return &[];
    };
    match program.rsplit('/').next().unwrap_or(program) {
        "npx" | "npm" => &["npm_config_cache"],
        "bunx" => &["BUN_INSTALL_CACHE_DIR"],
        "yarn" => &["YARN_CACHE_FOLDER"],
        "pnpm" => &["pnpm_config_store_dir", "npm_config_store_dir"],
        _ => &[],
    }
}

/// A readable prefix plus a hash of the whole name. The prefix alone maps
/// `team.alpha` and `team_alpha` (and, on a case-insensitive filesystem,
/// `Alpha` and `alpha`) to one directory; the hash keeps them apart.
fn cache_component(name: &str) -> String {
    let readable: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let hash = crate::hashing::sha256_hex(name.as_bytes());
    format!("{readable}-{}", &hash[..16])
}
