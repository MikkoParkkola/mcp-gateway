// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-backend package-manager cache directories for stdio children (#2258).

use std::collections::HashMap;
use std::path::PathBuf;

/// The npm cache variable: the one cache the start-path repair may clear.
pub(super) const CACHE_ENV: &str = "npm_config_cache";

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
    let dir = cache_dir(backend_name).to_string_lossy().into_owned();
    for var in vars {
        // An operator-set value wins, in any spelling: npm reads its
        // environment case-insensitively, so a `NPM_CONFIG_CACHE` beside an
        // injected `npm_config_cache` would leave the child two caches.
        if !backend_env.keys().any(|key| key.eq_ignore_ascii_case(var)) {
            backend_env.insert((*var).to_string(), dir.clone());
        }
    }
    backend_env
}

/// The cache directory the gateway assigns to a backend, or `None` when it
/// assigns none.
///
/// `None` means the value in the child's environment, if there is one, came
/// from the operator: either this backend does not invoke npm, or its
/// configuration already names a cache. That distinction is the whole point of
/// returning the path rather than only writing it into the environment — the
/// repair deletes what it is handed, and a directory the gateway did not create
/// is not the gateway's to delete, however much a caller's `npm_config_cache`
/// looks like one [#1759].
///
/// Only npm's cache is answered for: the repair was reviewed against npm's
/// install failures, and the other runners' trees are left to their own tools.
#[must_use]
pub(crate) fn assigned_package_cache_dir<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    backend_env: &HashMap<String, String, S>,
) -> Option<PathBuf> {
    // npm reads its environment case-insensitively, so `NPM_CONFIG_CACHE` in a
    // backend's `env:` is the operator naming a cache too.
    if !cache_vars_for(command).contains(&CACHE_ENV)
        || backend_env
            .keys()
            .any(|key| key.eq_ignore_ascii_case(CACHE_ENV))
    {
        return None;
    }
    // A relative data directory resolves against the gateway's working
    // directory here and against the child's `cwd` there, so the path the
    // repair would remove need not be the cache the child used.
    absolute(cache_dir(backend_name))
}

/// The directory, when it names one place whatever the working directory.
pub(super) fn absolute(dir: PathBuf) -> Option<PathBuf> {
    dir.is_absolute().then_some(dir)
}

/// One backend's cache directory: the single source of the path, so the one
/// written into the environment and the one the repair compares against agree.
fn cache_dir(backend_name: &str) -> PathBuf {
    crate::config_persistence::gateway_data_dir()
        .join("pkg-cache")
        .join(cache_component(backend_name))
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
