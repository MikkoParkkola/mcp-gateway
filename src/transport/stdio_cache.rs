// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-backend package-manager cache directories for stdio children (#2258).

use std::collections::HashMap;
use std::path::PathBuf;

use tracing::warn;

/// The npm cache variable: the one cache the start-path repair may clear.
pub(super) const CACHE_ENV: &str = "npm_config_cache";

/// Yarn Berry's switch that, on by default, makes it ignore `cacheFolder`.
const BERRY_GLOBAL_CACHE: &str = "YARN_ENABLE_GLOBAL_CACHE";

/// The variable both yarn generations read for the cache folder.
const YARN_CACHE: &str = "YARN_CACHE_FOLDER";

/// A per-backend package cache, so backends sharing a command cannot tear one
/// tree. Each runner reads its own variable; `npm_config_cache` alone does
/// nothing for bunx or yarn (#2258).
///
/// A variable the operator already set, in any spelling that runner reads,
/// is left alone. A cache path no runner could use as written is assigned to
/// none of them (MIK-8147): the runner keeps its default cache.
#[must_use]
pub fn isolated_package_manager_env<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    mut backend_env: HashMap<String, String, S>,
) -> HashMap<String, String, S> {
    // Decided on the operator's own environment, before anything is added.
    // Berry ignores a cache folder while its global cache is on, whoever set
    // the folder; an operator who set the switch keeps it.
    let yarn = cache_vars_for(command).contains(&YARN_CACHE);
    let operator_folder = yarn && operator_names(&backend_env, YARN_CACHE);
    let berry_switch_free = yarn && !operator_names(&backend_env, BERRY_GLOBAL_CACHE);
    let assigned_folder = match assignment(backend_name, command, &backend_env) {
        Assignment::None => false,
        Assignment::Unusable => {
            warn!(
                backend = backend_name,
                "package cache path is not one a package manager can use as written \
                 (not UTF-8, relative, holding `..`, or holding `${{`); the backend keeps its runner's default cache"
            );
            false
        }
        Assignment::To { vars, dir } => {
            let folder = vars.contains(&YARN_CACHE);
            for var in vars {
                backend_env.insert(var.to_owned(), dir.clone());
            }
            folder
        }
    };
    if berry_switch_free && (operator_folder || assigned_folder) {
        backend_env.insert(BERRY_GLOBAL_CACHE.to_owned(), "false".to_owned());
    }
    backend_env
}

/// What the gateway assigns one backend: the one decision the environment
/// writer and the repair both read, so they cannot disagree.
enum Assignment {
    /// The runner reads no cache variable, or the operator set every one.
    None,
    /// Variables are left to the gateway, but no runner could use its path.
    Unusable,
    /// These variables, each set to this directory.
    To {
        vars: Vec<&'static str>,
        dir: String,
    },
}

fn assignment<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    backend_env: &HashMap<String, String, S>,
) -> Assignment {
    let vars: Vec<&'static str> = cache_vars_for(command)
        .iter()
        .copied()
        .filter(|var| !operator_names(backend_env, var))
        .collect();
    if vars.is_empty() {
        return Assignment::None;
    }
    match usable_cache_dir(backend_name) {
        Some(dir) => Assignment::To { vars, dir },
        None => Assignment::Unusable,
    }
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
/// looks like one [#1759]. `None` too when the path is one npm could not use
/// as written: nothing was handed to the child, so nothing is the gateway's.
///
/// Only npm's cache is answered for: the repair was reviewed against npm's
/// install failures, and the other runners' trees are left to their own tools.
#[must_use]
pub(crate) fn assigned_package_cache_dir<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    backend_env: &HashMap<String, String, S>,
) -> Option<PathBuf> {
    match assignment(backend_name, command, backend_env) {
        Assignment::To { vars, dir } if vars.contains(&CACHE_ENV) => Some(PathBuf::from(dir)),
        _ => None,
    }
}

/// The backend's cache directory as a runner will read it, or `None` when no
/// runner could use it as written. npm (through Node) and pnpm (through
/// Rust's `env::var`) read their environment as UTF-8, so a path that is not
/// UTF-8 names another directory to them, or none. npm expands `${VAR}` in a
/// config value. A `..` is read as text by npm and through symlinks by the
/// filesystem. And a relative path resolves against the child's `cwd`, not
/// the gateway's (`gateway_data_dir` is absolute since MIK-7964 unless the
/// working directory is unreadable).
fn usable_cache_dir(backend_name: &str) -> Option<String> {
    usable(cache_dir(backend_name))
}

/// `dir` as a runner will read it, or `None` when no runner could use it as
/// written (see `usable_cache_dir`).
pub(super) fn usable(dir: PathBuf) -> Option<String> {
    // A `..` is resolved as text by npm but through any symlink before it by
    // the filesystem the repair deletes on: two different trees.
    if !dir.is_absolute()
        || dir
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return None;
    }
    dir.into_os_string()
        .into_string()
        .ok()
        .filter(|dir| !dir.contains("${"))
}

/// Whether the operator's environment already sets `var`, in a spelling the
/// runner that reads `var` reads (MIK-8147). Per variable, never per prefix:
/// a key one runner ignores must not cancel another runner's cache.
fn operator_names<S: std::hash::BuildHasher>(
    backend_env: &HashMap<String, String, S>,
    var: &str,
) -> bool {
    backend_env.keys().any(|key| names_setting(key, var))
}

/// Whether environment key `key` sets what `var` sets, for `var`'s runner.
fn names_setting(key: &str, var: &str) -> bool {
    // Windows keeps one entry per case-insensitive name: a case variant IS the
    // same variable there, and an injected one would replace it.
    if cfg!(windows) && key.eq_ignore_ascii_case(var) {
        return true;
    }
    if var.starts_with("npm_config_") {
        npm_setting(key).is_some_and(|setting| npm_setting(var) == Some(setting))
    } else if var.starts_with("pnpm_config_") {
        // pnpm reads `PNPM_CONFIG_<SUFFIX>` and `pnpm_config_<suffix>` only
        // (pnpm `config/src/env_overlay/string_reader.rs` `read_env`).
        key == var || key == var.to_ascii_uppercase()
    } else if var.starts_with("YARN_") {
        yarn_setting(key).is_some_and(|setting| yarn_setting(var) == Some(setting))
    } else {
        // Bun reads its variable verbatim.
        key == var
    }
}

/// The setting npm reads from an environment key, folded as npm folds it: the
/// `npm_config_` prefix in any case, then every non-leading `_` read as `-`,
/// lowercased (`@npmcli/config` `loadEnv`). `npm_config_strict_ssl` and
/// `NPM_CONFIG_STRICT-SSL` are one setting; a key outside the prefix is none.
/// Lowercasing is ASCII only, where npm's is Unicode: enough here, whose
/// settings are ASCII, since a key that folds differently cannot name one.
/// The rule MIK-8097 found for forwarded settings.
fn npm_setting(key: &str) -> Option<String> {
    const PREFIX: &str = "npm_config_";
    let rest = key
        .get(..PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(PREFIX))
        .map(|_| &key[PREFIX.len()..])?;
    if rest.starts_with("//") {
        return Some(rest.to_owned());
    }
    Some(
        rest.char_indices()
            .map(|(at, c)| {
                if at > 0 && c == '_' {
                    '-'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
    )
}

/// The setting yarn reads from an environment key: the `yarn_` prefix in any
/// case, then the words between separators (`_`, `-`, `.`, space; Berry's
/// camel-casing splits on all four), lowercased. Yarn 1
/// reads `yarn_cache-folder` as `cache-folder`; Berry camel-cases the
/// lowercased remainder, so `YARN_CACHE__FOLDER` is `cacheFolder`. A key
/// either generation reads as a setting names it.
fn yarn_setting(key: &str) -> Option<String> {
    const PREFIX: &str = "yarn_";
    let rest = key
        .get(..PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(PREFIX))
        .map(|_| &key[PREFIX.len()..])?;
    let words: Vec<String> = rest
        .split(['_', '-', '.', ' '])
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    Some(words.join("-"))
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
