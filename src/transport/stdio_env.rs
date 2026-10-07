// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The environment a stdio child starts with (split from `stdio.rs`).

use std::collections::HashMap;
use std::ffi::OsString;

use tokio::process::Command;

#[cfg(unix)]
const FALLBACK_EXEC_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg(windows)]
const FALLBACK_EXEC_PATH: &str = r"C:\Windows\System32;C:\Windows";
#[cfg(not(any(unix, windows)))]
const FALLBACK_EXEC_PATH: &str = "";

pub(crate) fn configure_child_environment(
    cmd: &mut Command,
    backend_env: &HashMap<String, String>,
) {
    cmd.env_clear();

    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from(FALLBACK_EXEC_PATH));
    cmd.env("PATH", path);

    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| crate::home_dir::home_dir().map(std::path::PathBuf::into_os_string))
    {
        cmd.env("HOME", home);
    }

    let tmpdir =
        std::env::var_os("TMPDIR").unwrap_or_else(|| std::env::temp_dir().into_os_string());
    cmd.env("TMPDIR", tmpdir);

    #[cfg(windows)]
    for key in [
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }

    // Operator-level npm settings that are behaviour rather than credentials,
    // and that apply to every backend rather than to one. An allowlist, not a
    // deny list: npm's credential surface is open-ended — `_password`,
    // `certfile`, `keyfile`, `userconfig`, and registry URLs with embedded
    // userinfo all name secrets — and anything a deny rule misses reaches every
    // backend. A backend that needs a credential names it in its own `env:`.
    // A backend that names one of these settings keeps its own value: see
    // `forwarded_npm_config`.
    for (name, value) in forwarded_npm_config(std::env::vars_os(), backend_env) {
        cmd.env(name, value);
    }

    // Backend configuration is authoritative and may intentionally override
    // a safe default such as PATH, HOME, or TMPDIR.
    for (key, value) in backend_env {
        cmd.env(key, value);
    }
}

/// npm settings forwarded to every backend.
///
/// Matched case-insensitively, because npm reads its environment that way and
/// `NPM_CONFIG_ALLOW_GIT` is the spelling npm's own documentation uses. The
/// operator's spelling is what the child receives.
const FORWARDED_NPM_SETTINGS: [&str; 6] = [
    "npm_config_allow_git",
    "npm_config_cafile",
    "npm_config_prefer_offline",
    "npm_config_offline",
    "npm_config_strict_ssl",
    "npm_config_loglevel",
];

/// The operator's npm settings that this gateway passes on.
///
/// `npm_config_cache` is not among them, and cannot be added by accident: the
/// gateway assigns that per backend, and a shared cache is what tears under
/// concurrent installs.
///
/// A setting `backend_env` already names is skipped, in whatever spelling
/// either side used. Forwarding it as well would leave the child holding the
/// same setting twice, and npm keeps the last value it reads: on Unix the child
/// environment is passed in sorted order, so the operator's lowercase
/// `npm_config_strict_ssl` arrives after a backend's `NPM_CONFIG_STRICT_SSL` and
/// silently overrules the backend's explicit choice.
pub(super) fn forwarded_npm_config<I>(
    vars: I,
    backend_env: &HashMap<String, String>,
) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter(|(key, _)| {
            key.to_str().is_some_and(|name| {
                let name = name.to_ascii_lowercase();
                FORWARDED_NPM_SETTINGS.contains(&name.as_str())
                    && !backend_env
                        .keys()
                        .any(|configured| configured.eq_ignore_ascii_case(name.as_str()))
            })
        })
        .collect()
}
