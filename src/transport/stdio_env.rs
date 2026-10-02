// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The environment a stdio child starts with: cleared, then the few variables
//! a process needs to run, then the backend's own configuration on top.
//! Split out of `stdio.rs` to keep it under the file-size ceiling.

use std::collections::HashMap;
use std::ffi::OsString;

use tokio::process::Command;

#[cfg(unix)]
const FALLBACK_EXEC_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg(windows)]
const FALLBACK_EXEC_PATH: &str = r"C:\Windows\System32;C:\Windows";
#[cfg(not(any(unix, windows)))]
const FALLBACK_EXEC_PATH: &str = "";

pub(super) fn configure_child_environment(
    cmd: &mut Command,
    backend_env: &HashMap<String, String>,
) {
    cmd.env_clear();

    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from(FALLBACK_EXEC_PATH));
    cmd.env("PATH", path);

    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| dirs::home_dir().map(std::path::PathBuf::into_os_string))
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

    for (name, value) in forwarded_npm_config(std::env::vars_os(), backend_env) {
        cmd.env(name, value);
    }

    // Backend configuration is authoritative and may intentionally override
    // a safe default such as PATH, HOME, or TMPDIR.
    for (key, value) in backend_env {
        cmd.env(key, value);
    }
}

/// npm settings forwarded to every backend: behaviour, not credentials.
///
/// An allowlist, not a deny list. npm's credential surface is open-ended
/// (`_auth`, `_password`, `certfile`, `keyfile`, `userconfig`, registry and
/// proxy URLs with userinfo), and anything a deny rule misses would reach every
/// backend. A backend that needs a credential names it in its own `env:`.
/// `npm_config_cache` is absent on purpose: the gateway assigns it per backend.
const FORWARDED_NPM_SETTINGS: [&str; 6] = [
    "npm_config_allow_git",
    "npm_config_cafile",
    "npm_config_loglevel",
    "npm_config_offline",
    "npm_config_prefer_offline",
    "npm_config_strict_ssl",
];

/// The operator's npm settings that the gateway passes on to a backend.
///
/// Keys match case-insensitively, as npm reads them, and keep the operator's
/// spelling. A setting the backend's own `env:` names, in any spelling, is
/// left out: the child would otherwise get both keys, and npm keeps whichever
/// it reads last, which need not be the backend's.
fn forwarded_npm_config<I>(
    vars: I,
    backend_env: &HashMap<String, String>,
) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter(|(key, _)| {
            key.to_str().is_some_and(|name| {
                FORWARDED_NPM_SETTINGS
                    .iter()
                    .any(|setting| setting.eq_ignore_ascii_case(name))
                    && !backend_env.keys().any(|own| own.eq_ignore_ascii_case(name))
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "stdio_env_tests.rs"]
mod tests;
