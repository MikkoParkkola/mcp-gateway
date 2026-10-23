// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The home and config directories the gateway resolves for a user.
//!
//! Debug builds let a test point both at a fixture (#2368): on Windows
//! `dirs::home_dir()` reads the Known Folder API and ignores `HOME` and
//! `USERPROFILE`, so a child process cannot otherwise be given an isolated
//! home. Release builds compile the override out, and the release job greps
//! the binary for its name.
//!
//! Everything else resolves home through here: `clippy.toml` disallows a direct
//! `dirs::home_dir` or `dirs::config_dir` anywhere else in the crate (MIK-8001).

use std::path::PathBuf;

/// The user's home directory.
#[cfg(debug_assertions)]
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the platform lookups are called"
)]
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
}

/// The user's home directory.
#[cfg(not(debug_assertions))]
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the platform lookups are called"
)]
pub(crate) fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// No home directory could be determined for a `~` path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoHome;

/// The part after a leading `~` or `~/`, with any further leading `/` or `\` trimmed, so `~//x` is `x`.
/// None for anything else: `~user/x`, `x/~`, "" and a remainder that is absolute or has a Windows prefix
/// (`~/C:/x`) after trimming. `~` alone gives "".
pub(crate) fn tilde_rest(path: &str) -> Option<&str> {
    if path == "~" {
        return Some("");
    }
    let rest = path.strip_prefix("~/")?;
    let rest = rest.trim_start_matches(['/', '\\']);
    let probe = std::path::Path::new(rest);
    if probe.has_root() {
        return None;
    }
    if matches!(
        probe.components().next(),
        Some(std::path::Component::Prefix(_))
    ) {
        return None;
    }
    Some(rest)
}

/// `path` with a leading `~`/`~/` replaced by `home`; `Err(NoHome)` for a tilde path when `home` is None.
pub(crate) fn expand_with(path: &str, home: Option<PathBuf>) -> Result<PathBuf, NoHome> {
    let Some(rest) = tilde_rest(path) else {
        return Ok(PathBuf::from(path));
    };
    if let Some(home) = home {
        return Ok(home.join(rest));
    }
    Err(NoHome)
}

/// `expand_with`, falling back to the current directory (`./rest`) when there is no home: the server's
/// and CLI's rule, and the transparency log's.
pub(crate) fn expand_or_cwd_with(path: &str, home: Option<PathBuf>) -> PathBuf {
    expand_with(path, home)
        .unwrap_or_else(|NoHome| PathBuf::from(".").join(tilde_rest(path).unwrap_or("")))
}

/// `expand_or_cwd_with` with the process's home.
pub(crate) fn expand_or_cwd(path: &str) -> PathBuf {
    expand_or_cwd_with(path, home_dir())
}

/// The OS config directory. Under the test override it follows
/// `XDG_CONFIG_HOME` (which Windows `dirs` ignores), else `<home>/.config`.
#[cfg(all(debug_assertions, not(target_os = "macos")))]
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the platform lookups are called"
)]
pub(crate) fn config_dir() -> Option<PathBuf> {
    match std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR") {
        Some(home) => Some(
            std::env::var_os("XDG_CONFIG_HOME")
                .map_or_else(|| PathBuf::from(home).join(".config"), PathBuf::from),
        ),
        None => dirs::config_dir(),
    }
}

/// The OS config directory.
#[cfg(all(not(debug_assertions), not(target_os = "macos")))]
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the platform lookups are called"
)]
pub(crate) fn config_dir() -> Option<PathBuf> {
    dirs::config_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_rest_names_home_paths() {
        assert_eq!(tilde_rest("~"), Some(""));
        assert_eq!(tilde_rest("~/x"), Some("x"));
        assert_eq!(tilde_rest("~//x"), Some("x"));
        assert_eq!(tilde_rest("~/\\x"), Some("x"));
        assert_eq!(tilde_rest("~user/x"), None);
        assert_eq!(tilde_rest("x/~"), None);
        assert_eq!(tilde_rest(""), None);
    }

    #[test]
    #[cfg(windows)]
    fn tilde_rest_rejects_a_windows_absolute_remainder() {
        assert_eq!(tilde_rest("~/C:/x"), None);
    }

    #[test]
    fn expand_with_resolves_against_the_given_home() {
        let home = PathBuf::from("/home/test");
        assert_eq!(expand_with("~", Some(home.clone())).unwrap(), home);
        assert_eq!(
            expand_with("~/x", Some(home.clone())).unwrap(),
            home.join("x")
        );
        assert_eq!(
            expand_with("~//x", Some(home.clone())).unwrap(),
            home.join("x")
        );
    }

    #[test]
    fn expand_without_a_home_refuses_or_falls_back_to_cwd() {
        assert_eq!(expand_with("~/x", None), Err(NoHome));
        assert_eq!(expand_or_cwd_with("~/x", None), PathBuf::from("./x"));
    }

    #[test]
    fn non_tilde_path_passes_through_unchanged() {
        let home = Some(PathBuf::from("/home/test"));
        assert_eq!(
            expand_with("x/~", home.clone()).unwrap(),
            PathBuf::from("x/~")
        );
        assert_eq!(expand_with("x/~", None).unwrap(), PathBuf::from("x/~"));
        assert_eq!(expand_or_cwd_with("x/~", home), PathBuf::from("x/~"));
        assert_eq!(expand_or_cwd_with("x/~", None), PathBuf::from("x/~"));
    }
}
