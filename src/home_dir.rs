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
#![allow(
    clippy::disallowed_methods,
    reason = "the one place the platform lookups are called"
)]

use std::path::PathBuf;

/// The user's home directory.
#[cfg(debug_assertions)]
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
}

/// The user's home directory.
#[cfg(not(debug_assertions))]
pub(crate) fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// The OS config directory. Under the test override it follows
/// `XDG_CONFIG_HOME` (which Windows `dirs` ignores), else `<home>/.config`.
#[cfg(all(debug_assertions, not(target_os = "macos")))]
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
pub(crate) fn config_dir() -> Option<PathBuf> {
    dirs::config_dir()
}
