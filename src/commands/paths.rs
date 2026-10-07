// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared platform path helpers for AI client config locations.
//!
//! These helpers are used by both `setup.rs` (import wizard) and
//! `config_export.rs` (config exporter) to locate client config files.

use std::path::PathBuf;

/// Join `rel` to the user's home directory.
///
/// Falls back to the current directory if no home directory resolves
/// (unusual, but possible in restricted environments).
pub fn home_path(rel: &str) -> PathBuf {
    crate::home_dir::home_dir().unwrap_or_default().join(rel)
}

/// Platform-specific path for Claude Desktop's config file.
pub fn claude_desktop_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    return home_path("Library/Application Support/Claude/claude_desktop_config.json");
    #[cfg(target_os = "linux")]
    return home_path(".config/Claude/claude_desktop_config.json");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return home_path("AppData/Roaming/Claude/claude_desktop_config.json");
}

/// Join `rel` to the OS config directory (`$XDG_CONFIG_HOME` or
/// `~/.config` on Linux, `%APPDATA%` on Windows).
#[cfg(not(target_os = "macos"))]
pub fn config_dir_path(rel: &str) -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| home_path(".config"))
        .join(rel)
}

/// Zed's settings file: Zed's own `config_dir()` joined with `settings.json`
/// (zed-industries/zed @ 1a28cff4, `crates/paths/src/paths.rs:133-152`).
/// ponytail: Zed's Flatpak override (`FLATPAK_XDG_CONFIG_HOME`) is not
/// followed; add it if a Flatpak user reports a miss.
pub fn zed_settings_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    return home_path(".config/zed/settings.json");
    #[cfg(target_os = "linux")]
    return config_dir_path("zed/settings.json");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return config_dir_path("Zed/settings.json");
}

/// Platform-specific path for Windsurf's MCP config file.
pub fn windsurf_path() -> PathBuf {
    home_path(".codeium/windsurf/mcp_config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_path_produces_nonempty_path() {
        let p = home_path(".claude.json");
        assert!(p.to_string_lossy().contains(".claude.json"));
    }

    #[test]
    fn claude_desktop_path_ends_with_expected_filename() {
        let p = claude_desktop_path();
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "claude_desktop_config.json"
        );
    }

    #[test]
    fn zed_settings_path_ends_with_settings_json() {
        let p = zed_settings_path();
        assert_eq!(p.file_name().unwrap().to_string_lossy(), "settings.json");
    }

    /// #1811: Zed reads `config_dir()/settings.json`, which is `~/.config/zed`
    /// on macOS and the OS config dir elsewhere (zed-industries/zed @ 1a28cff4,
    /// `crates/paths/src/paths.rs:133-152`).
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the oracle is the platform answer, independent of the routed lookup"
    )]
    fn zed_settings_path_matches_zed_config_dir() {
        let p = zed_settings_path();
        if cfg!(target_os = "macos") {
            assert_eq!(p, home_path(".config/zed/settings.json"));
        } else if cfg!(target_os = "linux") {
            assert_eq!(p, dirs::config_dir().unwrap().join("zed/settings.json"));
        } else {
            assert_eq!(p, dirs::config_dir().unwrap().join("Zed/settings.json"));
        }
    }

    #[test]
    fn windsurf_path_ends_with_mcp_config_json() {
        let p = windsurf_path();
        assert_eq!(p.file_name().unwrap().to_string_lossy(), "mcp_config.json");
    }
}
