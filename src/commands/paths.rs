// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared platform path helpers for AI client config locations.
//!
//! These helpers are used by both `setup.rs` (import wizard) and
//! `config_export.rs` (config exporter) to locate client config files.

use std::path::PathBuf;

/// Join `rel` to the user's home directory.
///
/// Falls back to the current directory if `dirs::home_dir()` returns `None`
/// (unusual, but possible in restricted environments).
pub fn home_path(rel: &str) -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(rel)
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

/// Platform-specific path for Zed's shared settings file.
pub fn zed_settings_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    return home_path("Library/Application Support/Zed/settings.json");
    #[cfg(not(target_os = "macos"))]
    return home_path(".config/zed/settings.json");
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

    #[test]
    fn windsurf_path_ends_with_mcp_config_json() {
        let p = windsurf_path();
        assert_eq!(p.file_name().unwrap().to_string_lossy(), "mcp_config.json");
    }
}
