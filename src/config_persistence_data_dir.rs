// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where the gateway keeps its state, resolved once per call (MIK-7964).
//! Included by `#[path]` from `config_persistence.rs`.

use std::path::PathBuf;

/// Gateway state directory, honoring the existing operator override.
///
/// Always absolute when the working directory is readable: a relative override
/// resolves against the gateway's own working directory, so a backend started
/// in another `cwd` is handed the same directory (MIK-7964).
#[must_use]
pub fn gateway_data_dir() -> PathBuf {
    absolutize(resolve_gateway_data_dir(
        configured_data_dir(),
        crate::home_dir::home_dir(),
    ))
}

/// The operator's data-dir override. `var_os`: a directory that is not UTF-8 is
/// still the operator's; `var` would drop it for the default under home.
#[cfg(not(test))]
fn configured_data_dir() -> Option<std::ffi::OsString> {
    mutant!("m8", None, std::env::var_os("MCP_GATEWAY_CONFIG_DIR"))
}

/// In a test build the override counts only beside the test-home override: a
/// value inherited from a developer's shell would otherwise point a bare run
/// at their real data dir. A harness, or a test passing `child_env`, sets both.
#[cfg(test)]
fn configured_data_dir() -> Option<std::ffi::OsString> {
    mutant!(
        "m5",
        std::env::var_os("MCP_GATEWAY_CONFIG_DIR"),
        mutant!("m10", None, {
            crate::home_dir::test_override()?;
            std::env::var_os("MCP_GATEWAY_CONFIG_DIR")
        })
    )
}

/// `path` made absolute against the working directory, or kept as given when
/// that cannot be read; the cache repair refuses a relative path on its own.
fn absolutize(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}

fn resolve_gateway_data_dir(
    configured: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> PathBuf {
    configured.map_or_else(
        || {
            home.unwrap_or_else(|| PathBuf::from("."))
                .join(".mcp-gateway")
        },
        PathBuf::from,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[test]
    fn gateway_state_override_precedes_home_and_preserves_default_fallback() {
        let home = Some(std::path::PathBuf::from("operator-home"));
        assert_eq!(
            super::resolve_gateway_data_dir(Some("isolated-state".into()), home.clone()),
            std::path::PathBuf::from("isolated-state")
        );
        assert_eq!(
            super::resolve_gateway_data_dir(None, home),
            std::path::PathBuf::from("operator-home/.mcp-gateway")
        );
        assert_eq!(
            super::resolve_gateway_data_dir(None, None),
            std::path::PathBuf::from("./.mcp-gateway")
        );
    }

    #[test]
    fn a_relative_path_is_made_absolute() {
        assert!(super::absolutize(PathBuf::from("isolated-state")).is_absolute());
    }

    // Drive-relative and rooted paths are relative on Windows, and `join`
    // would replace the base with them rather than resolve them.
    #[cfg(windows)]
    #[test]
    fn windows_drive_relative_and_rooted_paths_are_made_absolute() {
        for path in [r"C:foo", r"\foo"] {
            assert!(
                super::absolutize(PathBuf::from(path)).is_absolute(),
                "{path}"
            );
        }
    }
}
