// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! V1 (MIK-9681.CLIUX.20): `--version` names the CLI version and the UI API version. No feature gate, so the CLI built
//! without webui runs it too.

/// The package version, read from Cargo.toml (never from the macro or clap).
fn package_version() -> &'static str {
    include_str!("../Cargo.toml")
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("Cargo.toml names the package version")
}

#[test]
fn the_version_line_names_the_ui_api_version() {
    use clap::CommandFactory;
    assert_eq!(
        crate::cli::Cli::command().render_version(),
        format!("mcp-gateway {} (UI API 1)\n", package_version())
    );
}
