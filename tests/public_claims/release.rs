// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The release-metadata claims: `server.json` tracks the Cargo version between
//! releases, and the generated Homebrew formula stays Gatekeeper-safe. Moved
//! from the parent test file for the file-size ceiling.

use super::*;

fn cargo_toml_package_version() -> String {
    let cargo_toml = read_repo_file("Cargo.toml");
    let package_section = cargo_toml
        .split_once("[package]")
        .map(|(_, rest)| rest)
        .expect("Cargo.toml should have a [package] section");
    let package_section = package_section
        .split_once("\n[")
        .map_or(package_section, |(section, _)| section);
    package_section
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("version")?;
            let rest = rest.trim_start().strip_prefix('=')?.trim();
            rest.strip_prefix('"')?.strip_suffix('"')
        })
        .expect("[package] section should declare a version")
        .to_string()
}

#[test]
fn server_json_version_tracks_cargo_toml_between_releases() {
    let server_json: serde_json::Value = serde_json::from_str(&read_repo_file("server.json"))
        .expect("server.json should be valid JSON");
    let cargo_version = cargo_toml_package_version();

    assert_eq!(
        server_json["version"].as_str(),
        Some(cargo_version.as_str()),
        "checked-in server.json version should track Cargo.toml's [package] version; the \
         release workflow re-stamps version and package identifiers from the pushed git tag \
         at publish time, but the committed file must not drift behind development between \
         releases"
    );

    let packages = server_json["packages"]
        .as_array()
        .expect("server.json should declare at least one package");
    let oci_identifier = packages
        .iter()
        .find(|package| package["registryType"] == "oci")
        .and_then(|package| package["identifier"].as_str())
        .expect("server.json should declare an OCI package identifier");
    assert_eq!(
        oci_identifier,
        format!("ghcr.io/mikkoparkkola/mcp-gateway:{cargo_version}"),
        "checked-in OCI package identifier should carry the same version tag as Cargo.toml"
    );

    if let Some(cargo_package) = packages
        .iter()
        .find(|package| package["registryType"] == "cargo")
    {
        assert_eq!(
            cargo_package["version"].as_str(),
            Some(cargo_version.as_str()),
            "checked-in cargo package version should track Cargo.toml"
        );
    }
}

#[test]
fn generated_homebrew_formula_stays_gatekeeper_safe() {
    let workflow = read_repo_file(".github/workflows/release.yml");
    let formula = workflow
        .split_once("cat > homebrew-tap/Formula/mcp-gateway.rb <<EOF\n")
        .and_then(|(_, remainder)| remainder.split_once("\n          EOF"))
        .map(|(formula, _)| formula)
        .expect("release workflow should contain the generated Homebrew formula");

    for required in ["on_macos do", "on_linux do", "def install", "test do"] {
        assert!(
            formula.contains(required),
            "generated formula is missing {required:?}"
        );
    }

    assert!(
        formula
            .lines()
            .any(|line| line.trim() == "version \"${VERSION}\""),
        "generated formula must provide the release version explicitly"
    );
    for forbidden in ["post_install", "xattr", "com.apple.quarantine"] {
        assert!(
            !formula.contains(forbidden),
            "generated formula must not contain {forbidden:?}"
        );
    }
}
