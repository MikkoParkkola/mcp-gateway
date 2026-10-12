// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Integration tests for `mcp-gateway tool list`.
//!
//! Regression coverage for issue #225: `tool list` scans a *local* capability
//! YAML directory and is independent of the running gateway's config. When the
//! directory is absent it must degrade gracefully (empty catalogue, exit 0)
//! with a one-line explanation on stderr, rather than hard-failing.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

#[test]
fn test_tool_list_missing_dir_degrades_gracefully() {
    // A path guaranteed not to exist.
    let missing = {
        let mut p = std::env::temp_dir();
        p.push("mcp-gateway-nonexistent-caps-225");
        p.push("definitely-not-here");
        p
    };
    assert!(!missing.exists(), "test precondition: path must not exist");

    let home = tempfile::tempdir().expect("an isolated home");
    let output = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["tool", "list", "-C"])
        .arg(&missing)
        .output()
        .expect("run `mcp-gateway tool list`");

    // Must NOT hard-fail (issue #225 was a non-zero exit on a missing dir).
    assert!(
        output.status.success(),
        "tool list on a missing capability dir should exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // The explanation names the missing directory and says where the scanned
    // directories come from. Since MIK-8044 an unset -C reads the config's
    // `capabilities.directories`, so the 3.x "independent of your server
    // config" wording would now be false.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No capability catalogue at")
            && stderr.contains("without either it reads the gateway config's"),
        "expected an orienting message on stderr, got: {stderr:?}"
    );
}
