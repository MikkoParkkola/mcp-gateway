// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Verdict rows (V1, V2) and the rows for failures that once printed one line or none (N1-N3). They live here so
//! the table file stays under the size ceiling; they share its runner and checks.

use super::{Case, Pin, run, strings, text, two_lines};
#[cfg(feature = "config-export")]
use super::{finish, gateway_bin, write};

/// V1: doctor with a config that is not there is a verdict: its report on stdout, exit 1, nothing on stderr.
#[test]
fn doctor_missing_config_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("missing.yaml");
    let out = run(&strings(&["doctor", "--config", &text(&file)]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert!(
        stdout.starts_with("Gateway Doctor\n==============\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("{} not found", text(&file))),
        "{stdout}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "a verdict prints nothing on stderr"
    );
}

/// V2: doctor whose checks fail is a verdict: its report on stdout, exit 1, nothing on stderr.
#[test]
fn doctor_failed_check_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &file,
        "backends:\n  b1:\n    command: \"mcp-nonexistent-probe\"\n",
    )
    .expect("write config");
    let out = run(&strings(&[
        "doctor",
        "--config",
        &text(&file),
        "--no-registry-check",
    ]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("'mcp-nonexistent-probe' not found in PATH"),
        "the run did not reach the backend check: {stdout}"
    );
    assert!(
        !stdout.contains(&format!("{} not found", text(&file))),
        "the config did not load: {stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "a verdict prints nothing on stderr"
    );
}

/// N1: `upgrade` that cannot remove a key blocking the config used to exit 1 with nothing on stderr unless run with
/// `--quiet`; both forms now end with the two lines, each with its own remedy.
#[test]
fn upgrade_blocked_by_a_key_ends_with_two_lines() {
    for (quiet, remedy) in [
        (
            false,
            "Remove the keys listed above by hand, then run 'mcp-gateway upgrade' again.",
        ),
        (
            true,
            "Run `mcp-gateway upgrade` without --quiet to see them.",
        ),
    ] {
        let scratch = tempfile::tempdir().expect("scratch");
        let file = scratch.path().join("gateway.yaml");
        // A retired key in flow style: the rewrite cannot prove it safe to delete, so it stays.
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &file,
            "server: {ws_port: 1, port: 39400}\n",
        )
        .expect("write config");
        let data = scratch.path().join("data");
        let mut args = strings(&[
            "--config",
            &text(&file),
            "upgrade",
            "--data-dir",
            &text(&data),
        ]);
        if quiet {
            args.push("--quiet".to_owned());
        }
        let out = run(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "quiet {quiet}: {stderr:?}");
        let want = format!(
            "error: 1 key(s) could not be removed and the config will not load until they are.\n{remedy}\n"
        );
        assert!(stderr.ends_with(&want), "quiet {quiet}: {stderr:?}");
    }
}

/// N2: `setup export` with a client config it could not write used to exit 1 with only the FAILED row on stdout; it
/// now ends with the two lines on stderr.
#[cfg(feature = "config-export")]
#[test]
fn setup_export_with_a_failed_client_ends_with_two_lines() {
    let scratch = tempfile::tempdir().expect("scratch");
    let p = scratch.path();
    let file = p.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&file, "server:\n  port: 39400\n")
        .expect("write config");
    // Cursor's client config is .cursor/mcp.json under the working directory: a plain file named .cursor makes the
    // write fail instead of being skipped.
    write(&p.join(".cursor"), "not a folder\n");
    let home = tempfile::tempdir().expect("home");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Nothing);
    command
        .env("MCP_GATEWAY_CONFIG_DIR", home.path())
        .current_dir(p)
        .args([
            "--log-level",
            "off",
            "setup",
            "export",
            "--target",
            "cursor",
        ])
        .args(["--mode", "stdio", "--config"])
        .arg(&file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = finish(command);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FAILED"), "the client row: {stdout}");
    assert_eq!(
        stderr,
        "error: 1 client config(s) could not be written.\n\
         Fix the clients marked FAILED above, then rerun 'mcp-gateway setup export'.\n"
    );
}

/// N3: a grant argument that cannot be read is a wrong invocation, noticed before the file is touched: exit 2, the
/// grant command's help as the remedy, and no grants file written.
#[test]
fn a_bad_grant_argument_is_a_usage_error() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("grants.yaml");
    let mut args = strings(&["identity", "grants", "grant", "--file", &text(&file)]);
    args.extend(strings(&[
        "--grant-id",
        "g1",
        "--subject",
        "api_key:s1",
        "--any-agent",
        "--capability",
        "c1",
        "--reason",
        "r",
        "--expires-at",
        "not-a-time",
    ]));
    let case = Case {
        args,
        exit: 2,
        stdout: String::new(),
        first: Pin::Starts("error: expires-at must be RFC3339"),
        second: Pin::Exact("Run 'mcp-gateway identity grants grant --help' for usage.".to_owned()),
    };
    let misses = two_lines(
        "identity grants grant (bad --expires-at)",
        &run(&case.args),
        &case,
    );
    assert!(misses.is_empty(), "{}", misses.join("\n"));
    assert!(!file.exists(), "a refused invocation writes no grants file");
}
