//! GH475.NOTICE.1 — an automatic upgrade runs quiet, and the quiet flag must not
//! silence the notices the upgrade exists to deliver.
//!
//! The regression this pins: notice application was conditional on `!quiet`, so
//! the startup path — the only path most operators ever take, and the one that
//! always passes `quiet` — applied no migration at all. `quiet` suppresses
//! progress chatter on stdout; the warnings go to stderr and stay there.
//!
//! Driven through the built binary rather than the library because the defect
//! lived in the wiring between the flag and the migration loop, and only an
//! end-to-end run observes both streams the way an operator does.

use std::process::Command;

/// Runs `mcp-gateway upgrade` over a data directory that is mid-upgrade from a
/// 2.x install with authentication switched off, and returns `(stdout, stderr)`.
fn upgrade_from_2_x(extra_args: &[&str]) -> (String, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("version.stamp"), "2.0.0").expect("stamp");
    std::fs::write(dir.path().join("gateway.yaml"), "auth:\n  enabled: false\n").expect("config");

    let out = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .arg("upgrade")
        .args(extra_args)
        .arg("--data-dir")
        .arg(dir.path())
        .output()
        .expect("the upgrade command runs");

    assert!(out.status.success(), "upgrade exited {:?}", out.status);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_quiet_upgrade_still_delivers_the_breaking_change_notices() {
    let (stdout, stderr) = upgrade_from_2_x(&["--quiet"]);

    assert!(
        stderr.contains("v4.0.0: four changes need your attention"),
        "the 4.0.0 notice never reached a quiet operator; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("auth is disabled on this gateway"),
        "the auth-disabled posture notice never reached a quiet operator; stderr was:\n{stderr}"
    );
    assert!(
        !stdout.contains("Applying:"),
        "--quiet must still suppress progress chatter on stdout; stdout was:\n{stdout}"
    );
}

#[test]
fn a_dry_run_promises_the_notices_without_delivering_them() {
    let (stdout, stderr) = upgrade_from_2_x(&["--dry-run"]);

    assert!(
        stdout.contains("[dry-run]"),
        "a dry run must say what it would do; stdout was:\n{stdout}"
    );
    assert!(
        !stderr.contains("v4.0.0: four changes need your attention"),
        "a dry run must not fire the one-time notice; stderr was:\n{stderr}"
    );
}
