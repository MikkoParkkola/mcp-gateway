// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8664 (DUPC-7.PR7.7): a save through a rename-based writer keeps the mode
//! an operator gave the file. Each case runs in a child under `umask 022`: the
//! umask is process-wide, and a host's own (077 on some) would hide the reset.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

const CASE: &str = "MCP_GW_TEST_MODE_INHERIT_CASE";

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Runs [`child`] for `case` in a child under umask 022.
fn in_child(case: &str) {
    let out = std::process::Command::new("sh")
        .args(["-c", "umask 022; exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "file_mode_inherit_tests::child",
            "--ignored",
            "--nocapture",
        ])
        .env(CASE, case)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{case} under umask 022:\n{stdout}\n{stderr}"
    );
    // Printed only after the child's assertion, so a child that ran no case
    // cannot read as a pass.
    assert!(
        stdout.contains(&format!("{case} child ok")),
        "{case}: the child ran no case"
    );
}

#[test]
#[ignore = "run by the cases below, in a child under umask 022"]
fn child() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    let (start, want) = match case.as_str() {
        "skills-0600" | "cost-0600" => (0o600, 0o600),
        "skills-0640" => (0o640, 0o640),
        other => panic!("unknown case {other}"),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(start)).unwrap();
    match case.as_str() {
        #[cfg(feature = "cost-governance")]
        "cost-0600" => {
            crate::cost_accounting::persistence::save(
                &path,
                &crate::cost_accounting::persistence::PersistedCosts::default(),
            )
            .unwrap();
        }
        _ => crate::skills::SkillRegistry::new().save(&path).unwrap(),
    }
    assert_eq!(
        mode(&path),
        want,
        "{case}: the save changed the mode the operator set"
    );
    println!("{case} child ok");
}

#[test]
fn a_skills_save_keeps_an_owner_only_file() {
    in_child("skills-0600");
}

#[cfg(feature = "cost-governance")]
#[test]
fn a_cost_save_keeps_an_owner_only_file() {
    in_child("cost-0600");
}

/// Linux, the file's own group and no ACL: the operator's full mode stands.
#[cfg(target_os = "linux")]
#[test]
fn a_skills_save_keeps_a_group_readable_file() {
    in_child("skills-0640");
}
