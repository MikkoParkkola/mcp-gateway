// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A prerelease build keeps its prerelease in the stamp, and migrations gated
//! on a release still reach installs stamped with a prerelease of it.

use tempfile::TempDir;

use super::{SemVer, UpgradeContext, check_upgrade, read_stamp, stamp_path, write_stamp};

/// The stamp a 4.0.0 binary writes: major.minor.patch pinned to the literal
/// 4.0.0, plus the manifest's own prerelease (`4.0.0-beta.1` on the beta,
/// `4.0.0` on the final). Any other version, 4.0.1 included, fails.
pub(super) fn stamp_4_0_0() -> String {
    match env!("CARGO_PKG_VERSION_PRE") {
        "" => "4.0.0".to_string(),
        pre => format!("4.0.0-{pre}"),
    }
}

fn gated_on_4_0_0(installed: &str) -> usize {
    let dir = TempDir::new().unwrap();
    let ctx = UpgradeContext {
        data_dir: dir.path(),
        old_ver: SemVer::parse(installed).unwrap(),
        new_ver: SemVer::parse("4.0.0").unwrap(),
        dry_run: true,
        quiet: true,
    };
    ctx.applicable_migrations()
        .iter()
        .filter(|m| m.applies_below == "4.0.0")
        .count()
}

#[test]
fn upgrading_a_3x_install_stamps_the_full_binary_version() {
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), "3.5.1").unwrap();
    check_upgrade(dir.path()).unwrap();
    assert_eq!(
        read_stamp(&stamp_path(dir.path())).unwrap().unwrap(),
        env!("CARGO_PKG_VERSION"),
        "the migration path must not drop the prerelease from the stamp"
    );
}

#[test]
fn a_4_0_0_migration_reaches_a_beta_install_and_not_a_final_one() {
    assert_eq!(
        gated_on_4_0_0("4.0.0-beta.1"),
        1,
        "beta install must migrate"
    );
    assert_eq!(gated_on_4_0_0("4.0.0-rc.1"), 1, "rc install must migrate");
    assert_eq!(
        gated_on_4_0_0("4.0.0"),
        0,
        "a final install must not re-run it"
    );
}

#[test]
fn a_stamp_at_this_build_is_neither_unknown_nor_newer() {
    let current = SemVer::parse(env!("CARGO_PKG_VERSION")).expect("own version parses");
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), env!("CARGO_PKG_VERSION")).unwrap();
    check_upgrade(dir.path()).unwrap();
    let stamp = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(SemVer::parse(&stamp), Some(current));
    assert!(SemVer::parse("4.0.0-beta.1").unwrap() < SemVer::parse("4.0.0").unwrap());
}
