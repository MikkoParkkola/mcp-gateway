// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook `notify` notice reaches installs already stamped 4.0.0.
//!
//! Pre-release builds stamp 4.0.0, so the `applies_below: "4.0.0"` release
//! notice never runs for them. These rows pin the once-only notice that does,
//! through the marker file it leaves behind.

use std::path::Path;

use tempfile::TempDir;

use super::{check_upgrade, stamp_path, webhook_notice};

const MARKER: &str = ".notice-4.0.0-webhook-notify";

fn stamped(version: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::write(stamp_path(dir.path()), version).unwrap();
    dir
}

fn marked(dir: &Path) -> bool {
    dir.join(MARKER).exists()
}

#[test]
fn an_install_already_stamped_at_this_version_gets_the_webhook_notice() {
    let dir = stamped(env!("CARGO_PKG_VERSION"));
    check_upgrade(dir.path()).unwrap();
    assert!(
        marked(dir.path()),
        "the notice must reach a pre-stamped install"
    );
}

#[test]
fn an_upgrade_from_3_x_records_the_notice_the_release_notice_carried() {
    let dir = stamped("3.5.0");
    check_upgrade(dir.path()).unwrap();
    assert!(
        marked(dir.path()),
        "the release notice carries it; no repeat"
    );
}

#[test]
fn a_fresh_install_is_not_told_about_a_default_it_never_had() {
    let dir = TempDir::new().unwrap();
    check_upgrade(dir.path()).unwrap();
    assert!(
        marked(dir.path()),
        "a fresh install is marked, not notified"
    );
}

#[test]
fn the_notice_is_written_once_and_names_the_opt_in() {
    let dir = TempDir::new().unwrap();
    let mut first = Vec::new();
    assert!(webhook_notice::show_once(dir.path(), &mut first).unwrap());
    let text = String::from_utf8(first).unwrap();
    assert!(text.contains("notify: true"), "{text}");

    let mut second = Vec::new();
    assert!(!webhook_notice::show_once(dir.path(), &mut second).unwrap());
    assert!(second.is_empty(), "a second start repeats nothing");
}
