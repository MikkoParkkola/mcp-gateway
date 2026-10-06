// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `init --with-examples` can be turned off, through the shipped binary.
//!
//! The flag defaults to on. The parser rejected `--with-examples=false`, which
//! `init`'s own "already exists" hint tells the user to run, so examples could
//! not be turned off at all.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Output;

fn init(dir: &Path, flag: Option<&str>) -> Output {
    let mut command = gateway_bin::command(dir, gateway_bin::Inherit::Environment);
    command
        .arg("init")
        .arg("--output")
        .arg(dir.join("gateway.yaml"));
    if let Some(flag) = flag {
        command.arg(flag);
    }
    command.output().expect("run mcp-gateway init")
}

fn wrote_examples(dir: &Path) -> bool {
    dir.join("capabilities/knowledge/weather_current.yaml")
        .exists()
}

fn assert_ok(output: &Output, flag: Option<&str>) {
    assert!(
        output.status.success(),
        "init {flag:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn with_examples_false_writes_no_examples() {
    let dir = tempfile::tempdir().expect("dir");
    let flag = Some("--with-examples=false");
    let output = init(dir.path(), flag);
    assert_ok(&output, flag);
    assert!(!wrote_examples(dir.path()), "{flag:?} still wrote examples");
}

#[test]
fn examples_stay_on_by_default_and_with_the_bare_flag() {
    for flag in [None, Some("--with-examples"), Some("--with-examples=true")] {
        let dir = tempfile::tempdir().expect("dir");
        let output = init(dir.path(), flag);
        assert_ok(&output, flag);
        assert!(wrote_examples(dir.path()), "{flag:?} wrote no examples");
    }
}

/// The hint `init` prints when an example file is in the way must name a flag
/// the parser accepts.
#[test]
fn the_already_exists_hint_names_a_working_flag() {
    let dir = tempfile::tempdir().expect("dir");
    let sample = dir
        .path()
        .join("capabilities/knowledge/weather_current.yaml");
    std::fs::create_dir_all(sample.parent().expect("parent")).expect("mkdir");
    std::fs::write(&sample, "operator's own file\n").expect("write");

    let refused = init(dir.path(), None);
    assert!(!refused.status.success(), "init overwrote an example file");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    let hint = stderr
        .split_whitespace()
        .find(|word| word.starts_with("--with-examples"))
        .unwrap_or_else(|| panic!("no flag in the hint: {stderr}"))
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric());

    let output = init(dir.path(), Some(hint));
    assert_ok(&output, Some(hint));
}
