// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::path::{Path, PathBuf};

use super::*;

const CONFIG: &str = "\
# my gateway
backends:
  fs:
    http_url: \"https://fs.example.com/mcp?token=canary-upgrade\"  # primary
  rt:
    ws_url: \"wss://rt.example.com/mcp\"
";

fn config_in(dir: &Path) -> PathBuf {
    let path = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, CONFIG).expect("write config");
    path
}

fn report(path: &Path, mode: RewriteMode) -> (Vec<String>, String) {
    let rewrite = rewrite_url_aliases_in(path, mode).expect("rewrite runs");
    let text = std::fs::read_to_string(path).expect("read back");
    (url_report(path, &rewrite, mode), text)
}

#[test]
fn upgrade_rewrites_the_aliases_and_names_the_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_in(dir.path());
    let (lines, text) = report(&path, RewriteMode::Apply);
    assert!(
        text.contains("    url: \"https://fs") && text.contains("    url: \"wss://rt"),
        "{text}"
    );
    assert!(
        text.contains("# primary") && text.contains("# my gateway"),
        "{text}"
    );
    let said = lines.join("\n");
    assert!(said.contains("line 4") && said.contains("line 6"), "{said}");
    assert!(
        !said.contains("canary-upgrade") && !said.contains("example.com"),
        "the report printed a URL: {said}"
    );
}

#[test]
fn a_second_upgrade_changes_nothing_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_in(dir.path());
    let _ = report(&path, RewriteMode::Apply);
    let before = std::fs::read_to_string(&path).expect("read");
    let (lines, after) = report(&path, RewriteMode::Apply);
    assert_eq!(before, after);
    assert!(lines.join("\n").contains("nothing changed"), "{lines:?}");
}

#[test]
fn a_dry_run_leaves_the_file_and_says_what_it_would_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_in(dir.path());
    let (lines, text) = report(&path, RewriteMode::DryRun);
    assert_eq!(text, CONFIG);
    let said = lines.join("\n");
    assert!(said.contains("would") && said.contains("line 4"), "{said}");
}

#[test]
fn upgrade_with_config_rewrites_the_named_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_in(dir.path());
    let data = dir.path().join("data");
    let code = run_upgrade_with_config(false, true, Some(&data), Some(&path));
    assert_eq!(code, ExitCode::SUCCESS);
    let text = std::fs::read_to_string(&path).expect("read back");
    assert!(
        !text.contains("http_url") && !text.contains("ws_url"),
        "{text}"
    );
}

#[test]
fn a_skipped_backend_message_covers_every_reason() {
    let rewrite = UrlRewrite {
        skipped: vec!["fs".into()],
        ..UrlRewrite::default()
    };
    let lines = url_report(Path::new("g.yaml"), &rewrite, RewriteMode::Apply);
    let line = lines.last().expect("a line");
    assert!(line.contains("backends fs"), "{line}");
    assert!(line.contains("could not edit safely"), "{line}");
}

#[test]
fn upgrade_keeps_an_alias_that_is_not_an_address_of_its_scheme_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  fs:\n    http_url: \"${FS_URL}\"\n",
    )
    .expect("write config");
    let (lines, text) = report(&path, RewriteMode::Apply);
    assert!(text.contains("http_url: \"${FS_URL}\""), "{text}");
    let said = lines.join("\n");
    assert!(
        said.contains("kept") && said.contains("backends fs"),
        "{said}"
    );
}
