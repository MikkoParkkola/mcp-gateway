// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` checks the identity-grants file the config names and
//! edits nothing. A dry run checks it too when the config loads as it stands;
//! when it does not and the rewrite would change it, the dry run defers the
//! check to the run that applies the rewrite, which refuses what it finds.
//!
//! Driven through the built binary, so each row sees what the operator sees.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::PathBuf;
use std::process::Output;

const ROW_OK: &str = "- grant_id: g-ok\n  subject:\n    authority: api_key\n    subject: alice\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: p\n  reason: kept\n";
const ROW_EMPTY: &str = "- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: p\n  reason: empty\n";
/// A removed key the config refuses to load with, which the rewrite removes.
const REFUSING: &str = "marketplace:\n  plugin_dir: /tmp/p\n";
/// A removed key that only warns at load, which the rewrite also removes.
const WARNS: &str = "meta_mcp:\n  cache_tools: true\n";
/// A defect no rewrite touches.
const BAD_PORT: &str = "server:\n  port: not-a-port\n";
const NAMELESS: &str = "1 row(s) name no one: grant 'g-empty' (empty subject)";
const CONFIG_ERROR: &str =
    "Error: the config does not load, so its identity grants were not checked";
const DEFERRED: &str = "Identity grants are checked once the rewrite above is applied.";

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

/// A data dir stamped with this build, a grants file holding `rows`, and a
/// config naming it, with `extra` appended.
fn setup(rows: &str, extra: &str) -> Setup {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("version.stamp"), env!("CARGO_PKG_VERSION")).expect("stamp");
    let grants = dir.path().join("grants.yaml");
    let body = format!("schema_version: identity_grants.v1\ngrants:\n{rows}");
    mcp_gateway::gateway::test_helpers::write_owner_only(&grants, &body).expect("grants");
    let config = dir.path().join("gateway.yaml");
    let yaml = format!(
        "security:\n  identity_grants:\n    enabled: true\n    path: {}\n{extra}",
        grants.display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, &yaml).expect("config");
    Setup { dir, config }
}

fn upgrade(s: &Setup, extra: &[&str]) -> Output {
    gateway_bin::command(s.dir.path(), gateway_bin::Inherit::Environment)
        .arg("--config")
        .arg(&s.config)
        .arg("upgrade")
        .args(extra)
        .arg("--data-dir")
        .arg(s.dir.path())
        .output()
        .expect("the upgrade command runs")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The first line of `printed` that contains `needle`.
fn line<'a>(printed: &'a str, needle: &str) -> &'a str {
    printed
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in: {printed}"))
}

/// A run's exit status and the one printed line of interest.
fn run(rows: &str, extra: &str, flags: &[&str]) -> (Option<i32>, String) {
    let s = setup(rows, extra);
    let before = std::fs::read_to_string(&s.config).unwrap();
    let out = upgrade(&s, flags);
    if flags.contains(&"--dry-run") {
        assert_eq!(
            std::fs::read_to_string(&s.config).unwrap(),
            before,
            "a dry run writes nothing"
        );
    }
    (out.status.code(), text(&out))
}

#[test]
fn a_dry_run_defers_the_grants_of_a_config_the_rewrite_must_fix() {
    let rows = format!("{ROW_OK}{ROW_EMPTY}");
    let (code, printed) = run(&rows, REFUSING, &["--dry-run"]);
    assert_eq!(code, Some(0), "{printed}");
    assert_eq!(line(&printed, DEFERRED), DEFERRED);
    assert!(!printed.contains("name no one"), "{printed}");
    let (code, printed) = run(&rows, REFUSING, &[]);
    assert_eq!(code, Some(1), "{printed}");
    assert!(line(&printed, NAMELESS).starts_with("Error: "), "{printed}");
}

#[test]
fn a_dry_run_checks_grants_when_the_config_loads_as_it_stands() {
    let (code, printed) = run(&format!("{ROW_OK}{ROW_EMPTY}"), WARNS, &["--dry-run"]);
    assert_eq!(code, Some(1), "{printed}");
    assert!(line(&printed, NAMELESS).starts_with("Error: "), "{printed}");
    assert!(!printed.contains(DEFERRED), "{printed}");
}

/// Today's behaviour, pinned so a change to it is a visible decision: a
/// config the rewrite changes but cannot make load still defers in the dry
/// run, and the applying run refuses to save the rewritten config, which
/// does not parse, one run later; the file is left as it was.
#[test]
fn a_config_no_rewrite_makes_load_defers_in_a_dry_run_and_fails_the_apply() {
    let extra = format!("{REFUSING}{BAD_PORT}");
    let (code, printed) = run(ROW_OK, &extra, &["--dry-run"]);
    assert_eq!(code, Some(0), "{printed}");
    assert_eq!(line(&printed, DEFERRED), DEFERRED);
    let s = setup(ROW_OK, &extra);
    let before = std::fs::read_to_string(&s.config).unwrap();
    let out = upgrade(&s, &[]);
    let printed = text(&out);
    assert_eq!(out.status.code(), Some(1), "{printed}");
    assert!(
        line(&printed, "does not parse as a config").starts_with("Error: Not saved: "),
        "{printed}"
    );
    assert_eq!(
        std::fs::read_to_string(&s.config).unwrap(),
        before,
        "nothing is saved"
    );
}

#[test]
fn a_dry_run_fails_a_config_that_does_not_load_and_needs_no_rewrite() {
    let (code, printed) = run(ROW_OK, BAD_PORT, &["--dry-run"]);
    assert_eq!(code, Some(1), "{printed}");
    assert!(
        line(&printed, CONFIG_ERROR).starts_with(CONFIG_ERROR),
        "{printed}"
    );
}

#[test]
fn valid_grants_pass_and_print_no_refusal() {
    for (extra, deferred) in [("", false), (WARNS, false), (REFUSING, true)] {
        for flags in [&["--dry-run"][..], &[]] {
            let (code, printed) = run(ROW_OK, extra, flags);
            assert_eq!(code, Some(0), "{extra:?} {flags:?}: {printed}");
            assert!(!printed.contains("name no one"), "{printed}");
            assert!(!printed.contains(CONFIG_ERROR), "{printed}");
            assert_eq!(
                printed.contains(DEFERRED),
                deferred && !flags.is_empty(),
                "{extra:?} {flags:?}: {printed}"
            );
        }
    }
}

#[test]
fn an_upgrade_names_the_rules_and_edits_nothing() {
    let s = setup(&format!("{ROW_OK}{ROW_EMPTY}"), "");
    let grants = s.dir.path().join("grants.yaml");
    let before = std::fs::read(&grants).unwrap();
    let out = upgrade(&s, &[]);
    let printed = text(&out);
    assert_eq!(out.status.code(), Some(1), "{printed}");
    assert!(line(&printed, NAMELESS).starts_with("Error: "), "{printed}");
    assert_eq!(std::fs::read(&grants).unwrap(), before);
}
