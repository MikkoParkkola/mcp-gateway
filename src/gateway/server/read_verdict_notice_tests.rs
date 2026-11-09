// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-tenant read verdict runs on its own switch, so a gateway started
//! with the firewall off while the verdict is on says so once at startup: at
//! WARN when answers may be withheld (`block`), at INFO when it only flags.

use super::Gateway;
use crate::config::Config;

/// The marker every notice line carries.
const NOTICE: &str = "cross-tenant read verdict";

/// INFO-and-above lines logged while building the Meta-MCP for `yaml`.
fn startup_lines(yaml: &str) -> Vec<String> {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("the config loads");
    let ((), logs) = crate::test_log_capture::capture_at(tracing::Level::INFO, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let gateway = Gateway::new(config)
                    .await
                    .expect("gateway boots")
                    .with_data_dir(dir.path().to_path_buf());
                gateway.build_meta_mcp().await.expect("meta-MCP builds");
            });
    });
    logs.lines()
        .filter(|line| line.contains(NOTICE))
        .map(str::to_owned)
        .collect()
}

fn config(firewall_on: bool, arg_keys: bool, mode: &str) -> String {
    let keys = if arg_keys { "[customer_id]" } else { "[]" };
    format!(
        "security:\n  firewall:\n    enabled: {firewall_on}\n    tenant_guard:\n      \
         arg_keys: {keys}\n      cross_tenant_reads: {mode}\n"
    )
}

/// Firewall off, verdict on: one line, at the level the mode calls for,
/// naming every transport, what the mode does, attribution, and the way to
/// stop the verdict.
#[test]
fn a_firewall_off_start_names_the_read_verdict_still_running() {
    for (mode, level, consequence) in [
        ("block", "WARN", "answers may be withheld"),
        ("observe", "INFO", "only flags"),
    ] {
        let lines = startup_lines(&config(false, true, mode));
        assert_eq!(lines.len(), 1, "{mode}: exactly one notice: {lines:?}");
        let line = &lines[0];
        assert!(line.contains(level), "{mode}: logged at {level}: {line}");
        for needed in [
            "every transport",
            consequence,
            "Tenant attribution",
            "cross_tenant_reads: off",
            &format!("cross_tenant_reads: {mode}"),
        ] {
            assert!(line.contains(needed), "{mode}: names {needed:?}: {line}");
        }
    }
}

/// No notice when the verdict does not run, or runs with the firewall on.
#[test]
fn no_notice_when_the_firewall_is_on_or_the_verdict_is_off() {
    for (case, yaml) in [
        ("firewall on", config(true, true, "block")),
        ("mode off", config(false, true, "off")),
        ("no arg_keys", config(false, false, "block")),
    ] {
        assert!(startup_lines(&yaml).is_empty(), "{case}: no notice");
    }
}
