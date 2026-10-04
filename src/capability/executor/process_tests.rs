// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 SEC.1: a process-running capability runs only when it came from a
//! file whose pin matched, names an allowed invocation exactly, and the switch
//! is on. Everything else is refused before anything is resolved or spawned.

use super::{ProcessPolicy, admit, with_schema_defaults};
use crate::capability::definition::{Integrity, ProcessConfig};
use crate::capability::{
    CapabilityDefinition, compute_capability_hash, parse_capability, parse_capability_file,
    rewrite_with_pin,
};
use crate::config::{ProcessCommand, ProcessExecution};

fn yaml(command: &str, args: &str) -> String {
    format!(
        "name: gate_probe\ndescription: Gate probe.\nschema:\n  input:\n    type: object\n    \
         properties:\n      url:\n        type: string\nproviders:\n  primary:\n    service: cli\n    \
         config:\n      command: {command}\n      args: {args}\n"
    )
}

async fn pinned(command: &str, args: &str) -> CapabilityDefinition {
    let body = yaml(command, args);
    let pinned = rewrite_with_pin(&body, &compute_capability_hash(&body));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gate_probe.yaml");
    std::fs::write(&path, pinned).unwrap();
    parse_capability_file(&path)
        .await
        .expect("pinned file loads")
}

fn process(cap: &CapabilityDefinition) -> &ProcessConfig {
    cap.providers
        .process
        .get("primary")
        .expect("typed process config")
}

#[tokio::test]
async fn a_pinned_allowlisted_definition_is_admitted() {
    let cap = pinned("gws", "[gmail, +send, \"--to={url}\"]").await;
    assert_eq!(cap.providers.integrity, Integrity::Verified);
    admit(&ProcessPolicy::default(), &cap, process(&cap)).expect("admitted");
}

#[test]
fn an_unpinned_definition_is_refused() {
    let cap = parse_capability(&yaml("gws", "[gmail]")).unwrap();
    assert_eq!(cap.providers.integrity, Integrity::Unpinned);
    let err = admit(&ProcessPolicy::default(), &cap, process(&cap))
        .unwrap_err()
        .to_string();
    assert!(err.contains("must be pinned"), "{err}");
}

#[tokio::test]
async fn a_definition_built_outside_the_parser_is_unpinned() {
    let loaded = pinned("gws", "[gmail]").await;
    let mut built = CapabilityDefinition {
        name: "built".into(),
        ..loaded.clone()
    };
    built.providers = crate::capability::ProvidersConfig {
        named: loaded.providers.named.clone(),
        process: loaded.providers.process.clone(),
        ..Default::default()
    };
    assert!(admit(&ProcessPolicy::default(), &built, process(&built)).is_err());
}

#[tokio::test]
async fn the_disabled_switch_refuses_everything() {
    let cap = pinned("gws", "[gmail]").await;
    let policy = ProcessPolicy {
        execution: ProcessExecution::Disabled,
        ..ProcessPolicy::default()
    };
    let err = admit(&policy, &cap, process(&cap)).unwrap_err().to_string();
    assert!(err.contains("process_execution"), "{err}");
}

#[tokio::test]
async fn only_an_exact_allowed_invocation_runs() {
    let refused = [
        ("sh", "[-c, id]"),
        ("/tmp/evil/gws", "[gmail]"),
        ("gwsx", "[gmail]"),
        ("mcp-scanner", "[remote, \"--server-url={url}\"]"),
        ("mcp-scanner", "[stdio, --stdio-command, sh]"),
        ("mcp-scanner", "[--analyzers, api, remote]"),
        ("skill-scanner", "[scan-all]"),
    ];
    for (command, args) in refused {
        let cap = pinned(command, args).await;
        let err = admit(&ProcessPolicy::default(), &cap, process(&cap))
            .map_or_else(|e| e.to_string(), |()| "admitted".to_string());
        assert!(
            err.contains("process_commands"),
            "{command} {args} must be refused by the allowlist: {err}"
        );
    }
}

/// MIK-7788: no shipped capability runs `mcp-scanner remote`, and the tool
/// cannot refuse private addresses at connect time, so the default list must
/// not admit it for an operator-pinned capability either.
#[tokio::test]
async fn a_pinned_remote_scanner_capability_is_refused_by_default() {
    let cap = pinned(
        "mcp-scanner",
        "[--analyzers, yara, remote, \"--server-url={url}\"]",
    )
    .await;
    let err = admit(&ProcessPolicy::default(), &cap, process(&cap))
        .map_or_else(|e| e.to_string(), |()| "admitted".to_string());
    assert!(err.contains("process_commands"), "{err}");
}

#[tokio::test]
async fn an_operator_who_lists_the_remote_scanner_still_runs_it() {
    let cap = pinned(
        "mcp-scanner",
        "[--analyzers, yara, remote, \"--server-url={url}\"]",
    )
    .await;
    let policy = ProcessPolicy {
        commands: vec![ProcessCommand {
            command: "mcp-scanner".into(),
            args_prefix: vec!["--analyzers".into(), "yara".into(), "remote".into()],
        }],
        ..ProcessPolicy::default()
    };
    admit(&policy, &cap, process(&cap)).expect("operator-listed command admitted");
}

#[tokio::test]
async fn an_operator_list_replaces_the_shipped_one() {
    let cap = pinned("/opt/tools/mytool", "[run]").await;
    let policy = ProcessPolicy {
        commands: vec![ProcessCommand {
            command: "/opt/tools/mytool".into(),
            args_prefix: vec!["run".into()],
        }],
        ..ProcessPolicy::default()
    };
    admit(&policy, &cap, process(&cap)).expect("operator-listed command admitted");
    let gws = pinned("gws", "[gmail]").await;
    assert!(
        admit(&policy, &gws, process(&gws)).is_err(),
        "shipped list replaced"
    );
}

#[test]
fn schema_defaults_fill_only_missing_or_null() {
    let schema = serde_json::json!({"properties": {
        "calendar_id": {"default": "primary"},
        "format": {"default": "json"},
        "n": {"type": "integer"}
    }});
    let merged = with_schema_defaults(&serde_json::json!({"format": "csv"}), &schema);
    assert_eq!(merged["calendar_id"], "primary");
    assert_eq!(merged["format"], "csv");
    assert!(merged.get("n").is_none());
}

/// MIK-7814 T1: a verified definition changed after loading no longer runs.
#[tokio::test]
async fn a_verified_definition_changed_after_loading_is_refused() {
    let loaded = pinned("gws", "[gmail]").await;
    let mut changed = loaded.clone();
    changed.description = "Changed after the pin was checked.".into();
    assert_eq!(changed.providers.integrity, Integrity::Verified);
    let err = admit(&ProcessPolicy::default(), &changed, process(&changed))
        .unwrap_err()
        .to_string();
    assert!(err.contains("changed after its pin"), "{err}");
}
