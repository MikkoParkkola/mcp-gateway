// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 CAT.1 / CLAIM.1: every shipped `cli` and `mcp` capability loads
//! pinned, with typed config and no unread keys, and either is admitted by the
//! shipped command list or is held for an egress parameter it cannot confine.

use mcp_gateway::capability::{CapabilityLoader, Integrity};
use mcp_gateway::config::ProcessCommand;

fn held_for_egress(def: &mcp_gateway::capability::CapabilityDefinition) -> bool {
    def.schema
        .input
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|props| {
            props
                .values()
                .any(|p| p.get("egress").and_then(serde_json::Value::as_bool) == Some(true))
        })
}

#[tokio::test]
async fn every_shipped_process_capability_is_pinned_typed_and_allowed_or_held() {
    let dir = format!("{}/capabilities", env!("CARGO_MANIFEST_DIR"));
    let defs = CapabilityLoader::load_directory(&dir).await.unwrap();
    let allowed = ProcessCommand::shipped();
    let mut process_caps = 0;
    for def in &defs {
        let Some(process) = def.providers.process.get("primary") else {
            continue;
        };
        process_caps += 1;
        let name = &def.name;
        assert_eq!(
            def.providers.integrity,
            Integrity::Verified,
            "{name} must load through a matching pin"
        );
        assert!(
            def.providers.unread_keys.is_empty(),
            "{name} has unread provider keys: {:?}",
            def.providers.unread_keys
        );
        let admitted = allowed
            .iter()
            .any(|a| a.admits(process.command(), &process.static_args_prefix()));
        assert!(
            admitted || held_for_egress(def),
            "{name} runs '{}', which the shipped list does not allow and is not held",
            process.command()
        );
    }
    println!("process capabilities: {process_caps}");
    assert!(
        process_caps >= 23,
        "expected the shipped cli/mcp capabilities, found {process_caps}"
    );
}

/// The mapped pyghidra tools exist in the server's published tool list
/// (snapshot from its README, v0.2.x). A real Ghidra is not available in CI, so
/// this catches a renamed or misspelled tool, not a behaviour change.
#[tokio::test]
async fn every_mapped_pyghidra_tool_is_in_the_server_snapshot() {
    use mcp_gateway::capability::ProcessConfig;
    let snapshot: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/fixtures/cap_exec/pyghidra_tools.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let dir = format!("{}/capabilities", env!("CARGO_MANIFEST_DIR"));
    let defs = CapabilityLoader::load_directory(&dir).await.unwrap();
    let def = defs.iter().find(|d| d.name == "pyghidra_reverse").unwrap();
    let Some(ProcessConfig::Mcp(config)) = def.providers.process.get("primary") else {
        panic!("pyghidra_reverse must be an mcp capability");
    };
    let selector = config.tool_selector.as_ref().expect("mapped");
    assert!(selector.tools.len() >= 10, "all operations mapped");
    for (op, call) in &selector.tools {
        assert!(
            snapshot.contains(&call.tool),
            "{op} maps to a tool the server lacks: {}",
            call.tool
        );
        if let Some(wait) = &call.wait {
            assert!(
                snapshot.contains(&wait.tool),
                "{op} waits on a tool the server lacks: {}",
                wait.tool
            );
        }
    }
}
