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
