// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An MCP child's injected env value never reaches the caller, and a call
//! redacts against the env snapshot its child started with.

use serde_json::json;

use super::{
    CapabilityDefinition, CapabilityExecutor, ProcessConfig, call, caller, capability_yaml,
    executor_holding, parse_capability,
};

fn capability_with_env() -> CapabilityDefinition {
    let yaml = capability_yaml().replace(
        "transport: stdio",
        "transport: stdio\n      env: [CAP_EXEC_TEST_TOKEN]",
    );
    parse_capability(&yaml).expect("probe parses")
}

/// The server echoes the injected env value in a successful
/// result, in its `wait` ready payload too; the caller receives neither.
#[tokio::test]
async fn a_successful_result_loses_the_injected_env_value() {
    let secret = "tok-7882-mcp-redact-me";
    let (_dir, executor) = executor_holding(secret);
    let cap = capability_with_env();
    let ctx = caller("a");

    let plain = call(
        &executor,
        &cap,
        json!({"operation": "say", "text": "hello"}),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(
        plain["test_values"]["CAP_EXEC_TEST_TOKEN"], "[redacted]",
        "the child received the value, the caller does not: {plain}"
    );
    assert!(!plain.to_string().contains(secret), "{plain}");
    assert_eq!(plain["arguments"]["message"], "hello", "the rest is intact");

    let waited = call(
        &executor,
        &cap,
        json!({"operation": "import_wait", "binary_path": "x"}),
        &ctx,
    )
    .await
    .unwrap();
    assert!(
        !waited.to_string().contains(secret),
        "ready payload: {waited}"
    );
    assert!(
        waited["ready"].to_string().contains("[redacted]"),
        "the ready payload was reached and redacted: {waited}"
    );
}

/// The child is started with the environment the call redacts against, not a
/// second read of it: after a reload between the two, the value the child holds
/// is still one the result is scrubbed of.
#[tokio::test]
async fn the_child_starts_with_the_snapshot_the_call_redacts_against() {
    let (_dir, executor) = executor_holding("old-snapshot-value");
    let cap = capability_with_env();
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    let snapshot =
        |name: &str| (name == "CAP_EXEC_TEST_TOKEN").then(|| "old-snapshot-value".into());

    // A reload publishes another value after the call took its snapshot.
    let (_other, reloaded) = executor_holding("new-value-after-reload");
    executor.env.set(reloaded.env.get());

    let (backend, _workdir) = CapabilityExecutor::start_mcp(&cap, config, &snapshot, &[]).unwrap();
    let args = serde_json::Map::from_iter([("message".to_owned(), json!("x"))]);
    let echoed = super::super::call_tool(&backend, "echo", args)
        .await
        .unwrap();
    assert_eq!(
        echoed["test_values"]["CAP_EXEC_TEST_TOKEN"], "old-snapshot-value",
        "the child got the snapshot, not the reloaded value: {echoed}"
    );
}
