// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 MCP.1 (T9): an MCP capability calls its server's tool through the
//! gateway's own backend stack, one child per caller, in a private directory,
//! and every child (and its descendants) stops when it is evicted.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::capability::definition::ProcessConfig;
use crate::capability::executor::CapabilityExecutor;
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext, parse_capability};
use crate::identity_grants::GrantSubject;

fn python() -> String {
    let name = if cfg!(windows) { "python" } else { "python3" };
    let path = std::env::var_os("PATH");
    let pathext = std::env::var_os("PATHEXT");
    super::super::cli_run::resolve_command(name, path.as_deref(), pathext.as_deref())
        .expect("python on PATH in CI")
        .display()
        .to_string()
}

fn capability() -> CapabilityDefinition {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    let yaml = format!(
        r#"name: mcp_probe
description: MCP probe.
schema:
  input:
    type: object
    properties:
      operation:
        type: string
      text:
        type: string
      binary_path:
        type: string
providers:
  primary:
    service: mcp
    timeout: 20
    config:
      command: '{python}'
      args: ['{script}']
      transport: stdio
      tool_selector:
        param: operation
        tools:
          say: {{ tool: echo, arguments: {{ message: "{{text}}" }} }}
          refuse: {{ tool: fail }}
          flood: {{ tool: flood }}
          spawn: {{ tool: grandchild }}
          analyze:
            tool: echo
            arguments: {{ binary_name: "" }}
            prepare:
              tool: import_binary
              arguments: {{ binary_path: "{{binary_path}}" }}
              bind: {{ binary_name: program_name }}
"#,
        python = python(),
    );
    parse_capability(&yaml).expect("probe parses")
}

fn caller(subject: &str) -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        caller_identity: Some(GrantSubject::new("test", subject, None)),
        ..CapabilityExecutionContext::default()
    }
}

async fn call(
    executor: &CapabilityExecutor,
    cap: &CapabilityDefinition,
    params: Value,
    context: &CapabilityExecutionContext,
) -> crate::Result<Value> {
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    executor.execute_mcp(cap, config, &params, context).await
}

#[tokio::test]
async fn an_operation_calls_its_mapped_tool_with_typed_arguments() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let out = call(
        &executor,
        &cap,
        json!({"operation": "say", "text": "hi"}),
        &caller("a"),
    )
    .await
    .unwrap();
    assert_eq!(out["name"], "echo");
    assert_eq!(out["arguments"], json!({"message": "hi"}));
}

#[tokio::test]
async fn an_unknown_operation_is_refused_before_any_child_starts() {
    let executor = CapabilityExecutor::new();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "rm"}),
        &caller("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown operation"), "{err}");
    assert_eq!(executor.mcp_children.len(), 0);
}

#[tokio::test]
async fn a_tool_error_is_an_error() {
    let executor = CapabilityExecutor::new();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "refuse"}),
        &caller("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("tool said no"), "{err}");
}

#[tokio::test]
async fn each_caller_has_its_own_child_and_directory() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    let a1 = call(&executor, &cap, say.clone(), &caller("alice"))
        .await
        .unwrap();
    let a2 = call(&executor, &cap, say.clone(), &caller("alice"))
        .await
        .unwrap();
    let b = call(&executor, &cap, say, &caller("bob")).await.unwrap();
    assert_eq!(a1["pid"], a2["pid"], "one caller reuses its child");
    assert_ne!(a1["pid"], b["pid"], "another caller gets another child");
    assert_ne!(a1["cwd"], b["cwd"], "and another directory");
    let home = Path::new(a1["home"].as_str().unwrap());
    assert_eq!(
        home.file_name(),
        Path::new(a1["cwd"].as_str().unwrap()).file_name(),
        "HOME is the child's private directory"
    );
}

#[tokio::test]
async fn an_unidentified_caller_is_refused_on_a_multi_user_gateway() {
    let executor = CapabilityExecutor::new();
    executor.multi_user.store(true, Ordering::Release);
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "say", "text": "x"}),
        &CapabilityExecutionContext::default(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("identified caller"), "{err}");
}

#[tokio::test]
async fn the_prepare_step_binds_its_result_into_the_main_call() {
    let executor = CapabilityExecutor::new();
    let out = call(
        &executor,
        &capability(),
        json!({"operation": "analyze", "binary_path": "/bin/ls"}),
        &caller("a"),
    )
    .await
    .unwrap();
    assert_eq!(out["arguments"]["binary_name"], "prog-ls");
}

#[tokio::test]
async fn a_frame_over_the_limit_fails_the_call() {
    let executor = CapabilityExecutor::new();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "flood"}),
        &caller("a"),
    )
    .await;
    assert!(err.is_err(), "a 20 MiB frame must not be accepted");
}

#[cfg(unix)]
#[tokio::test]
async fn unloading_stops_the_child_and_its_descendants() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let out = call(&executor, &cap, json!({"operation": "spawn"}), &caller("a"))
        .await
        .unwrap();
    let pid = out["pid"].as_i64().unwrap().to_string();
    assert_eq!(executor.mcp_children.len(), 1);
    executor.stop_unloaded_mcp(&|_| false);
    assert_eq!(executor.mcp_children.len(), 0, "evicted at once");
    let mut alive = true;
    for _ in 0..50 {
        let status = std::process::Command::new("kill")
            .args(["-0", &pid])
            .status()
            .unwrap();
        if !status.success() {
            alive = false;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!alive, "grandchild {pid} outlived its MCP child");
}

#[tokio::test]
async fn a_full_pool_evicts_its_least_recently_used_idle_child() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    for n in 0..=super::MAX_CHILDREN_PER_CAPABILITY {
        call(
            &executor,
            &cap,
            say.clone(),
            &caller(&format!("caller-{n}")),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        executor.mcp_children.len(),
        super::MAX_CHILDREN_PER_CAPABILITY,
        "the 17th caller replaced the idlest child instead of growing the pool"
    );
}

#[tokio::test]
async fn unloading_stops_a_child_even_while_a_call_is_in_flight() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    call(&executor, &cap, say, &caller("alice")).await.unwrap();
    let lease = executor.mcp_children.hold_for_test("alice");
    executor.stop_unloaded_mcp(&|name| name != cap.name);
    assert_eq!(
        executor.mcp_children.len(),
        0,
        "unload does not wait for a busy child"
    );
    drop(lease);
}
