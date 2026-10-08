// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7823: shipped `cisco_scanner` and `openpencil_design` do what they
//! claim. A held scan operation is refused with its reason, and the design
//! server opens files inside `capabilities.files.projects`, the root its
//! `file_path` is confined to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use crate::capability::definition::ProcessConfig;
use crate::capability::executor::CapabilityExecutor;
use crate::capability::{
    CapabilityBackend, CapabilityDefinition, CapabilityExecutionContext, parse_capability,
};
use crate::identity_grants::GrantSubject;

fn shipped(relative: &str) -> CapabilityDefinition {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative}: {e}"));
    parse_capability(&yaml).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn python() -> String {
    let name = if cfg!(windows) { "python" } else { "python3" };
    let path = std::env::var_os("PATH");
    let pathext = std::env::var_os("PATHEXT");
    super::super::cli_run::resolve_command(name, path.as_deref(), pathext.as_deref())
        .expect("python on PATH in CI")
        .display()
        .to_string()
}

/// The shipped design capability, its server swapped for the stdio double
/// that scopes `open_file` the way `@open-pencil/mcp` does.
fn openpencil() -> CapabilityDefinition {
    let mut cap = shipped("capabilities/productivity/openpencil_design.yaml");
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get_mut("primary") else {
        panic!("openpencil_design is an mcp capability");
    };
    config.command = python();
    config.args = vec![
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cap_exec/fake_mcp.py")
            .display()
            .to_string(),
    ];
    cap
}

fn executor_with_projects(projects: &Path) -> CapabilityExecutor {
    let mut executor = CapabilityExecutor::new();
    executor.process_policy.files.projects = Some(projects.to_path_buf());
    executor
}

fn caller() -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        caller_identity: Some(GrantSubject::new("test", "designer", None)),
        ..CapabilityExecutionContext::default()
    }
}

async fn open(executor: &CapabilityExecutor, cap: &CapabilityDefinition, file: &str) -> Value {
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    let params = json!({ "operation": "open_file", "file_path": file });
    executor
        .execute_mcp(cap, config, &params, &caller())
        .await
        .unwrap_or_else(|e| panic!("open_file {file}: {e}"))
}

fn project_with_design() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("design.fig");
    std::fs::write(&file, b"fig").unwrap();
    let canonical = super::super::cli::canonical(&file).unwrap();
    (dir, canonical)
}

#[tokio::test]
async fn a_held_scan_operation_is_refused_with_its_reason() {
    let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
    backend
        .register_capability(shipped("capabilities/security/cisco_scanner.yaml"))
        .unwrap();
    let args = json!({ "operation": "scan_mcp_server", "target": "server" });
    let out = backend.call_tool("cisco_scanner", args).await.unwrap();
    assert!(out.is_error, "a held operation is refused");
    let text = serde_json::to_string(&out.content).unwrap();
    assert!(
        text.contains("scan_skill_file"),
        "names the supported one: {text}"
    );
    assert!(text.contains("MIK-7788"), "says why it is held: {text}");
}

#[tokio::test]
async fn open_file_succeeds_inside_the_projects_root() {
    let (dir, file) = project_with_design();
    let executor = executor_with_projects(dir.path());
    let out = open(&executor, &openpencil(), "design.fig").await;
    assert_eq!(out["opened"], json!(file.display().to_string()));
}

/// The root reaches the server in the canonical form `file_path` is given
/// in, so a symlinked `projects` setting still matches.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_projects_root_reaches_the_server_canonical() {
    let (dir, file) = project_with_design();
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("projects");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();
    let executor = executor_with_projects(&link);
    let out = open(&executor, &openpencil(), "design.fig").await;
    assert_eq!(out["opened"], json!(file.display().to_string()));
}

/// MIK-7911: on Windows the root reaches the server in the plain drive form,
/// as the confined path does, so a server that resolves only the file still
/// finds it inside the root.
#[cfg(windows)]
#[test]
fn the_root_reaches_a_windows_server_without_the_verbatim_prefix() {
    let (dir, _) = project_with_design();
    let cap = openpencil();
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    let files = crate::config::FileRoots {
        projects: Some(dir.path().to_path_buf()),
        ..crate::config::FileRoots::default()
    };
    let roots = super::bound_roots(config, &files);
    assert!(!roots.is_empty(), "precondition: the root is bound");
    for (name, root) in &roots {
        assert!(!root.starts_with(r"\\?\"), "{name}={root}");
    }
}

#[tokio::test]
async fn a_changed_projects_root_restarts_the_server() {
    let (first, _) = project_with_design();
    let (second, file) = project_with_design();
    let mut executor = executor_with_projects(first.path());
    let cap = openpencil();
    let before = open(&executor, &cap, "design.fig").await;
    executor.process_policy.files.projects = Some(second.path().to_path_buf());
    let after = open(&executor, &cap, "design.fig").await;
    assert_eq!(after["opened"], json!(file.display().to_string()));
    assert_ne!(
        before["pid"], after["pid"],
        "a new root starts a new server"
    );
}

#[tokio::test]
async fn a_root_bound_to_a_reserved_name_is_ignored() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    let yaml = format!(
        r"name: root_probe
description: Root probe.
schema:
  input:
    type: object
    properties:
      operation:
        type: string
providers:
  primary:
    service: mcp
    timeout: 20
    config:
      command: '{python}'
      args: ['{script}']
      root_env:
        HOME: projects
      tool_selector:
        param: operation
        tools:
          say: {{ tool: echo }}
",
        python = python(),
    );
    let cap = parse_capability(&yaml).expect("probe parses");
    let (dir, _) = project_with_design();
    let executor = executor_with_projects(dir.path());
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    let out = executor
        .execute_mcp(&cap, config, &json!({ "operation": "say" }), &caller())
        .await
        .unwrap();
    let root = super::super::cli::canonical(dir.path()).unwrap();
    assert_ne!(
        out["home"],
        json!(root.display().to_string()),
        "HOME stays the private work directory"
    );
}
