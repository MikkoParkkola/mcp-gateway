// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 MCP.1 (T9): an MCP capability calls its server's tool through the
//! gateway's own backend stack, one child per caller, in a private directory,
//! and every child (and its descendants) stops when it is evicted.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

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

pub(super) fn capability_yaml() -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    format!(
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
          get_contract:
            tool: echo
            requires: [text]
            arguments: {{ message: "{{text}}" }}
          import_wait:
            tool: import_binary
            requires: [binary_path]
            arguments: {{ binary_path: "{{binary_path}}" }}
            wait:
              tool: list_project_binaries
              arguments: {{ expect: "{{binary_path}}" }}
              until:
                array: programs
                match: {{ file_path: "{{binary_path}}" }}
                field: analysis_complete
                equals: true
              interval_ms: 200
              max_wait_s: 5
          import_die:
            tool: import_binary
            requires: [binary_path]
            arguments: {{ binary_path: "{{binary_path}}" }}
            wait:
              tool: list_project_binaries
              arguments: {{ expect: "die" }}
              until:
                array: programs
                match: {{ file_path: "x" }}
                field: analysis_complete
                equals: true
              interval_ms: 200
              max_wait_s: 10
          import_slow:
            tool: import_binary
            requires: [binary_path]
            arguments: {{ binary_path: "{{binary_path}}" }}
            wait:
              tool: list_project_binaries
              arguments: {{ expect: "never" }}
              until:
                array: programs
                match: {{ file_path: "never-there" }}
                field: analysis_complete
                equals: true
              interval_ms: 200
              max_wait_s: 1
          analyze:
            tool: echo
            arguments: {{ binary_name: "" }}
            prepare:
              tool: import_binary
              arguments: {{ binary_path: "{{binary_path}}" }}
              bind: {{ binary_name: program_name }}
"#,
        python = python(),
    )
}

pub(super) fn capability() -> CapabilityDefinition {
    parse_capability(&capability_yaml()).expect("probe parses")
}

pub(super) fn caller(subject: &str) -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        caller_identity: Some(GrantSubject::new("test", subject, None)),
        ..CapabilityExecutionContext::default()
    }
}

pub(super) async fn call(
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
    let started = std::time::Instant::now();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "flood"}),
        &caller("a"),
    )
    .await;
    assert!(err.is_err(), "a 20 MiB frame must not be accepted");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a broken stream wakes the waiting call at once, not at its 20 s timeout: {:?}",
        started.elapsed()
    );
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

fn ctx_with_generation(generation: u64) -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        mcp_generation: Some(generation),
        ..caller("alice")
    }
}

/// MIK-7889 (#2777): a reload revokes under the same lock that admits a call,
/// so it cannot land between the epoch check and the lease. The bump from
/// another thread must wait for an acquire that is already past its check.
#[test]
fn a_generation_bump_waits_for_an_acquire_past_its_epoch_check() {
    let executor = std::sync::Arc::new(CapabilityExecutor::new());
    let cap = capability();
    let config: crate::capability::definition::McpConfig =
        serde_json::from_value(json!({"command": "x"})).unwrap();
    let name = cap.name.clone();
    let mut bumper = None;
    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refused = executor.mcp_children.acquire(
        &cap,
        &config,
        "alice",
        (0, Duration::from_secs(1)),
        |_| true,
        || {
            let e = std::sync::Arc::clone(&executor);
            let n = name.clone();
            let flag = std::sync::Arc::clone(&started);
            bumper = Some(std::thread::spawn(move || {
                flag.store(true, Ordering::SeqCst);
                e.bump_mcp_generation(&n);
            }));
            // The bumper is running and about to bump before the check, so
            // the unchanged generation below is the lock's doing, not a late
            // thread's.
            while !started.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(
                executor.mcp_generation(&name),
                0,
                "the reload revoked between the epoch check and the lease"
            );
            Err(crate::Error::Config("no child in this test".into()))
        },
    );
    assert!(refused.is_err());
    bumper.unwrap().join().unwrap();
    assert_eq!(executor.mcp_generation(&cap.name), 1);
}

#[tokio::test]
async fn a_call_from_before_an_unload_never_starts_a_child() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    // The backend read the generation with the definition, then the unload ran.
    let stale = ctx_with_generation(executor.mcp_generation(&cap.name));
    executor.bump_mcp_generation(&cap.name);
    executor.stop_unloaded_mcp(&|name| name != cap.name);
    let err = call(&executor, &cap, say.clone(), &stale).await;
    assert!(err.is_err(), "a stale call is refused: {err:?}");
    assert_eq!(executor.mcp_children.len(), 0, "and starts no child");
    let fresh = ctx_with_generation(executor.mcp_generation(&cap.name));
    call(&executor, &cap, say, &fresh).await.unwrap();
}

#[tokio::test]
async fn a_late_discard_leaves_a_newer_child_alone() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    call(&executor, &cap, say, &caller("alice")).await.unwrap();
    let current = executor.mcp_children.id_for_test(&cap.name);
    executor
        .mcp_children
        .discard_for_test(&cap.name, current + 1000);
    assert_eq!(
        executor.mcp_children.len(),
        1,
        "another child's id removes nothing"
    );
    executor.mcp_children.discard_for_test(&cap.name, current);
    assert_eq!(executor.mcp_children.len(), 0, "its own id removes it");
}

#[tokio::test]
async fn a_changed_provider_timeout_restarts_the_child() {
    let executor = CapabilityExecutor::new();
    let mut cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    let first = call(&executor, &cap, say.clone(), &caller("alice"))
        .await
        .unwrap();
    cap.providers.named.get_mut("primary").unwrap().timeout = 25;
    let second = call(&executor, &cap, say, &caller("alice")).await.unwrap();
    assert_ne!(
        first["pid"], second["pid"],
        "a new timeout starts a new child"
    );
}

#[tokio::test]
async fn a_long_call_does_not_count_as_idle_time() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    call(&executor, &cap, say, &caller("alice")).await.unwrap();
    let lease = executor.mcp_children.hold_for_test("alice");
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(lease);
    executor
        .mcp_children
        .evict(Duration::from_millis(200), &|_| true);
    assert_eq!(
        executor.mcp_children.len(),
        1,
        "idleness counts from when the call ended"
    );
}

#[tokio::test]
async fn an_operation_missing_a_required_parameter_is_refused_before_any_child_starts() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let err = call(
        &executor,
        &cap,
        json!({"operation": "get_contract"}),
        &caller("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("needs parameter 'text'"), "{err}");
    assert_eq!(
        executor.mcp_children.len(),
        0,
        "no child was started for it"
    );
    let ok = call(
        &executor,
        &cap,
        json!({"operation": "get_contract", "text": "hi"}),
        &caller("a"),
    )
    .await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[tokio::test]
async fn a_wait_polls_until_the_matching_item_is_ready() {
    let executor = CapabilityExecutor::new();
    let out = call(
        &executor,
        &capability(),
        json!({"operation": "import_wait", "binary_path": "/data/x"}),
        &caller("a"),
    )
    .await
    .unwrap();
    assert_eq!(out["ready"]["analysis_complete"], true, "{out}");
    assert_eq!(out["ready"]["name"], "prog-x");
    assert_eq!(out["result"]["program_name"], "prog-x");
}

#[tokio::test]
async fn a_wait_that_runs_out_says_so_and_keeps_the_child() {
    let executor = CapabilityExecutor::new();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "import_slow", "binary_path": "/data/x"}),
        &caller("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("poll again to keep waiting"), "{err}");
    assert_eq!(
        executor.mcp_children.len(),
        1,
        "a busy server is not discarded"
    );
}

fn probe_with(operation: &str) -> String {
    format!(
        r"name: mcp_probe2
description: probe
schema:
  input:
    type: object
    properties:
      operation: {{ type: string }}
      text: {{ type: string }}
providers:
  primary:
    service: mcp
    timeout: 30
    config:
      command: '{python}'
      transport: stdio
      tool_selector:
        param: operation
        tools:
          op:
{operation}
",
        python = python(),
    )
}

#[test]
fn a_requires_naming_an_undeclared_property_fails_the_load() {
    let def = parse_capability(&probe_with(
        "            tool: echo\n            requires: [typo]",
    ))
    .unwrap();
    let err = crate::capability::validate_capability(&def)
        .unwrap_err()
        .to_string();
    assert!(err.contains("requires 'typo'"), "{err}");
}

#[test]
fn a_wait_must_leave_ten_seconds_of_the_provider_timeout() {
    let wait = |max: u64| {
        probe_with(&format!(
            "            tool: echo\n            wait:\n              tool: echo\n              until: {{ array: a, match: {{ x: y }}, field: f, equals: true }}\n              max_wait_s: {max}"
        ))
    };
    let check =
        |max| crate::capability::validate_capability(&parse_capability(&wait(max)).unwrap());
    assert!(check(20).is_ok());
    let err = check(21).unwrap_err().to_string();
    assert!(err.contains("max_wait_s"), "{err}");
}

#[tokio::test]
async fn a_server_that_dies_during_a_wait_ends_it_at_once() {
    let executor = CapabilityExecutor::new();
    let started = std::time::Instant::now();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "import_die", "binary_path": "/data/x"}),
        &caller("a"),
    )
    .await;
    assert!(err.is_err(), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "a dead server is not polled for the whole wait: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn unloading_one_capability_does_not_refuse_a_call_to_another() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    let before = ctx_with_generation(executor.mcp_generation(&cap.name));
    executor.bump_mcp_generation("some_other_capability");
    call(&executor, &cap, say, &before).await.unwrap();
}

/// An env file holding one injected secret, as the executor's overlay.
fn executor_holding(secret: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(
        &file,
        format!("CAP_EXEC_TEST_TOKEN={secret}\n"),
    )
    .unwrap();
    let overlay = std::sync::Arc::new(crate::config::EnvOverlay::from_paths(&[file]));
    let env = std::sync::Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    ));
    (dir, CapabilityExecutor::new().with_env(env))
}

fn capability_with_env() -> CapabilityDefinition {
    let yaml = capability_yaml().replace(
        "transport: stdio",
        "transport: stdio\n      env: [CAP_EXEC_TEST_TOKEN]",
    );
    parse_capability(&yaml).expect("probe parses")
}

/// MIK-7882.REDACT.2: the server echoes the injected env value in a successful
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
    let echoed = super::call_tool(&backend, "echo", args).await.unwrap();
    assert_eq!(
        echoed["test_values"]["CAP_EXEC_TEST_TOKEN"], "old-snapshot-value",
        "the child got the snapshot, not the reloaded value: {echoed}"
    );
}

/// MIK-7870.RELOAD.2 and .3: a call read its definition and generation, then a
/// reload swapped in an EDITED definition of the same capability; the call
/// reaches acquire with the pre-edit generation and is refused, while a call
/// that reads after the reload runs.
#[tokio::test]
async fn a_call_that_read_the_pre_edit_definition_is_refused_after_reload() {
    use crate::capability::CapabilityBackend;

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("probe.yaml");
    std::fs::write(&file, capability_yaml()).unwrap();
    let executor = std::sync::Arc::new(CapabilityExecutor::new());
    let backend = CapabilityBackend::new("t", std::sync::Arc::clone(&executor));
    backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    // The call's read: definition, then generation.
    let stale_def = backend.get("mcp_probe").unwrap();
    let stale = ctx_with_generation(executor.mcp_generation("mcp_probe"));

    // The interleaved reload edits the capability.
    std::fs::write(
        &file,
        capability_yaml().replace("MCP probe.", "MCP probe, edited."),
    )
    .unwrap();
    backend.reload().await.unwrap();

    let say = json!({"operation": "say", "text": "x"});
    let err = call(&executor, &stale_def, say.clone(), &stale)
        .await
        .expect_err("a pre-edit call is refused at acquire");
    assert!(
        err.to_string()
            .contains("changed while this call was starting"),
        "refused by the generation check, not by a failed spawn: {err}"
    );
    assert_eq!(executor.mcp_children.len(), 0, "and starts no child");

    let fresh_def = backend.get("mcp_probe").unwrap();
    let fresh = ctx_with_generation(executor.mcp_generation("mcp_probe"));
    call(&executor, &fresh_def, say, &fresh).await.unwrap();
}

/// MIK-7925: a reload that edits an mcp capability stops its children at once,
/// without another call, as `register_capability` does; a reload that leaves
/// it unchanged keeps them.
#[tokio::test]
async fn reload_stops_an_edited_capabilitys_children_and_keeps_an_unchanged_ones() {
    use crate::capability::CapabilityBackend;

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("probe.yaml");
    std::fs::write(&file, capability_yaml()).unwrap();
    let executor = std::sync::Arc::new(CapabilityExecutor::new());
    let backend = CapabilityBackend::new("t", std::sync::Arc::clone(&executor));
    backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    let def = backend.get("mcp_probe").unwrap();
    let ctx = ctx_with_generation(executor.mcp_generation("mcp_probe"));
    let out = call(
        &executor,
        &def,
        json!({"operation": "say", "text": "x"}),
        &ctx,
    )
    .await
    .unwrap();
    let pid = out["pid"].as_i64().expect("echo reports its pid");

    backend.reload().await.unwrap();
    assert_eq!(
        executor.mcp_children.len(),
        1,
        "an unchanged reload keeps it"
    );

    std::fs::write(
        &file,
        capability_yaml().replace("MCP probe.", "MCP probe, edited."),
    )
    .unwrap();
    backend.reload().await.unwrap();
    assert_eq!(executor.mcp_children.len(), 0, "the edit stops it at once");

    #[cfg(unix)]
    {
        let pid = pid.to_string();
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
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!alive, "superseded child {pid} still running after 5 s");
    }
    #[cfg(not(unix))]
    let _ = pid;
}

#[path = "mcp_env_tests.rs"]
mod env_tests;
