// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A second gateway process on the same config is refused at start by the
//! audit logs' writer lease, before it serves anything, and the first one goes
//! on serving.
//!
//! Each process listens on its own OS-chosen port, so a refusal here can only
//! be the lease, never a port clash. The invocation log refuses at
//! `Gateway::new` and the governance log before the router is built; both come
//! before the listener binds (`src/gateway/server/run.rs`). A refused process
//! logs no `Listening` banner: that is asserted, though only the code order
//! proves it never bound.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Above the lease's 10 s wait, so a refusal always lands inside it.
const EXIT_BOUND: Duration = Duration::from_secs(60);
const READY_BOUND: Duration = Duration::from_secs(60);
/// The invocation log, relative: opened against each process's working
/// directory, as written.
const INVOCATION_LOG: &str = "audit/transparency.jsonl";

/// One config both processes start on. Auth on also opens the governance
/// store at `<root>/cp`. The task store, which
/// holds a lease of its own, is opened after both audit logs: the exact refusal
/// sentence asserted below is what shows the audit-log lease refused first.
fn write_config(root: &Path, auth: bool) -> PathBuf {
    let auth_yaml = if auth {
        "auth:\n  enabled: true\n  bearer_token: second-process-token\n"
    } else {
        "auth:\n  enabled: false\n"
    };
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {port}\n  modern_protocol: false\n{auth_yaml}\
         security:\n  transparency_log:\n    enabled: true\n    path: {INVOCATION_LOG}\n\
         control_plane:\n  store_dir: '{cp}'\ntasks:\n  store_dir: '{tasks}'\n",
        port = gateway_bin::ANY_PORT,
        cp = root.join("cp").display(),
        tasks = root.join("tasks").display(),
    );
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, text).expect("write config");
    path
}

/// One process of the install at `root` (shared home, state dir and config),
/// run from `cwd`, logging to `log`.
fn start(root: &Path, config: &Path, cwd: &Path, log: &Path) -> gateway_bin::Reaped {
    std::fs::create_dir_all(cwd).expect("working directory");
    gateway_bin::spawn_logged(
        &root.join("home"),
        &root.join("gateway-state"),
        config,
        cwd,
        log,
    )
}

fn read(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

/// Waits until the process logging to `log` answers `/livez`.
async fn serving(gateway: &mut gateway_bin::Reaped, log: &Path) {
    let ready_by = Instant::now() + READY_BOUND;
    loop {
        if let Some(status) = gateway.child_mut().try_wait().expect("wait on the gateway") {
            panic!(
                "the gateway exited {status} instead of serving:\n{}",
                read(log)
            );
        }
        if gateway_bin::logged_port(log).is_some_and(gateway_bin::answers_livez) {
            return;
        }
        assert!(
            Instant::now() < ready_by,
            "the gateway never served:\n{}",
            read(log)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The process logging to `log` exits non-zero inside the bound, saying that
/// another gateway process writes the audit log `audit` and holds its lease,
/// and it never logged a `Listening` line.
async fn refused(gateway: &mut gateway_bin::Reaped, log: &Path, audit: &str) {
    let deadline = Instant::now() + EXIT_BOUND;
    let status = loop {
        if let Some(status) = gateway.child_mut().try_wait().expect("wait on the gateway") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the second gateway kept running:\n{}",
            read(log)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let logs = read(log);
    assert!(!status.success(), "the second gateway exited 0:\n{logs}");
    let sentence =
        format!("refusing to start: audit log {audit} is being written by another gateway process");
    assert!(
        logs.contains(&sentence) && logs.contains("is held"),
        "the refusal must name {audit} and its held lease:\n{logs}"
    );
    assert_eq!(
        gateway_bin::reported_port(&logs),
        None,
        "the refused gateway listened:\n{logs}"
    );
}

/// A first process serves; a second on the same config, run from
/// `<root>/<second_cwd>`, is refused naming `audit(root)`; the first still
/// serves. The first owns the folder, so its drained stop removes it.
async fn second_is_refused(auth: bool, second_cwd: &str, audit: impl Fn(&Path) -> String) {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let config = write_config(&root, auth);
    let (first_log, second_log) = (root.join("first.log"), root.join("second.log"));
    let mut first = start(&root, &config, &root, &first_log);
    serving(&mut first, &first_log).await;
    let mut second = start(&root, &config, &root.join(second_cwd), &second_log);
    refused(&mut second, &second_log, &audit(&root)).await;
    serving(&mut first, &first_log).await;
    first.owning(temp);
    first.stop().await;
}

/// R1 (MIK-10116.ACCEPT.5, LEASE.2): the invocation log refuses the second
/// process, naming the path as configured.
#[tokio::test]
async fn a_second_process_on_one_config_is_refused_by_the_invocation_log() {
    second_is_refused(true, ".", |_| INVOCATION_LOG.to_string()).await;
}

/// R2 (MIK-10116.ACCEPT.5): from another working directory the relative
/// invocation log is a different file, so the shared governance log refuses.
#[tokio::test]
async fn a_second_process_from_another_directory_is_refused_by_the_governance_log() {
    second_is_refused(true, "elsewhere", |root| {
        root.join("cp").join("audit.jsonl").display().to_string()
    })
    .await;
}

/// R4: with auth off a log that fails to open is skipped, but a held lease
/// still refuses.
#[tokio::test]
async fn with_auth_off_a_held_invocation_log_still_refuses() {
    second_is_refused(false, ".", |_| INVOCATION_LOG.to_string()).await;
}

/// R3 (control): once the first process has stopped, the same second start
/// serves, so what refused it in R1 was the first process's lease.
#[tokio::test]
async fn the_second_process_starts_once_the_first_has_stopped() {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let config = write_config(&root, true);
    let (first_log, second_log) = (root.join("first.log"), root.join("second.log"));
    let mut first = start(&root, &config, &root, &first_log);
    serving(&mut first, &first_log).await;
    first.stop().await;
    let mut second = start(&root, &config, &root, &second_log);
    serving(&mut second, &second_log).await;
    second.owning(temp);
    second.stop().await;
}
