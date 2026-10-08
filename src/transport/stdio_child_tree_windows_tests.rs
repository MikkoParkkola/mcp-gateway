// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8080 W1: on Windows the Job is ended by its handle even after the
//! leader exited, so a descendant left in the Job dies, and `finish` (whose
//! `JobObject` wait blocks until the Job is empty) returns the leader's status.
//!
//! The descendant is checked through a process handle (`Get-Process` plus its
//! start time), so a reused pid cannot pass for it.

use std::path::Path;
use std::time::Duration;

use super::super::spawn_in_own_tree;
use super::{ChildTree, wait_exited};

const LIMIT: Duration = Duration::from_secs(20);

/// Leader: starts a long `ping` in its Job, records `pid ticks`, exits 3.
const LEADER: &str = "$p = Start-Process -FilePath ping -ArgumentList '-n','120','127.0.0.1' \
    -PassThru -NoNewWindow -RedirectStandardOutput nul; \
    Set-Content -Path d.pid -Value \"$($p.Id) $($p.StartTime.Ticks)\"; exit 3";

fn powershell(script: &str, dir: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    cmd
}

/// The leader has exited (observed, not waited on); its descendant is alive.
async fn exited_leader(dir: &Path) -> (ChildTree, String) {
    let mut tree = ChildTree::new(spawn_in_own_tree(powershell(LEADER, dir)).expect("spawn"));
    assert!(wait_exited(&mut tree, LIMIT).await, "the leader exits");
    let descendant = std::fs::read_to_string(dir.join("d.pid")).expect("descendant pid");
    let descendant = descendant.trim().to_owned();
    assert!(running(&descendant, dir).await, "the descendant runs on");
    (tree, descendant)
}

/// Whether the recorded descendant (same pid and start time) still runs.
async fn running(descendant: &str, dir: &Path) -> bool {
    let (pid, ticks) = descendant.split_once(' ').expect("pid ticks");
    let script = format!(
        "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
         if (-not $p -or $p.StartTime.Ticks -ne {ticks}) {{ exit 1 }}; exit 0"
    );
    powershell(&script, dir)
        .status()
        .await
        .expect("powershell")
        .success()
}

/// Waits on the descendant's handle: true once it has exited.
async fn dies(descendant: &str, dir: &Path) -> bool {
    let (pid, ticks) = descendant.split_once(' ').expect("pid ticks");
    let script = format!(
        "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
         if (-not $p -or $p.StartTime.Ticks -ne {ticks}) {{ exit 0 }}; \
         if ($p.WaitForExit(10000)) {{ exit 0 }} else {{ exit 1 }}"
    );
    powershell(&script, dir)
        .status()
        .await
        .expect("powershell")
        .success()
}

#[tokio::test]
async fn finish_after_the_exit_ends_the_job() {
    let dir = tempfile::tempdir().expect("dir");
    let (mut tree, descendant) = exited_leader(dir.path()).await;
    let status = tokio::time::timeout(LIMIT, tree.finish())
        .await
        .expect("finish returns once the Job is ended");
    assert_eq!(status.and_then(|s| s.code()), Some(3));
    assert_eq!(tree.group_signals_sent, 1);
    assert!(
        dies(&descendant, dir.path()).await,
        "the Job outlived finish"
    );
}

#[tokio::test]
async fn dropping_after_the_exit_ends_the_job() {
    let dir = tempfile::tempdir().expect("dir");
    let (tree, descendant) = exited_leader(dir.path()).await;
    drop(tree);
    assert!(
        dies(&descendant, dir.path()).await,
        "the Job outlived the drop"
    );
}
