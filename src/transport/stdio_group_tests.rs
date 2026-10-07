// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process-group teardown tests for the stdio transport.

use super::*;
use std::collections::HashMap;

#[cfg(unix)]
fn tree_backend(workspace: &std::path::Path, term_ignoring: bool) -> (String, std::path::PathBuf) {
    let server = workspace.join("tree-server.sh");
    let pidfile = workspace.join("pids");
    let (trap, linger) = if term_ignoring {
        ("trap '' TERM\n", "wait\n")
    } else {
        ("", "")
    };
    std::fs::write(
        &server,
        format!(
            r#"{trap}echo $$ > "{pids}"
sleep 1000 &
echo $! >> "{pids}"
while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-11-25"}}}}'
        ;;
esac
done
{linger}"#,
            pids = pidfile.display()
        ),
    )
    .expect("write tree backend");
    ("sh tree-server.sh".to_string(), pidfile)
}

#[cfg(unix)]
fn start_tree_transport(workspace: &std::path::Path, command: &str) -> Arc<StdioTransport> {
    StdioTransport::new(
        command,
        HashMap::new(),
        Some(workspace.to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    )
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
async fn wait_until_gone(pid: u32, within: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if !pid_is_alive(pid) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    !pid_is_alive(pid)
}

#[cfg(unix)]
fn read_pids(pidfile: &std::path::Path) -> (u32, u32) {
    let raw = std::fs::read_to_string(pidfile).expect("backend recorded its pids");
    let pids: Vec<u32> = raw
        .split_whitespace()
        .filter_map(|value| value.parse().ok())
        .collect();
    assert_eq!(
        pids.len(),
        2,
        "expected a leader and a descendant, got {pids:?}"
    );
    (pids[0], pids[1])
}

#[cfg(unix)]
#[tokio::test]
async fn close_kills_the_whole_backend_process_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = tree_backend(workspace.path(), false);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (leader, descendant) = read_pids(&pidfile);
    assert!(
        pid_is_alive(descendant),
        "precondition: descendant is running"
    );

    transport.close().await.expect("close");

    assert!(
        wait_until_gone(descendant, std::time::Duration::from_secs(5)).await,
        "descendant pid {descendant} survived close(): the group was not signalled"
    );
    assert!(
        wait_until_gone(leader, std::time::Duration::from_secs(5)).await,
        "leader pid {leader} survived close()"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_without_close_also_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = tree_backend(workspace.path(), false);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (leader, descendant) = read_pids(&pidfile);

    drop(transport);

    assert!(
        wait_until_gone(descendant, std::time::Duration::from_secs(5)).await,
        "descendant pid {descendant} survived dropping every handle: kill_on_drop \
         reaches the leader only, so the drop path needs its own group kill"
    );
    assert!(
        wait_until_gone(leader, std::time::Duration::from_secs(5)).await,
        "leader pid {leader} survived the drop"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_leader_that_ignores_sigterm_is_killed_after_the_grace() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = tree_backend(workspace.path(), true);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (leader, descendant) = read_pids(&pidfile);

    transport.close().await.expect("close");

    assert!(
        wait_until_gone(leader, std::time::Duration::from_secs(10)).await,
        "leader pid {leader} ignores SIGTERM and survived the escalation to SIGKILL"
    );
    assert!(
        wait_until_gone(descendant, std::time::Duration::from_secs(10)).await,
        "descendant pid {descendant} survived alongside an ignoring leader"
    );
}

#[cfg(unix)]
fn self_exiting_leader_backend(workspace: &std::path::Path) -> (String, std::path::PathBuf) {
    let server = workspace.join("self-exit-server.sh");
    let pidfile = workspace.join("pids");
    std::fs::write(
        &server,
        format!(
            r#"echo $$ > "{pids}"
sh -c 'sleep 1000' &
echo $! >> "{pids}"
while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-11-25"}}}}'
        ;;
    *'notifications/initialized'*)
        exit 0
        ;;
esac
done
"#,
            pids = pidfile.display()
        ),
    )
    .expect("write self-exiting backend");
    ("sh self-exit-server.sh".to_string(), pidfile)
}

#[cfg(unix)]
async fn wait_until_disconnected(transport: &StdioTransport) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while transport.is_connected() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(!transport.is_connected(), "precondition: the leader exited");
}

#[cfg(unix)]
fn pid(raw: u32) -> Pid {
    Pid::from_raw(raw.cast_signed()).expect("nonzero pid")
}

#[cfg(unix)]
#[tokio::test]
async fn close_after_the_leader_exited_still_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = tree_backend(workspace.path(), false);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (leader, descendant) = read_pids(&pidfile);

    std::process::Command::new("kill")
        .args(["-9", &leader.to_string()])
        .status()
        .expect("kill leader");
    wait_until_disconnected(&transport).await;
    assert!(
        pid_is_alive(descendant),
        "precondition: the descendant outlives its leader"
    );

    transport
        .close()
        .await
        .expect("close on an exited leader must not error");

    assert!(
        wait_until_gone(descendant, std::time::Duration::from_secs(5)).await,
        "descendant pid {descendant} survived a close() after its leader exited"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn close_kills_a_grandchild_that_outlived_a_self_exiting_leader() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = self_exiting_leader_backend(workspace.path());
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (_leader, grandchild) = read_pids(&pidfile);

    wait_until_disconnected(&transport).await;
    assert!(
        pid_is_alive(grandchild),
        "precondition: the grandchild still runs"
    );

    transport.close().await.expect("close");

    assert!(
        wait_until_gone(grandchild, std::time::Duration::from_secs(5)).await,
        "grandchild pid {grandchild} outlived its own leader and close() did not reach it"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn is_connected_leaves_an_exited_leader_unreaped() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = self_exiting_leader_backend(workspace.path());
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (leader, _grandchild) = read_pids(&pidfile);

    wait_until_disconnected(&transport).await;

    assert!(
        leader_exited(pid(leader)),
        "is_connected() reaped leader {leader}, so its group id can be reused before teardown"
    );
    transport.close().await.expect("close");
}

#[cfg(unix)]
#[tokio::test]
async fn a_clean_close_does_not_wait_out_the_grace() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, _pidfile) = tree_backend(workspace.path(), false);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");

    let began = std::time::Instant::now();
    transport.close().await.expect("close");

    assert!(
        began.elapsed() < GROUP_TERM_GRACE / 2,
        "close() of a SIGTERM-respecting backend took {:?}",
        began.elapsed()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn drop_after_a_cancelled_close_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (command, pidfile) = tree_backend(workspace.path(), true);
    let transport = start_tree_transport(workspace.path(), &command);
    transport.start().await.expect("start");
    let (_leader, descendant) = read_pids(&pidfile);

    let cancelled =
        tokio::time::timeout(std::time::Duration::from_millis(200), transport.close()).await;
    assert!(
        cancelled.is_err(),
        "precondition: close() was cancelled in its grace"
    );
    drop(transport);

    assert!(
        wait_until_gone(descendant, std::time::Duration::from_secs(5)).await,
        "descendant pid {descendant} survived a drop after close() was cancelled"
    );
}
