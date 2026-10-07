// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782: stdio frames are bounded, and a stdio child's whole process tree
//! ends with it.

use tokio::io::BufReader;

use super::{DEFAULT_MAX_FRAME_BYTES as MAX_FRAME_BYTES, read_frame};

async fn frames(input: &[u8]) -> Vec<std::io::Result<Option<String>>> {
    frames_within(input, MAX_FRAME_BYTES).await
}

async fn frames_within(input: &[u8], max: usize) -> Vec<std::io::Result<Option<String>>> {
    let mut reader = BufReader::new(input);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    loop {
        let next = read_frame(&mut reader, &mut buf, max).await;
        let stop = !matches!(next, Ok(Some(_)));
        out.push(next);
        if stop {
            return out;
        }
    }
}

#[tokio::test]
async fn frames_split_on_newline_and_drop_the_terminator() {
    let got = frames(b"{\"a\":1}\n{\"b\":2}\r\nlast").await;
    let lines: Vec<_> = got
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned().flatten())
        .collect();
    assert_eq!(lines, ["{\"a\":1}", "{\"b\":2}", "last"]);
    assert!(matches!(got.last(), Some(Ok(None))), "ends at EOF");
}

#[tokio::test]
async fn a_frame_over_the_limit_is_an_error_not_a_growing_buffer() {
    let mut input = vec![b'x'; MAX_FRAME_BYTES + 10];
    input.push(b'\n');
    let got = frames(&input).await;
    assert!(got[0].is_err(), "oversized frame must fail");
}

#[tokio::test]
async fn a_frame_exactly_at_the_limit_is_accepted() {
    let mut input = vec![b'x'; MAX_FRAME_BYTES];
    input.push(b'\n');
    let got = frames(&input).await;
    assert_eq!(
        got[0].as_ref().unwrap().as_ref().map(String::len),
        Some(MAX_FRAME_BYTES)
    );
}

#[tokio::test]
async fn a_frame_that_is_not_utf8_is_an_error() {
    let got = frames(b"\xff\xfe\n").await;
    assert!(got[0].is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn a_child_that_fails_to_start_takes_its_grandchild_with_it() {
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("grandchild.pid");
    // Not an MCP server: it starts a grandchild, records its pid, closes
    // stdout by exec'ing a sleeper, so initialize fails and start tears down.
    let command = format!(
        "sh -c 'sleep 120 & echo $! > {}; exec sleep 120 >/dev/null'",
        pidfile.display()
    );
    let transport = super::StdioTransport::new(
        &command,
        HashMap::new(),
        None,
        std::time::Duration::from_secs(3),
        None,
    );
    assert!(transport.start().await.is_err(), "not an MCP server");
    let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_owned();
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
    assert!(!alive, "grandchild {pid} outlived its backend");
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_a_live_transport_takes_its_descendants_with_it() {
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("descendant.pid");
    let transport = super::StdioTransport::new(
        "true",
        HashMap::new(),
        None,
        std::time::Duration::from_secs(3),
        None,
    );
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c")
        .arg(format!("sleep 120 & echo $! > {}; wait", pidfile.display()));
    *transport.child.lock().await = Some(super::spawn_in_own_tree(cmd).unwrap());
    let mut pid = String::new();
    for _ in 0..50 {
        pid = std::fs::read_to_string(&pidfile)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !pid.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!pid.is_empty(), "the descendant never started");
    drop(transport);
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
    assert!(!alive, "descendant {pid} outlived a dropped transport");
}

#[tokio::test]
async fn a_configured_larger_limit_accepts_what_the_default_refuses() {
    let mut input = vec![b'x'; MAX_FRAME_BYTES + 1024];
    input.push(b'\n');
    assert!(frames(&input).await[0].is_err(), "the default refuses it");
    let got = frames_within(&input, MAX_FRAME_BYTES + 2048).await;
    assert_eq!(
        got[0].as_ref().unwrap().as_ref().map(String::len),
        Some(MAX_FRAME_BYTES + 1024),
        "a configured larger limit is honoured"
    );
}

#[tokio::test]
async fn a_configured_smaller_limit_refuses_a_frame_the_default_accepts() {
    let mut input = vec![b'x'; 70_000];
    input.push(b'\n');
    assert!(frames(&input).await[0].is_ok());
    assert!(frames_within(&input, 65_536).await[0].is_err());
}

/// Stopping a backend ends its whole process group, not just the leader.
///
/// A launcher backend (`npx`, `npm exec`, a wrapper script) is a tree: the
/// direct child is the launcher and the server is a descendant. These rows pin
/// that `close()` reaches the descendants, including when the leader is already
/// gone and reaped. Cases contributed with #3419.
#[cfg(unix)]
mod tree_kill {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::StdioTransport;
    use crate::transport::Transport as _;

    /// The backend's answer to `initialize` (request id 1), quoted for `printf`.
    const INITIALIZE_REPLY: &str =
        r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;

    /// A backend that answers `initialize` and starts a descendant, recording the
    /// leader's pid and then the descendant's. With `exit_after_handshake` the
    /// leader exits on its own once `notifications/initialized` arrives, while
    /// the descendant keeps stdout open, so the transport never sees EOF.
    fn tree_backend(workspace: &Path, exit_after_handshake: bool) -> (String, PathBuf) {
        let server = workspace.join("tree-server.sh");
        let pidfile = workspace.join("pids");
        let pids = pidfile.display().to_string();
        let mut script = String::new();
        script.push_str(&format!("echo $$ > \"{pids}\"\n"));
        script.push_str("sh -c 'sleep 1000' &\n");
        script.push_str(&format!("echo $! >> \"{pids}\"\n"));
        script.push_str("while IFS= read -r request; do\ncase \"$request\" in\n");
        script.push_str("    *'\"method\":\"initialize\"'*)\n");
        script.push_str(&format!(
            "        printf '%s\\n' {INITIALIZE_REPLY}\n        ;;\n"
        ));
        if exit_after_handshake {
            script.push_str("    *'notifications/initialized'*)\n        exit 0\n        ;;\n");
        }
        script.push_str("esac\ndone\n");
        std::fs::write(&server, script).expect("write tree backend");
        ("sh tree-server.sh".to_string(), pidfile)
    }

    fn start_tree_transport(workspace: &Path, command: &str) -> Arc<StdioTransport> {
        StdioTransport::new(
            command,
            HashMap::new(),
            Some(workspace.to_string_lossy().into_owned()),
            Duration::from_secs(5),
            None,
        )
    }

    /// The `ps` state letter of `pid`, or `None` once it no longer exists.
    fn pid_state(pid: u32) -> Option<char> {
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .trim_start()
            .chars()
            .next()
    }

    /// Running: present and not a zombie. A descendant reparented to a PID 1
    /// that never reaps stays a zombie, which is dead for these rows.
    fn pid_is_alive(pid: u32) -> bool {
        pid_state(pid).is_some_and(|state| state != 'Z')
    }

    /// Wait for a pid to disappear, then report whether it did.
    async fn wait_until_gone(pid: u32, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if !pid_is_alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        !pid_is_alive(pid)
    }

    fn read_pids(pidfile: &Path) -> (u32, u32) {
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

    /// Poll the liveness check until it sees the leader has exited; whether it
    /// did within 5 s.
    async fn await_leader_exit(transport: &StdioTransport) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if !transport.is_connected() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// Whether `pid` is an exited process nobody has reaped yet.
    fn is_zombie(pid: u32) -> bool {
        pid_state(pid) == Some('Z')
    }

    /// Wait until `pid` is gone entirely, reaped and not a zombie.
    async fn wait_until_reaped(pid: u32) -> bool {
        for _ in 0..100 {
            if pid_state(pid).is_none() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

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
            wait_until_gone(descendant, Duration::from_secs(5)).await,
            "descendant pid {descendant} survived close(): the group was not signalled"
        );
        assert!(
            wait_until_gone(leader, Duration::from_secs(5)).await,
            "leader pid {leader} survived close()"
        );
    }

    #[tokio::test]
    async fn close_after_the_leader_exited_still_kills_the_group() {
        let workspace = tempfile::tempdir().expect("workspace");
        let (command, pidfile) = tree_backend(workspace.path(), false);
        let transport = start_tree_transport(workspace.path(), &command);
        transport.start().await.expect("start");
        let (leader, descendant) = read_pids(&pidfile);

        // End the leader behind the transport's back while the descendant runs.
        std::process::Command::new("kill")
            .args(["-9", &leader.to_string()])
            .status()
            .expect("kill leader");
        assert!(
            await_leader_exit(&transport).await,
            "precondition: the liveness check saw the leader exit"
        );
        assert!(
            pid_is_alive(descendant),
            "precondition: the descendant outlives its leader"
        );

        transport
            .close()
            .await
            .expect("close on an exited leader must not error");

        assert!(
            wait_until_gone(descendant, Duration::from_secs(5)).await,
            "descendant pid {descendant} survived a close() that found the leader already exited"
        );
    }

    #[tokio::test]
    async fn close_kills_a_descendant_that_outlived_a_self_exiting_leader() {
        let workspace = tempfile::tempdir().expect("workspace");
        let (command, pidfile) = tree_backend(workspace.path(), true);
        let transport = start_tree_transport(workspace.path(), &command);
        transport.start().await.expect("start");
        let (_leader, descendant) = read_pids(&pidfile);

        assert!(
            await_leader_exit(&transport).await,
            "precondition: the leader exited on its own"
        );
        assert!(
            pid_is_alive(descendant),
            "precondition: the descendant is still running with stdout open"
        );

        transport.close().await.expect("close");

        assert!(
            wait_until_gone(descendant, Duration::from_secs(5)).await,
            "descendant pid {descendant} outlived its own leader and close() did not reach it"
        );
    }

    /// MIK-8080: the liveness check sees the leader exit WITHOUT reaping it, so
    /// the zombie keeps the group id reserved; only `close()` kills the group
    /// and reaps the leader.
    #[tokio::test]
    async fn the_liveness_check_leaves_an_exited_leader_unreaped_until_close() {
        let workspace = tempfile::tempdir().expect("workspace");
        let (command, pidfile) = tree_backend(workspace.path(), false);
        let transport = start_tree_transport(workspace.path(), &command);
        transport.start().await.expect("start");
        let (leader, descendant) = read_pids(&pidfile);
        std::process::Command::new("kill")
            .args(["-9", &leader.to_string()])
            .status()
            .expect("kill leader");
        assert!(
            await_leader_exit(&transport).await,
            "precondition: the liveness check saw the leader exit"
        );
        assert!(
            is_zombie(leader),
            "the liveness check reaped leader {leader}, freeing its group id while {descendant} \
             may still run under it"
        );

        transport.close().await.expect("close");

        assert!(
            wait_until_gone(descendant, Duration::from_secs(5)).await,
            "descendant pid {descendant} survived close()"
        );
        assert!(
            wait_until_reaped(leader).await,
            "close() did not reap leader {leader}"
        );
    }

    /// MIK-8080: `close()` gives up the child it reaped, so nothing (a second
    /// `close()`, `Drop`, a read error) can signal that group id again.
    #[tokio::test]
    async fn close_gives_up_the_reaped_child() {
        let workspace = tempfile::tempdir().expect("workspace");
        let (command, _pidfile) = tree_backend(workspace.path(), false);
        let transport = start_tree_transport(workspace.path(), &command);
        transport.start().await.expect("start");
        transport.close().await.expect("close");
        assert!(
            transport.child.lock().await.is_none(),
            "close() kept the reaped child, whose group id can be reused"
        );
    }

    /// MIK-8080: a transport dropped without `close()` while its leader is an
    /// unreaped zombie still ends the descendants: the zombie keeps the group id.
    #[tokio::test]
    async fn dropping_a_transport_with_an_exited_leader_ends_the_descendants() {
        let workspace = tempfile::tempdir().expect("workspace");
        let (command, pidfile) = tree_backend(workspace.path(), false);
        let transport = start_tree_transport(workspace.path(), &command);
        transport.start().await.expect("start");
        let (leader, descendant) = read_pids(&pidfile);
        std::process::Command::new("kill")
            .args(["-9", &leader.to_string()])
            .status()
            .expect("kill leader");
        assert!(
            await_leader_exit(&transport).await,
            "precondition: the liveness check saw the leader exit"
        );

        drop(transport);

        assert!(
            wait_until_gone(descendant, Duration::from_secs(5)).await,
            "descendant pid {descendant} outlived a dropped transport whose leader had exited"
        );
    }
}
