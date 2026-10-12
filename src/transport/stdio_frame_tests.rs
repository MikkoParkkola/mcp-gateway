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
    transport.child.lock().tree = Some(super::ChildTree::new(
        super::spawn_in_own_tree(cmd).unwrap(),
    ));
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

/// MIK-8079: a request dropped mid-write must not leave a partial frame on the
/// shared stdin. The backend stops reading after the handshake so a large
/// frame blocks on the full pipe, the caller gives up, and a later message is
/// written; once the backend reads again, every line it got must be whole JSON.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_request_leaves_no_partial_frame_for_the_next_caller() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frames.log");
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) while [ ! -e release ]; do sleep 0.05; done; break ;;\n\
         esac\ndone\n\
         while IFS= read -r line; do printf '%s\\n' \"$line\" >> \"{log}\"; done\n",
        log = log.display()
    );
    std::fs::write(dir.path().join("reader.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh reader.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );
    transport.start().await.expect("start");

    // Far over a pipe buffer, so the write blocks until the backend is
    // released: it reads nothing more until the test creates `release`, so
    // both give-up windows below expire however loaded the runner is
    // (MIK-8266: this used to race a 2 s sleep in the backend).
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    // timing: precondition
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        transport.request("tools/call", Some(big)),
    )
    .await;
    assert!(
        dropped.is_err(),
        "precondition: the large request was still writing"
    );

    // A caller queued behind the stuck write and then cancelled sends nothing.
    // timing: precondition
    let queued = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        transport.request("resources/list", None),
    )
    .await;
    assert!(queued.is_err(), "precondition: the queued request gave up");
    std::fs::write(dir.path().join("release"), "").unwrap();

    transport
        .notify("notifications/roots/list_changed", None)
        .await
        .expect("a later message is written");

    // Bounded polling for the two frames the backend should log.
    let mut frames = String::new();
    for _ in 0..100 {
        frames = std::fs::read_to_string(&log).unwrap_or_default();
        if frames.contains("notifications/roots/list_changed") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let torn: Vec<String> = frames
        .lines()
        .filter(|line| serde_json::from_str::<serde_json::Value>(line).is_err())
        .map(|line| line.chars().take(80).collect())
        .collect();
    assert!(
        torn.is_empty(),
        "the backend received {} torn frame(s), e.g. {:?}",
        torn.len(),
        torn.first()
    );
    // The admitted large frame is finished first, whole, and its dropped caller
    // cancels it by its id (`MIK-7642.PR.B`); the queued request never reaches
    // the peer, so it has no cancel; the later message follows.
    let parsed: Vec<serde_json::Value> = frames
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let methods: Vec<&str> = parsed
        .iter()
        .map(|frame| frame["method"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        methods,
        [
            "tools/call",
            "notifications/cancelled",
            "notifications/roots/list_changed"
        ],
        "{} bytes logged",
        frames.len()
    );
    assert_eq!(
        parsed[1]["params"]["requestId"], parsed[0]["id"],
        "the cancel names the dropped call"
    );
}

/// MIK-8079: `close()` is not held up by a write stuck on a peer that stopped
/// reading; ending the tree breaks that write.
#[cfg(unix)]
#[tokio::test]
async fn close_returns_while_a_write_is_stuck_on_a_peer_that_stopped_reading() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) exec sleep 1000 ;;\n\
         esac\ndone\n"
    );
    std::fs::write(dir.path().join("deaf.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh deaf.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("start");
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    let stuck = {
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move { transport.request("tools/call", Some(big)).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!stuck.is_finished(), "precondition: the write is stuck");
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), transport.close()).await;
    assert!(closed.is_ok(), "close() waited behind a stuck write");
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), stuck).await;
    assert!(
        matches!(ended, Ok(Ok(Err(_)))),
        "the stuck request did not end in an error after close(): {ended:?}"
    );
}

/// Kills the process whose pid the file holds, if any, when dropped.
#[cfg(unix)]
struct KillEscapedOnDrop(std::path::PathBuf);

#[cfg(unix)]
impl Drop for KillEscapedOnDrop {
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(&self.0).unwrap_or_default();
        if !pid.trim().is_empty() {
            let _ = std::process::Command::new("kill")
                .args(["-9", pid.trim()])
                .status();
        }
    }
}

/// MIK-8079: `close()` returns even when a reader that escaped the process
/// group (a daemonized descendant still holding stdin) keeps a write stuck.
/// The pipe goes through fd 3: a background job's own stdin is `/dev/null`
/// in a non-interactive shell, so `<&0` would not hand it the pipe. The
/// reader leaves the group through perl's `setsid`, since macOS ships no
/// `setsid` command (MIK-8183).
#[cfg(unix)]
#[tokio::test]
async fn close_returns_when_an_escaped_reader_keeps_a_write_stuck() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("escaped.pid");
    // Kills the escaped reader however the row ends, so a failed precondition
    // cannot leave a `sleep 1000` behind on the host (MIK-8099.HYG.1).
    let _reaper = KillEscapedOnDrop(pidfile.clone());
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) exec 3<&0; perl -MPOSIX -e 'setsid; exec @ARGV' sleep 1000 <&3 3<&- >/dev/null 2>&1 & echo $! > \"{pid}\"; exec sleep 1000 ;;\n\
         esac\ndone\n",
        pid = pidfile.display()
    );
    std::fs::write(dir.path().join("escape.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh escape.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("start");
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    let stuck = {
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move { transport.request("tools/call", Some(big)).await })
    };
    // Wait until the escaped reader is running and has recorded its pid.
    let mut escaped = String::new();
    for _ in 0..100 {
        escaped = std::fs::read_to_string(&pidfile).unwrap_or_default();
        if !escaped.trim().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        !escaped.trim().is_empty(),
        "precondition: the escaped reader started"
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        transport.writer.try_lock().is_err(),
        "precondition: the write holds stdin"
    );
    let closed = tokio::time::timeout(std::time::Duration::from_secs(10), transport.close()).await;
    let escaped_alive = std::process::Command::new("kill")
        .args(["-0", escaped.trim()])
        .status()
        .is_ok_and(|s| s.success());
    // Judged while the escaped reader still holds the pipe: killing it would
    // end the write by itself.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), stuck).await;
    let released = transport.writer.try_lock().is_ok_and(|w| w.is_none());
    assert!(
        closed.is_ok(),
        "close() hung on a write an escaped reader keeps stuck"
    );
    assert!(
        matches!(ended, Ok(Ok(Err(_)))),
        "the stuck write outlived close(): {ended:?}"
    );
    assert!(released, "close() left stdin held by the stuck write");
    assert!(
        escaped_alive,
        "precondition: the reader escaped the killed group"
    );
}

/// MIK-8079 (codex P2): a transport dropped without `close()` while a write is
/// stuck on an escaped reader still ends that write and frees stdin.
#[cfg(unix)]
#[tokio::test]
async fn dropping_the_transport_ends_a_write_stuck_on_an_escaped_reader() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("escaped.pid");
    // Kills the escaped reader however the row ends, so a failed precondition
    // cannot leave a `sleep 1000` behind on the host (MIK-8099.HYG.1).
    let _reaper = KillEscapedOnDrop(pidfile.clone());
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) exec 3<&0; perl -MPOSIX -e 'setsid; exec @ARGV' sleep 1000 <&3 3<&- >/dev/null 2>&1 & echo $! > \"{pid}\"; exec sleep 1000 ;;\n\
         esac\ndone\n",
        pid = pidfile.display()
    );
    std::fs::write(dir.path().join("escape.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh escape.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("start");
    let writer = std::sync::Arc::clone(&transport.writer);
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    let stuck = {
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move { transport.request("tools/call", Some(big)).await })
    };
    for _ in 0..100 {
        if !std::fs::read_to_string(&pidfile)
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let held = writer.try_lock().is_err();
    stuck.abort();
    let _ = stuck.await;
    drop(transport);
    let mut freed = false;
    for _ in 0..50 {
        if writer.try_lock().is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(held, "precondition: the write holds stdin");
    assert!(
        freed,
        "a dropped transport left its stuck write holding stdin"
    );
}

/// MIK-7923 T1-stdin: a retire, with the transport still held and no close,
/// ends a write stuck on an escaped reader and frees stdin. The request fails
/// at the stdout-closed latch either way; the write itself holds stdin until
/// the per-start token is cancelled, which `kill_tree_now` does.
#[cfg(unix)]
#[tokio::test]
async fn a_retire_frees_a_write_stuck_on_an_escaped_reader() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("escaped.pid");
    let _reaper = KillEscapedOnDrop(pidfile.clone());
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) exec 3<&0; perl -MPOSIX -e 'setsid; exec @ARGV' sleep 1000 <&3 3<&- >/dev/null 2>&1 & echo $! > \"{pid}\"; exec sleep 1000 ;;\n\
         esac\ndone\n",
        pid = pidfile.display()
    );
    std::fs::write(dir.path().join("escape.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh escape.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("start");
    let writer = std::sync::Arc::clone(&transport.writer);
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    let stuck = {
        let transport = std::sync::Arc::clone(&transport);
        tokio::spawn(async move { transport.request("tools/call", Some(big)).await })
    };
    for _ in 0..100 {
        if !std::fs::read_to_string(&pidfile)
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let held = writer.try_lock().is_err();
    transport.kill_tree_now();
    let mut freed = false;
    for _ in 0..50 {
        if writer.try_lock().is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    stuck.abort();
    let _ = stuck.await;
    assert!(held, "precondition: the write holds stdin");
    assert!(freed, "a retire left a stuck write holding stdin");
    drop(transport);
}

/// `MIK-8099.ROW.1`: a write queued behind the stdin lock while the shutdown
/// token is renewed (what `close()` then `start()` do to it) takes the NEW
/// token: the token is read under the stdin lock, so the old token's cancel
/// does not end it. The write is polled to pending before the renewal, and
/// the frame (larger than a pipe) cannot finish until the row lets the peer
/// read, so a write holding the cancelled token would end first.
#[cfg(unix)]
#[tokio::test]
async fn a_write_queued_across_a_token_renewal_takes_the_new_token() {
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let go = dir.path().join("go");
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) break ;;\n\
         esac\ndone\n\
         while [ ! -f \"{go}\" ]; do sleep 0.05; done\n\
         cat >/dev/null\n",
        go = go.display()
    );
    std::fs::write(dir.path().join("late.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh late.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("start");
    let frame = serde_json::json!({
        "jsonrpc": "2.0", "method": "x", "params": { "blob": "a".repeat(256 * 1024) },
    })
    .to_string();
    let held = transport.writer.lock().await;
    let old = transport.shutdown.lock().clone();
    let mut write = Box::pin(transport.write_message(frame));
    let polled = tokio::time::timeout(std::time::Duration::from_millis(100), &mut write).await;
    assert!(polled.is_err(), "precondition: the write waits on stdin");
    old.cancel();
    *transport.shutdown.lock() = tokio_util::sync::CancellationToken::new();
    drop(held);
    let early = tokio::time::timeout(std::time::Duration::from_millis(300), &mut write).await;
    std::fs::write(&go, b"").unwrap();
    let written = match early {
        Ok(done) => Ok(done),
        Err(_) => tokio::time::timeout(std::time::Duration::from_secs(10), write).await,
    };
    assert!(
        matches!(written, Ok(Ok(()))),
        "the old token's cancel ended a write queued before the renewal: {written:?}"
    );
}

/// Whether the second launch logged (a restart's fresh child), if any, is
/// gone within 5 s; then every logged launch is killed, so none outlives
/// the row.
#[cfg(unix)]
fn second_launch_gone_then_kill_all(all: &[String]) -> bool {
    let alive = |pid: &str| {
        std::process::Command::new("kill")
            .args(["-0", pid])
            .status()
            .is_ok_and(|status| status.success())
    };
    let mut gone = false;
    for _ in 0..50 {
        if all.get(1).is_none_or(|pid| !alive(pid)) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    for pid in all {
        let _ = std::process::Command::new("kill")
            .args(["-9", pid])
            .status();
    }
    gone
}

/// MIK-7923 T1-install: a restart parked at the writer lock on an idle runtime
/// has spawned nothing, so a retire there misses no child. The server logs
/// each launch; while the runtime idles there is still only the first. Driven
/// again, the restart finds the transport retired and spawns nothing (a start
/// the retire overtakes after that check is refused at install instead).
#[cfg(unix)]
#[test]
fn a_restart_parked_on_the_writer_lock_spawns_nothing_a_retire_misses() {
    use crate::transport::Transport as _;
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("escaped.pid");
    let launch_log = dir.path().join("launches");
    let _reaper = KillEscapedOnDrop(pidfile.clone());
    let reply = r#"'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'"#;
    let script = format!(
        "echo $$ >> \"{launches}\"\n\
         while IFS= read -r line; do\n\
         case \"$line\" in\n\
         *'\"method\":\"initialize\"'*) printf '%s\\n' {reply} ;;\n\
         *'notifications/initialized'*) exec 3<&0; perl -MPOSIX -e 'setsid; exec @ARGV' sleep 1000 <&3 3<&- >/dev/null 2>&1 & echo $! > \"{pid}\"; exec sleep 1000 ;;\n\
         esac\ndone\n",
        pid = pidfile.display(),
        launches = launch_log.display()
    );
    std::fs::write(dir.path().join("escape.sh"), script).unwrap();
    let launched = || -> Vec<String> {
        std::fs::read_to_string(&launch_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let transport = super::StdioTransport::new(
        "sh escape.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    runtime.block_on(async {
        transport.start().await.expect("first start");
        // A write stuck on the escaped reader holds the writer lock.
        let big =
            serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
        let writing = std::sync::Arc::clone(&transport);
        tokio::spawn(async move { writing.request("tools/call", Some(big)).await });
        while transport.writer.try_lock().is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    });
    let restarting = std::sync::Arc::clone(&transport);
    let restart = runtime.spawn(async move { restarting.start().await });
    // Let the restart run up to the writer lock and park there.
    runtime.block_on(async { tokio::time::sleep(std::time::Duration::from_millis(300)).await });
    // The runtime idles from here until the restart is driven again.
    let first = launched();
    transport.kill_tree_now();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let while_idle = launched();
    let outcome = runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), restart).await
    });
    let all = launched();
    let fresh_gone = second_launch_gone_then_kill_all(&all);
    drop(runtime);
    assert_eq!(
        first.len(),
        1,
        "a restart parked at the writer lock had already spawned"
    );
    assert_eq!(
        while_idle.len(),
        1,
        "the parked restart spawned before taking the writer lock"
    );
    let refused = outcome
        .expect("the restart finished once driven")
        .expect("no panic");
    // Decided by the gateway, not by the child's own log line: a child the
    // install guard kills may never get to write that line (MIK-7923, m08).
    assert!(
        matches!(&refused, Err(crate::Error::BackendNotFound(m)) if m.contains("before it started")),
        "the retired restart was refused only at install, after spawning: {refused:?}"
    );
    assert_eq!(
        all.len(),
        1,
        "the retired restart spawned a child once driven"
    );
    assert!(fresh_gone, "the refused start's tree outlived the retire");
}

/// `MIK-7642.PR.B`: an `initialize` dropped before its answer is never
/// cancelled; the protocol forbids it.
#[cfg(unix)]
#[tokio::test]
async fn a_dropped_initialize_is_never_cancelled() {
    use std::collections::HashMap;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frames.log");
    let script = format!(
        "while IFS= read -r line; do printf '%s\\n' \"$line\" >> \"{}\"; done\n",
        log.display()
    );
    std::fs::write(dir.path().join("deaf.sh"), script).unwrap();
    let transport = super::StdioTransport::new(
        "sh deaf.sh",
        HashMap::new(),
        Some(dir.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30),
        None,
    );
    // Dropped once the child has logged the initialize, not after a fixed
    // window: a slow spawn on a loaded runner would otherwise drop it unsent.
    let mut start = Box::pin(transport.start());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("\"method\":\"initialize\"")
        {
            tokio::select! {
                started = &mut start => panic!("precondition: initialize was still waiting: {started:?}"),
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
        }
    })
    .await
    .expect("precondition: the child logged the initialize");
    drop(start);
    // Grace for a cancel frame to be written: load can only hide one here.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let frames = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!frames.contains("notifications/cancelled"), "{frames}");
}
