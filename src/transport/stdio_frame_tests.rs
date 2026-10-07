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
         *'notifications/initialized'*) sleep 2; break ;;\n\
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

    // Far over a pipe buffer, so the write blocks while the backend sleeps.
    let big = serde_json::json!({ "name": "x", "arguments": { "blob": "a".repeat(256 * 1024) } });
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        transport.request("tools/call", Some(big)),
    )
    .await;
    assert!(
        dropped.is_err(),
        "precondition: the large request was still writing"
    );

    transport
        .notify("notifications/roots/list_changed", None)
        .await
        .expect("a later message is written");

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let frames = std::fs::read_to_string(&log).unwrap_or_default();
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
    assert!(
        frames.contains("notifications/roots/list_changed"),
        "the later message arrived: {} bytes logged",
        frames.len()
    );
}
