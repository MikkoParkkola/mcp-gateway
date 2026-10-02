// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782: stdio frames are bounded, and a stdio child's whole process tree
//! ends with it.

use tokio::io::BufReader;

use super::{MAX_FRAME_BYTES, read_frame};

async fn frames(input: &[u8]) -> Vec<std::io::Result<Option<String>>> {
    let mut reader = BufReader::new(input);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    loop {
        let next = read_frame(&mut reader, &mut buf).await;
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
