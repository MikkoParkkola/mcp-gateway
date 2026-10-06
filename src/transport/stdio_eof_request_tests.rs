// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7871: a request made after, or during, the child's stdout closing fails
//! at once instead of waiting out the request timeout.
//!
//! Unix-only: the fake backend is a `sh` script. The child keeps running with
//! stdout closed, which is the stall: a dead child fails the write (EPIPE)
//! with or without the fix, so it proves nothing.

use super::*;
use std::collections::HashMap;
use std::time::Duration;

/// Far longer than any row may take: a row that waits it out has regressed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ROW_LIMIT: Duration = Duration::from_secs(5);

/// Answers `initialize`, reads `notifications/initialized`, then runs `after`.
async fn started(after: &str) -> (tempfile::TempDir, Arc<StdioTransport>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
read -r request
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"PROTO","capabilities":{}}}\n' "$(id_of "$request")"
read -r initialized
AFTER
"#
    .replace("PROTO", PROTOCOL_VERSION)
    .replace("AFTER", after);
    std::fs::write(workspace.path().join("server.sh"), script).expect("write server");
    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        REQUEST_TIMEOUT,
        None,
    );
    transport.start().await.expect("handshake");
    (workspace, transport)
}

async fn stdout_closed(transport: &StdioTransport) {
    // The reader drops `connected` after it trips the EOF latch and clears
    // the pending map, and nothing else does while the child lives.
    tokio::time::timeout(ROW_LIMIT, async {
        while transport.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the child closes stdout");
}

async fn fails_fast(transport: &StdioTransport, params: Option<Value>) -> Error {
    tokio::time::timeout(ROW_LIMIT, transport.request("tools/list", params))
        .await
        .expect("must fail at once, not wait out the request timeout")
        .expect_err("nothing can answer after stdout closed")
}

/// STDIO.1: stdout already closed, stdin still read. The write succeeds, and
/// without the fix the entry lands after `pending.clear()` and waits 30 s.
#[tokio::test]
async fn a_request_after_stdout_closed_fails_at_once() {
    let (_w, t) = started("exec 1>&-\nwhile IFS= read -r l; do :; done").await;
    stdout_closed(&t).await;
    let err = fails_fast(&t, None).await;
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    let _ = t.close().await;
}

/// STDIO.2: stdout closes while the write is blocked on a full stdin pipe the
/// child never reads. The call ends at EOF, not at a write that never returns.
#[tokio::test]
async fn eof_during_a_blocked_write_ends_the_call() {
    let (_w, t) = started("sleep 1\nexec 1>&-\nsleep 60").await;
    let began = std::time::Instant::now();
    let err = fails_fast(&t, big_params()).await;
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    // EOF came a second after the handshake; a call that ended sooner went
    // through the already-closed check, not the in-flight race.
    assert!(
        began.elapsed() >= Duration::from_millis(500),
        "ended before EOF: {:?}",
        began.elapsed()
    );
    let _ = t.close().await;
}

/// Larger than any pipe buffer, so its write cannot complete on a child that
/// does not read stdin.
fn big_params() -> Option<Value> {
    Some(serde_json::json!({ "pad": "x".repeat(1 << 20) }))
}

/// A write cut off mid-frame retires stdin: the next write fails instead of
/// appending to half a frame.
#[tokio::test]
async fn a_cancelled_write_retires_stdin() {
    let (_w, t) = started("sleep 60").await;
    let cut = tokio::time::timeout(
        Duration::from_millis(300),
        t.request("tools/list", big_params()),
    )
    .await;
    assert!(cut.is_err(), "the write cannot complete: {cut:?}");
    let err = tokio::time::timeout(ROW_LIMIT, t.notify("notifications/progress", None))
        .await
        .expect("a retired stdin fails at once, not behind a full pipe")
        .expect_err("half a frame is on stdin");
    assert!(err.to_string().contains("Not connected"), "{err}");
    assert!(!t.is_connected());
    let _ = t.close().await;
}

/// A reply read before EOF still wins: a child that answered and then closed
/// stdout has answered.
#[tokio::test]
async fn a_reply_followed_by_eof_is_still_the_answer() {
    let (_w, t) = started(
        r#"read -r request
printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}\n' "$(id_of "$request")"
exec 1>&-
while IFS= read -r l; do :; done"#,
    )
    .await;
    let response = tokio::time::timeout(ROW_LIMIT, t.request("tools/list", None))
        .await
        .expect("answered")
        .expect("a reply read before EOF is the answer");
    assert!(response.result.is_some(), "{response:?}");
    let _ = t.close().await;
}
