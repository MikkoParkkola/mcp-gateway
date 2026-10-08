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
    started_with_timeout(after, REQUEST_TIMEOUT).await
}

async fn started_with_timeout(
    after: &str,
    request_timeout: Duration,
) -> (tempfile::TempDir, Arc<StdioTransport>) {
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
        request_timeout,
        None,
    );
    transport.start().await.expect("handshake");
    (workspace, transport)
}

async fn stdout_closed(transport: &StdioTransport) {
    // The latch itself: `connected` is set after the handshake, so it can
    // read true again after a child that closes stdout at once.
    let mut eof = transport.start.eof_receiver().expect("a started transport");
    tokio::time::timeout(ROW_LIMIT, eof.wait_for(|closed| *closed))
        .await
        .expect("the child closes stdout")
        .expect("latch alive");
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
    assert!(
        matches!(&err, Error::TransportConnect(message) if message.contains("stdout closed")),
        "{err:?}"
    );
    // Nothing was sent, so a keyed retry of the same call may still run.
    assert!(err.is_pre_dispatch(), "{err:?}");
    let _ = t.close().await;
}

/// STDIO.1, the precheck's own effect: a request made after stdout closed
/// fails before its frame is written, so the child never receives it.
#[tokio::test]
async fn a_request_after_stdout_closed_writes_nothing() {
    let (w, t) = started("exec 1>&-\ncat > seen").await;
    stdout_closed(&t).await;
    fails_fast(&t, None).await;
    // A pipe keeps order: once this marker is recorded, any frame the request
    // wrote before it is recorded too.
    t.notify("notifications/marker", None)
        .await
        .expect("stdin is still open");
    let seen = w.path().join("seen");
    let recorded = tokio::time::timeout(ROW_LIMIT, async {
        loop {
            let text = std::fs::read_to_string(&seen).unwrap_or_default();
            if text.contains("notifications/marker") {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the child records its stdin");
    assert!(!recorded.contains("tools/list"), "{recorded}");
    let _ = t.close().await;
}

/// STDIO.2: stdout closes while the write is blocked on a full stdin pipe the
/// child never reads. The call ends at EOF, not at a write that never returns.
#[tokio::test]
async fn eof_during_a_blocked_write_ends_the_call() {
    // The child closes stdout only once the request's first byte arrives, so
    // the EOF lands while the write is in flight, never before the call.
    let (_w, t) = started("head -c 1 >/dev/null\nexec 1>&-\nsleep 60").await;
    let err = fails_fast(&t, Some(big_params())).await;
    assert!(
        matches!(&err, Error::Transport(message) if message.contains("stdout closed")),
        "{err:?}"
    );
    // Part of the frame left, so the outcome is not known: no free retry.
    assert!(!err.is_pre_dispatch(), "{err:?}");
    // The frame keeps going out whole (#3453); close() cancels it, bounded.
    tokio::time::timeout(ROW_LIMIT, t.close())
        .await
        .expect("close ends the stuck whole-frame write")
        .expect("close");
}

/// Larger than any pipe buffer, so its write cannot complete on a child that
/// does not read stdin.
fn big_params() -> Value {
    serde_json::json!({ "pad": "x".repeat(1 << 20) })
}

/// Whole-frame contract (#3453): a request cancelled while its frame waits on
/// a full pipe still delivers that frame whole, and the next message follows
/// it intact instead of being torn into it.
#[tokio::test]
async fn a_cancelled_request_still_writes_its_whole_frame() {
    let (w, t) = started("sleep 1\ncat > seen").await;
    let cut = tokio::time::timeout(
        Duration::from_millis(300),
        t.request("tools/list", Some(big_params())),
    )
    .await;
    assert!(cut.is_err(), "the child is not reading yet: {cut:?}");
    t.notify("notifications/marker", None)
        .await
        .expect("the next write queues behind the whole frame");
    let seen = w.path().join("seen");
    let recorded = tokio::time::timeout(ROW_LIMIT, async {
        loop {
            let text = std::fs::read_to_string(&seen).unwrap_or_default();
            if text.contains("notifications/marker") {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the child records both frames");
    let frames: Vec<&str> = recorded.lines().collect();
    assert_eq!(frames.len(), 2, "two whole frames, nothing torn");
    for frame in frames {
        serde_json::from_str::<Value>(frame).expect("each line is one whole frame");
    }
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

/// A child that keeps stdout open but never reads stdin: the request's own
/// deadline covers the write, so the call ends at `request_timeout`.
#[tokio::test]
async fn a_write_the_child_never_reads_ends_at_the_request_timeout() {
    let (_w, t) = started_with_timeout("sleep 60", Duration::from_millis(500)).await;
    let err = tokio::time::timeout(ROW_LIMIT, t.request("tools/list", Some(big_params())))
        .await
        .expect("the request timeout bounds the write")
        .expect_err("nothing reads the request");
    assert!(matches!(err, Error::BackendTimeout(_)), "{err:?}");
    // The frame keeps going out whole (#3453); close() cancels it, bounded.
    tokio::time::timeout(ROW_LIMIT, t.close())
        .await
        .expect("close ends the stuck whole-frame write")
        .expect("close");
}

/// agy review on #3531: the latch trips even when the reader task panics, so
/// a handshake racing it fails fast instead of waiting out its timeout.
#[test]
fn the_latch_trips_when_the_reader_panics() {
    let tx = Arc::new(tokio::sync::watch::channel(false).0);
    let rx = tx.subscribe();
    let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _latch = super::early_exit::TripOnDrop(Arc::clone(&tx));
        panic!("the reader task died");
    }));
    assert!(ended.is_err());
    assert!(*rx.borrow(), "the latch tripped on the way out");
}

/// gpt review on #3531: a call that ends with no reply is pre-send only when
/// no byte of it could have left, so a keyed retry is freed exactly then.
#[test]
fn an_unanswered_call_is_pre_send_only_before_its_first_byte() {
    use std::sync::atomic::AtomicBool;
    let unsent =
        super::write::unsent_or(&AtomicBool::new(false), "stdout closed", Error::Transport);
    assert!(unsent.is_pre_dispatch(), "{unsent:?}");
    let sent = super::write::unsent_or(&AtomicBool::new(true), "stdout closed", Error::Transport);
    assert!(!sent.is_pre_dispatch(), "{sent:?}");
    assert!(matches!(sent, Error::Transport(_)), "{sent:?}");
}

/// gpt review on #3531: a request queued behind a blocked write never sends a
/// byte (the first call's whole frame keeps stdin until `close`), so it ends
/// at its own deadline as pre-send and a keyed retry may run.
#[tokio::test]
async fn a_request_queued_behind_a_blocked_write_ends_pre_send() {
    let (_w, t) = started_with_timeout("sleep 60", Duration::from_millis(500)).await;
    let blocked = {
        let t = Arc::clone(&t);
        tokio::spawn(async move { t.request("tools/list", Some(big_params())).await })
    };
    // The first call holds stdin (its frame cannot finish) before the second
    // queues; observed, not assumed from a sleep.
    tokio::time::timeout(ROW_LIMIT, async {
        while t.writer.try_lock().is_ok() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the blocked call takes stdin");
    let queued = tokio::time::timeout(ROW_LIMIT, t.request("tools/list", None))
        .await
        .expect("the queued call ends within its deadline")
        .expect_err("nothing reads either request");
    assert!(queued.is_pre_dispatch(), "{queued:?}");
    let first = blocked
        .await
        .expect("task")
        .expect_err("the blocked call fails");
    assert!(!first.is_pre_dispatch(), "{first:?}");
    let _ = t.close().await;
}
