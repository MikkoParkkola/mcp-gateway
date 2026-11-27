// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio answer over `max_frame_bytes` fails only its own call as too large
//! (S1-S4); the waiter maps it on either exit and from its own start only
//! (W1, W2, R1). Unix-only: the fake backend is a `sh` script.

use super::*;
use std::collections::HashMap;
use std::time::Duration;

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
        REQUEST_TIMEOUT,
        None,
    );
    transport.set_max_frame_bytes(LIMIT);
    transport.start().await.expect("handshake");
    transport.set_request_timeout(request_timeout);
    assert_eq!(transport.request_timeout(), request_timeout);
    (workspace, transport)
}

use crate::error::Error;

const LIMIT: usize = 1024;
/// Far longer than a row takes: a row that waits it out has regressed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const ROW_LIMIT: Duration = Duration::from_secs(20);

/// A backend under `LIMIT`; in `after`, `$BIG` is 2000 bytes of text and
/// `id_of LINE` the line's numeric id.
async fn backend(after: &str) -> (tempfile::TempDir, Arc<StdioTransport>) {
    let after = format!("BIG=$(head -c 2000 /dev/zero | tr '\\0' x)\n{after}");
    started_with_timeout(&after, REQUEST_TIMEOUT).await
}

type Outcome = Result<crate::protocol::JsonRpcResponse>;

async fn call(transport: &Arc<StdioTransport>, name: &str) -> Outcome {
    let params = serde_json::json!({"name": name, "arguments": {}});
    tokio::time::timeout(ROW_LIMIT, transport.request("tools/call", Some(params)))
        .await
        .expect("the call ends without waiting out its timeout")
}

fn too_large(outcome: &Outcome) -> bool {
    matches!(outcome, Err(Error::ResponseTooLarge { limit: LIMIT }))
}

/// One call answered with `answer` (a printf format: the call's id, then
/// `$BIG`), then the backend idles.
async fn one_call_answered(answer: &str) -> (Outcome, Arc<StdioTransport>) {
    let after = format!(
        "read -r big\nprintf '{answer}\\n' \"$(id_of \"$big\")\" \"$BIG\"\ncat > /dev/null"
    );
    let (_workspace, transport) = backend(&after).await;
    (call(&transport, "big").await, transport)
}

/// S1 (SIZE.1): an answer over the limit, leading with its id, fails its call
/// as too large, and the transport reads as disconnected (the next call
/// restarts the backend). Kills: no mapping; a mapping that never fires.
#[tokio::test]
async fn s1_an_answer_over_the_limit_fails_its_call_as_too_large() {
    let (outcome, transport) =
        one_call_answered(r#"{"jsonrpc":"2.0","id":%s,"result":{"text":"%s"}}"#).await;
    assert!(too_large(&outcome), "{outcome:?}");
    assert!(
        !transport.is_connected(),
        "the stream ended with the cut frame"
    );
}

/// S2: two calls in flight; the over-limit answer is the `big` one's. Only it
/// is too large; the other keeps its retryable error. Kills: blame every
/// waiting call.
#[tokio::test]
async fn s2_the_other_call_in_flight_keeps_its_retryable_error() {
    let after = r#"read -r one
read -r two
case "$one" in *'"big"'*) big=$one;; *) big=$two;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"text":"%s"}}\n' "$(id_of "$big")" "$BIG"
cat > /dev/null"#;
    let (_workspace, transport) = backend(after).await;
    let (big, small) = tokio::join!(call(&transport, "big"), call(&transport, "small"));
    assert!(too_large(&big), "{big:?}");
    assert!(small.is_err() && !too_large(&small), "{small:?}");
}

/// S3: frames with no positive evidence name nobody: a well-formed peer
/// request reusing the waiting call's id, a notification, and an answer whose
/// id comes after its result. Kills: id alone; any id anywhere.
#[tokio::test]
async fn s3_a_frame_without_positive_evidence_blames_nobody() {
    for answer in [
        r#"{"jsonrpc":"2.0","id":%s,"method":"sampling/createMessage","params":{"x":"%s"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"n":%s,"data":"%s"}}"#,
        r#"{"jsonrpc":"2.0","result":{"n":%s,"text":"%s"},"id":0}"#,
    ] {
        let (outcome, _transport) = one_call_answered(answer).await;
        assert!(
            outcome.is_err() && !too_large(&outcome),
            "{answer}: {outcome:?}"
        );
    }
}

/// S4 (SIZE.2): a backend that exits mid-call reports its own error, not too
/// large. Kills: a mapping on any closed channel.
#[tokio::test]
async fn s4_a_backend_that_exits_mid_call_is_not_too_large() {
    let (_workspace, transport) = backend("read -r request\nexit 0").await;
    let outcome = call(&transport, "small").await;
    assert!(outcome.is_err() && !too_large(&outcome), "{outcome:?}");
}

/// A call left waiting on a backend that never answers, and its pending key.
async fn waiting_call(
    transport: &Arc<StdioTransport>,
) -> (tokio::task::JoinHandle<Outcome>, String) {
    let caller = Arc::clone(transport);
    let task = tokio::spawn(async move { call(&caller, "big").await });
    let key = tokio::time::timeout(ROW_LIMIT, async {
        loop {
            if let Some(entry) = transport.pending.iter().next() {
                break entry.key().clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the call registers");
    (task, key)
}

/// W1: the call's reply channel drops while the stdout latch is still unset;
/// its own start's record makes it too large. Kills: a mapping on the eof
/// arm only.
#[tokio::test]
async fn w1_a_dropped_reply_reads_the_record() {
    let (_workspace, transport) = backend("cat > /dev/null").await;
    let (task, key) = waiting_call(&transport).await;
    *transport.start.oversize_slot().lock() = Some((key, LIMIT));
    transport.pending.clear();
    let outcome = task.await.expect("the call task");
    assert!(too_large(&outcome), "{outcome:?}");
}

/// W2: the stdout latch trips first; the call reads the record on that exit
/// too. Kills: a mapping on the dropped channel only.
#[tokio::test]
async fn w2_a_tripped_latch_reads_the_record() {
    let (_workspace, transport) = backend("cat > /dev/null").await;
    let (task, key) = waiting_call(&transport).await;
    *transport.start.oversize_slot().lock() = Some((key, LIMIT));
    transport.start.trip_eof();
    let outcome = task.await.expect("the call task");
    assert!(too_large(&outcome), "{outcome:?}");
}

/// R1: a replacement start's fresh record neither erases nor fakes the one
/// the call registered on. Kills: reading the transport's current record.
#[tokio::test]
async fn r1_a_replacement_start_keeps_the_calls_own_record() {
    let (_workspace, transport) = backend("cat > /dev/null").await;
    let (task, key) = waiting_call(&transport).await;
    *transport.start.oversize_slot().lock() = Some((key, LIMIT));
    let fresh = Arc::new(tokio::sync::watch::channel(false).0);
    transport.start.begin(fresh);
    assert!(
        transport.start.oversize_slot().lock().is_none(),
        "a fresh record"
    );
    transport.pending.clear();
    let outcome = task.await.expect("the call task");
    assert!(too_large(&outcome), "{outcome:?}");
}
