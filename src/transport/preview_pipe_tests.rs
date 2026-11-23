// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows R5, R6a, R6b, R7, R12, R12b and R12s: the preview pipe's
//! failure kinds, its two size limits, the fixed refusal of a server's own
//! requests, and the shared opening exchange run over it.
//!
//! The fake server is a `sh` loop (Unix only, as in the negotiation rows):
//! it appends every line it reads to `record`, byte for byte, and after its
//! Nth line sources `step.N` when the row wrote one. Each row breaks one
//! thing.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use super::{PipeFailure, PreviewPipe};
use crate::Error;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;
use crate::transport::handshake::preview_handshake;

const LOOP: &str = r#"n=0
while IFS= read -r line; do
    printf '%s\n' "$line" >> record
    n=$((n+1))
    if [ -f "step.$n" ]; then . "./step.$n"; fi
done
"#;

/// A running fake server and the pipe over its standard streams. The child
/// is declared first and its drop waits (below), so the server has exited
/// before its folder is removed.
struct Server {
    child: std::process::Child,
    pipe: PreviewPipe,
    folder: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// The lines the server read, in order.
    fn record(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("record"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.folder.path().join(name)
    }
}

/// Starts the loop with `steps` (line number, shell text) and `files` (name,
/// bytes) written beside it first.
fn serve(steps: &[(usize, &str)], files: &[(&str, Vec<u8>)]) -> Server {
    let folder = tempfile::tempdir().expect("server folder");
    std::fs::write(folder.path().join("server.sh"), LOOP).expect("write the loop");
    for (n, text) in steps {
        std::fs::write(folder.path().join(format!("step.{n}")), text).expect("write a step");
    }
    for (name, bytes) in files {
        std::fs::write(folder.path().join(name), bytes).expect("write a file");
    }
    let mut child = std::process::Command::new("sh")
        .arg("server.sh")
        .current_dir(folder.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start sh");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let pipe = PreviewPipe::new(
        tokio::process::ChildStdin::from_std(stdin).expect("async stdin"),
        tokio::process::ChildStdout::from_std(stdout).expect("async stdout"),
    );
    Server {
        child,
        pipe,
        folder,
    }
}

/// One newline-ended answer to `id` whose line is exactly `len` bytes.
fn answer_of_len(id: i64, len: usize) -> Vec<u8> {
    let head = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"pad":""#);
    let tail = r#""}}"#;
    let pad = len - head.len() - tail.len();
    let mut line = head.into_bytes();
    line.resize(line.len() + pad, b'a');
    line.extend_from_slice(tail.as_bytes());
    assert_eq!(line.len(), len, "fixture line length");
    line.push(b'\n');
    line
}

fn line(text: &str) -> Vec<u8> {
    format!("{text}\n").into_bytes()
}

/// The pipe stopped with `kind`: kept, shown with its fixed text, and the
/// error the call returned carries that same text.
fn stopped_with(server: &Server, outcome: crate::Result<()>, kind: PipeFailure, text: &str) {
    let error = outcome.expect_err("the call must fail");
    assert_eq!(server.pipe.failure(), Some(kind), "kept failure");
    assert_eq!(kind.to_string(), text, "fixed text of {kind:?}");
    assert!(
        matches!(&error, Error::Transport(said) if said == text),
        "the call's error is the kind's text, got {error:?}"
    );
    assert!(
        !server.pipe.is_connected(),
        "a failed pipe is not connected"
    );
}

async fn ask(server: &Server, method: &str) -> crate::Result<JsonRpcResponse> {
    server.pipe.request(method, None).await
}

#[tokio::test]
async fn r5_a_server_that_exits_before_answering_ends_the_output() {
    let server = serve(&[(1, "exit 0")], &[]);
    let outcome = ask(&server, "initialize").await.map(drop);
    stopped_with(
        &server,
        outcome,
        PipeFailure::OutputEnded,
        "the server's output ended before it answered",
    );
}

#[tokio::test]
async fn r5_a_server_that_closes_its_output_while_alive_ends_the_output() {
    let server = serve(&[(1, "exec 1>&-; exec sleep 30")], &[]);
    let outcome = ask(&server, "initialize").await.map(drop);
    stopped_with(
        &server,
        outcome,
        PipeFailure::OutputEnded,
        "the server's output ended before it answered",
    );
}

#[tokio::test]
async fn r5_a_notification_to_a_server_that_closed_its_input_fails() {
    let server = serve(
        &[(1, "exec 0<&-; cat out.1; exec sleep 30")],
        &[("out.1", line(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))],
    );
    ask(&server, "initialize")
        .await
        .expect("the answer was written before the input closed");
    let outcome = server.pipe.notify("notifications/initialized", None).await;
    stopped_with(
        &server,
        outcome,
        PipeFailure::InputClosed,
        "the server stopped reading its input",
    );
}

#[tokio::test]
async fn r5_frames_that_are_not_json_rpc_end_the_pipe() {
    let cases: [(&str, Vec<u8>); 5] = [
        ("not JSON", line("this is not json")),
        ("not UTF-8", vec![0xff, 0xfe, b'\n']),
        (
            "an error that is a string",
            line(r#"{"jsonrpc":"2.0","id":1,"error":"boom"}"#),
        ),
        (
            "a request whose method is null",
            line(r#"{"jsonrpc":"2.0","id":"r1","method":null}"#),
        ),
        (
            "a notification whose method is a number",
            line(r#"{"jsonrpc":"2.0","method":7}"#),
        ),
    ];
    for (case, bytes) in cases {
        // The server exits right after the frame (its loop would otherwise
        // wait for more input), so a pipe that read past the frame reports
        // the end of output instead of waiting.
        let server = serve(&[(1, "cat out.1; exit 0")], &[("out.1", bytes)]);
        let outcome = ask(&server, "initialize").await.map(drop);
        assert_eq!(
            server.pipe.failure(),
            Some(PipeFailure::NotJsonRpc),
            "{case}"
        );
        stopped_with(
            &server,
            outcome,
            PipeFailure::NotJsonRpc,
            "the server sent a frame that is not JSON-RPC",
        );
    }
}

#[tokio::test]
async fn r5_a_server_request_after_its_input_closed_fails_the_refusal_write() {
    let server = serve(
        &[(1, "exec 0<&-; cat out.1; exec sleep 30")],
        &[(
            "out.1",
            line(r#"{"jsonrpc":"2.0","id":"r1","method":"roots/list"}"#),
        )],
    );
    let outcome = ask(&server, "initialize").await.map(drop);
    stopped_with(
        &server,
        outcome,
        PipeFailure::InputClosed,
        "the server stopped reading its input",
    );
}

#[tokio::test]
async fn r5_an_answer_to_an_id_never_sent_is_dropped() {
    let mut out = line(r#"{"jsonrpc":"2.0","id":999,"result":{"which":"stray"}}"#);
    out.extend(line(
        r#"{"jsonrpc":"2.0","id":1,"result":{"which":"ours"}}"#,
    ));
    let server = serve(&[(1, "cat out.1; exec sleep 30")], &[("out.1", out)]);
    let answer = ask(&server, "initialize").await.expect("our answer");
    assert_eq!(answer.id, Some(RequestId::Number(1)));
    assert_eq!(answer.result, Some(json!({"which": "ours"})));
    assert_eq!(server.pipe.failure(), None);
    let record = server.record();
    assert_eq!(record.len(), 1, "one request went out: {record:?}");
}

#[tokio::test]
async fn r6a_a_frame_of_exactly_four_mib_is_read_and_one_byte_more_is_not() {
    let server = serve(
        &[(1, "cat out.1; exec sleep 30")],
        &[("out.1", answer_of_len(1, 4_194_304))],
    );
    let answer = ask(&server, "initialize")
        .await
        .expect("a frame at the cap");
    assert_eq!(answer.id, Some(RequestId::Number(1)));

    let server = serve(
        &[(1, "cat out.1; exec sleep 30")],
        &[("out.1", answer_of_len(1, 4_194_305))],
    );
    let outcome = ask(&server, "initialize").await.map(drop);
    stopped_with(
        &server,
        outcome,
        PipeFailure::FrameOverCap,
        "a frame over the preview's 4 MiB limit",
    );
}

#[tokio::test]
async fn r6b_eight_mib_across_four_answers_is_read_and_one_byte_more_is_not() {
    // 2 MiB for the opening answer and three pages of 2 MiB: 8 MiB in all.
    for extra in [0, 1] {
        let steps: Vec<(usize, String)> = (1..=4).map(|n| (n, format!("cat out.{n}"))).collect();
        let steps: Vec<(usize, &str)> = steps.iter().map(|(n, s)| (*n, s.as_str())).collect();
        let files: Vec<(String, Vec<u8>)> = (1..=4_i64)
            .map(|n| {
                let len = if n == 4 { 2_097_152 + extra } else { 2_097_152 };
                (format!("out.{n}"), answer_of_len(n, len))
            })
            .collect();
        let files: Vec<(&str, Vec<u8>)> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect();
        let server = serve(&steps, &files);
        ask(&server, "initialize")
            .await
            .expect("the opening answer");
        for page in 1..=2 {
            ask(&server, "tools/list")
                .await
                .unwrap_or_else(|e| panic!("page {page}: {e}"));
        }
        let last = ask(&server, "tools/list").await;
        if extra == 0 {
            let last = last.expect("the last page ends exactly at 8 MiB");
            assert_eq!(last.id, Some(RequestId::Number(4)));
        } else {
            stopped_with(
                &server,
                last.map(drop),
                PipeFailure::OverBudget,
                "more than the preview's 8 MiB in total",
            );
        }
    }
}

/// The literal the pipe must send back to a server request with this id.
fn refusal_for(id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"the preview does not serve client methods"}}}}"#
    )
}

fn parsed(line: &str) -> Value {
    serde_json::from_str(line).unwrap_or_else(|e| panic!("record line {line}: {e}"))
}

#[tokio::test]
async fn r7_server_requests_get_the_fixed_refusal_and_nothing_of_theirs_is_kept() {
    let mut out = line(r#"{"jsonrpc":"2.0","id":"s1","method":"roots/list"}"#);
    out.extend(line(
        r#"{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{"note":"CANARY-7"}}"#,
    ));
    out.extend(line(
        r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"CANARY-7"}}"#,
    ));
    out.extend(line(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#,
    ));
    let listing = line(r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}"#);
    let server = serve(
        &[(1, "cat out.1"), (5, "cat out.5")],
        &[("out.1", out), ("out.5", listing)],
    );

    let agreed = preview_handshake(&server.pipe, None)
        .await
        .expect("the opening exchange");
    let listed = ask(&server, "tools/list").await.expect("the listing");
    assert_eq!(listed.result, Some(json!({"tools": [{"name": "echo"}]})));

    let record = server.record();
    assert_eq!(record.len(), 5, "{record:#?}");
    assert_eq!(parsed(&record[0])["method"], "initialize");
    assert_eq!(parsed(&record[0])["id"], 1);
    assert_eq!(
        record[1],
        refusal_for(r#""s1""#),
        "the string id stays a string"
    );
    assert_eq!(record[2], refusal_for("7"), "the number id stays a number");
    assert_eq!(parsed(&record[3])["method"], "notifications/initialized");
    assert_eq!(parsed(&record[3]).get("id"), None);
    assert_eq!(parsed(&record[4])["method"], "tools/list");
    assert_eq!(parsed(&record[4])["id"], 2);
    assert_eq!(server.pipe.client_requests_refused(), 2);

    let returned = format!("{agreed} {}", serde_json::to_string(&listed).expect("json"));
    assert!(!returned.contains("CANARY-7"), "{returned}");
}

/// The answer a fake server gives an `initialize` with this id, selecting
/// `selects`.
fn selects(id: i64, revision: &str) -> Vec<u8> {
    line(&format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"{revision}","capabilities":{{}}}}}}"#
    ))
}

#[tokio::test]
async fn r12_a_rejected_first_proposal_is_retried_with_a_revision_both_speak() {
    let rejection = line(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Unsupported protocol version. Supported versions: 2025-06-18"}}"#,
    );
    let server = serve(
        &[(1, "cat out.1"), (2, "cat out.2")],
        &[("out.1", rejection), ("out.2", selects(2, "2025-06-18"))],
    );
    let agreed = preview_handshake(&server.pipe, None)
        .await
        .expect("the retry is accepted");
    assert_eq!(agreed, "2025-06-18");
    let record = server.record();
    assert_eq!(record.len(), 3, "{record:#?}");
    assert_eq!(
        parsed(&record[0])["params"]["protocolVersion"],
        "2025-11-25"
    );
    assert_eq!(
        parsed(&record[1])["params"]["protocolVersion"],
        "2025-06-18"
    );
    assert_eq!(parsed(&record[2])["method"], "notifications/initialized");
}

#[tokio::test]
async fn r12b_the_first_proposal_is_the_configured_revision_else_the_latest() {
    for (configured, expected) in [(Some("2025-06-18"), "2025-06-18"), (None, "2025-11-25")] {
        let server = serve(&[(1, "cat out.1")], &[("out.1", selects(1, expected))]);
        let agreed = preview_handshake(&server.pipe, configured)
            .await
            .expect("the opening exchange");
        assert_eq!(agreed, expected);
        let first = parsed(&server.record()[0]);
        assert_eq!(
            first["params"]["protocolVersion"], expected,
            "configured {configured:?}"
        );
    }
}

/// An in-process server that answers at once and notes when each call
/// arrived, so the settle wait can be read on paused time.
#[derive(Default)]
struct Clocked {
    calls: parking_lot::Mutex<Vec<(String, tokio::time::Instant)>>,
}

impl Clocked {
    fn at(&self, method: &str) -> tokio::time::Instant {
        let calls = self.calls.lock();
        let Some((_, at)) = calls.iter().find(|(seen, _)| seen == method) else {
            panic!("no {method} call");
        };
        *at
    }
}

#[async_trait::async_trait]
impl Transport for Clocked {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.calls
            .lock()
            .push((method.to_owned(), tokio::time::Instant::now()));
        let id = RequestId::Number(i64::try_from(self.calls.lock().len()).expect("small"));
        Ok(JsonRpcResponse::success(
            id,
            json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
        ))
    }

    async fn notify(&self, method: &str, _params: Option<Value>) -> crate::Result<()> {
        self.calls
            .lock()
            .push((method.to_owned(), tokio::time::Instant::now()));
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn r12s_the_first_call_after_the_exchange_waits_250_ms_after_the_notification() {
    let server = Clocked::default();
    preview_handshake(&server, None)
        .await
        .expect("the opening exchange");
    server
        .request("tools/list", None)
        .await
        .expect("the listing");
    let waited = server.at("tools/list") - server.at("notifications/initialized");
    // limit-under-test (paused-clock): the settle wait itself, pinned exactly on tokio's paused clock
    assert_eq!(waited, Duration::from_millis(250));
}
