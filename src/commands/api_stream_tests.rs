// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the api command's streamed path: bounded event streams, raw
//! downloads, line-wise masking and the waits that bound them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;
use mcp_gateway::cli::api::{ApiArgs, ApiMethod};
use mcp_gateway::cli::dashboard_link::DashboardLinkTls;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};

use super::super::super::dashboard_link::{
    AdminCallError, AdminFailureKind, AdminStream, LinkTls, TOKEN_ENV,
};
use super::*;

const TOKEN: &str = "stream-unit-credential-7f3a";
const BASE: &str = "http://127.0.0.1:9";
const STREAM: &str = "/ui/api/stream";
const EXPORT: &str = "/ui/api/activity/export";

fn args(path: &str, limit: Option<u32>, json: bool) -> ApiArgs {
    ApiArgs {
        method: ApiMethod::Get,
        path: path.to_owned(),
        data: None,
        if_match: None,
        limit,
        json,
        gateway: mcp_gateway::cli::dashboard_link::GatewayArg::default(),
        tls: DashboardLinkTls::default(),
    }
}

fn credential(name: &str) -> Option<String> {
    (name == TOKEN_ENV).then(|| TOKEN.to_owned())
}

/// A sink the row reads back; the printing thread owns one clone.
#[derive(Clone, Default)]
struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("sink").clone()
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// The one named test limit for every row that checks what a run prints and how it exits rather than a wait: 10 s
/// per wait and 30 s overall. That leaves wide room for the stalls a loaded runner causes (the starved-printer row
/// below holds its printer for 2 s and still passes), yet a real hang still fails in seconds. A longer stall can
/// still pass these limits; they are finite on purpose. Rows that end at a wait use the short limits in
/// `api_stream_wait_tests.rs`.
fn content() -> Deadlines {
    let (wait, total) = (Duration::from_secs(10), Duration::from_secs(30));
    Deadlines {
        headers: wait,
        stall: wait,
        event: wait,
        stream_total: total,
        download_total: total,
        fallback_total: total,
    }
}

/// A scripted answer; `open` keeps the body pending after its chunks, as a
/// live stream does.
fn answer(status: u16, content_type: &str, chunks: Vec<Vec<u8>>, open: bool) -> AdminStream {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("content type"),
    );
    let items = futures::stream::iter(chunks.into_iter().map(|c| Ok(bytes::Bytes::from(c))));
    let body = if open {
        items.chain(futures::stream::pending()).boxed()
    } else {
        items.boxed()
    };
    AdminStream {
        status: StatusCode::from_u16(status).expect("status"),
        headers,
        body,
    }
}

/// The streamed path with a scripted answer (`None`: it must not be sent):
/// what it printed, its outcome, and how many requests it sent.
async fn run(request: &ApiArgs, reply: Option<AdminStream>) -> (Vec<u8>, CliOutcome, usize) {
    run_as(request, reply, TOKEN).await
}

/// [`run`] with `token` as the credential.
async fn run_as(
    request: &ApiArgs,
    reply: Option<AdminStream>,
    token: &str,
) -> (Vec<u8>, CliOutcome, usize) {
    run_within(request, reply, token, &content()).await
}

/// [`run_as`] under the given waits; a row that ends at a wait passes the short ones.
async fn run_within(
    request: &ApiArgs,
    reply: Option<AdminStream>,
    token: &str,
    deadlines: &Deadlines,
) -> (Vec<u8>, CliOutcome, usize) {
    let sends = AtomicUsize::new(0);
    let out = Shared::default();
    let outcome = run_streamed_with(
        request,
        BASE,
        &LinkTls::default(),
        |name: &str| (name == TOKEN_ENV).then(|| token.to_owned()),
        out.clone(),
        deadlines,
        |_| {
            sends.fetch_add(1, Ordering::SeqCst);
            async move {
                reply.ok_or(AdminCallError {
                    kind: AdminFailureKind::Connect,
                    detail: "this row must send nothing".to_owned(),
                    status: None,
                    request_id: None,
                })
            }
        },
    )
    .await;
    (out.bytes(), outcome, sends.load(Ordering::SeqCst))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `body` cut into two chunks at `at`.
fn split(body: &str, at: usize) -> Vec<Vec<u8>> {
    let (a, b) = body.as_bytes().split_at(at);
    vec![a.to_vec(), b.to_vec()]
}

/// R4: the stream needs --limit, --limit belongs to the stream, and a
/// credential with a control character is refused; nothing is sent.
#[tokio::test]
async fn stream_flags_and_credentials_are_checked_before_sending() {
    let elsewhere = args("/ui/api/status", Some(1), false);
    for request in [
        args(STREAM, None, true),
        args("/ui/api/stream?x=1", None, false),
        elsewhere,
    ] {
        let (out, outcome, sends) = run(&request, None).await;
        assert_eq!(
            (outcome.exit(), sends, out.len()),
            (CliExit::Usage, 0, 0),
            "{}",
            request.path
        );
    }
    // The streamed sender carries no body or If-Match: refused, not dropped.
    let mut with_data = args(STREAM, Some(1), false);
    with_data.data = Some("{}".to_owned());
    let mut with_if_match = args(EXPORT, None, false);
    with_if_match.if_match = Some("\"v1\"".to_owned());
    for (request, named) in [
        (with_data, "--data does not apply to /ui/api/stream."),
        (
            with_if_match,
            "--if-match does not apply to /ui/api/activity/export.",
        ),
    ] {
        let (out, outcome, sends) = run(&request, None).await;
        assert_eq!(
            (outcome.exit(), sends, out.len()),
            (CliExit::Usage, 0, 0),
            "{}",
            request.path
        );
        assert!(outcome.stderr().contains(named), "{}", outcome.stderr());
    }
    for bad in ["two\nlines", "tab\there"] {
        let refused = super::super::resolve_token(Ok(bad.to_owned()), BASE);
        assert!(
            refused.is_err(),
            "{bad:?}: a control character is refused before sending"
        );
    }
}

/// R7: the event-stream rules the command relies on.
#[test]
fn events_follow_the_event_stream_rules() {
    let mut parser = Events::default();
    let mut all = Vec::new();
    for chunk in [
        "\u{feff}: hello\r",
        "\nid: 7\r\ndata: a\ndata: b\n",
        "\nevent: tick\r",
        "data\rid: x\0y\n\n",
        "id: 9\n\ndata: {\"n\":1}\n\n",
    ] {
        all.extend(parser.push(chunk.as_bytes()).expect("under the limit"));
    }
    let event = |name: &str, id: Option<&str>, data: &str| Event {
        name: name.to_owned(),
        id: id.map(str::to_owned),
        data: data.to_owned(),
    };
    assert_eq!(
        all,
        vec![
            event("message", Some("7"), "a\nb"),
            event("tick", Some("7"), ""),
            event("message", Some("9"), "{\"n\":1}"),
        ],
        "BOM and comment dropped, CRLF split across chunks, multiline data, field without colon, NUL id ignored, id-only block dispatching nothing, persistent id"
    );
}

/// R6: the credential cut at every offset across two chunks comes out masked,
/// and the rest is exactly the gateway's bytes. The oracle redacts the whole
/// body at once, so it does not share the line-wise path it checks; the body
/// holds a CSV field with an LF inside quotes and the marker's own text, and
/// few enough matches that the redactor never collapses a dense run.
#[tokio::test]
async fn a_download_masks_the_credential_at_every_cut() {
    let body = format!(
        "{{\"k\":\"{TOKEN}\"}}\n\"quoted\nfield {TOKEN}\",[redacted]\nplain,line\nend {TOKEN}"
    );
    let expected = redact::text(&body, &[TOKEN.to_owned()]);
    assert!(
        !expected.contains(TOKEN),
        "premise: the oracle masks the credential"
    );
    for at in 1..body.len() {
        let reply = answer(200, "application/x-ndjson", split(&body, at), false);
        let (out, outcome, _) = run(&args(EXPORT, None, false), Some(reply)).await;
        assert_eq!(outcome.exit(), CliExit::Ok, "cut at {at}");
        assert_eq!(text(&out), expected, "cut at {at}");
    }
}

/// Load: a printing thread the scheduler leaves idle for 2 s, as on a starved test machine, must not fail a row about
/// content. The sink stalls its first write; the run still prints every line and exits Ok under the waits every row
/// in this file uses.
#[tokio::test]
async fn a_starved_printer_does_not_fail_a_content_row() {
    struct Starved {
        out: Shared,
        stalled: bool,
    }
    impl Write for Starved {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.stalled {
                self.stalled = true;
                std::thread::sleep(ms(2000));
            }
            self.out.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let out = Shared::default();
    let reply = answer(
        200,
        "application/x-ndjson",
        vec![b"one\ntwo\n".to_vec()],
        false,
    );
    let request = args(EXPORT, None, false);
    let outcome = run_streamed_with(
        &request,
        BASE,
        &LinkTls::default(),
        credential,
        Starved {
            out: out.clone(),
            stalled: false,
        },
        &content(),
        |_| async { Ok(reply) },
    )
    .await;
    assert_eq!(outcome.exit(), CliExit::Ok, "{}", outcome.stderr());
    assert_eq!(text(&out.bytes()), "one\ntwo\n");
}

/// R6: in an event's data, id and name, in both output modes.
#[tokio::test]
async fn an_event_masks_the_credential_in_every_field() {
    let body = format!("event: e{TOKEN}\nid: i{TOKEN}\ndata: d{TOKEN}\n\n");
    for json in [false, true] {
        for at in [3, 12, body.len() / 2, body.len() - 3] {
            let reply = answer(200, "text/event-stream", split(&body, at), true);
            let (out, outcome, _) = run(&args(STREAM, Some(1), json), Some(reply)).await;
            assert_eq!(outcome.exit(), CliExit::Ok, "json {json}, cut {at}");
            assert!(
                !text(&out).contains(TOKEN),
                "json {json}, cut {at}: {}",
                text(&out)
            );
            assert!(
                text(&out).contains("event") && !out.is_empty(),
                "json {json}: the event printed"
            );
        }
    }
}

/// R6: a non-UTF-8 line is passed through unless it holds the credential.
#[tokio::test]
async fn a_non_utf8_line_passes_only_without_the_credential() {
    let clean = vec![b"ok\n".to_vec(), vec![0xff, b'a', b'\n']];
    let (out, outcome, _) = run(
        &args(EXPORT, None, false),
        Some(answer(200, "text/csv", clean, false)),
    )
    .await;
    assert_eq!(
        (outcome.exit(), out),
        (CliExit::Ok, b"ok\n\xffa\n".to_vec())
    );
    let mut dirty = vec![0xff];
    dirty.extend_from_slice(TOKEN.as_bytes());
    dirty.push(b'\n');
    let (out, outcome, _) = run(
        &args(EXPORT, None, false),
        Some(answer(
            200,
            "text/csv",
            vec![b"ok\n".to_vec(), dirty],
            false,
        )),
    )
    .await;
    assert_eq!(outcome.exit(), CliExit::LocalFailure);
    assert_eq!(
        out,
        b"ok\n".to_vec(),
        "nothing of the unsafe line is printed"
    );
}

/// R10: on a streamed route, JSON, a refusal, and a non-2xx answer of a
/// streamed type take the buffered path; a charset or upper case still streams.
#[tokio::test]
async fn non_stream_answers_take_the_buffered_path() {
    let (out, outcome, _) = run(
        &args(EXPORT, None, false),
        Some(answer(
            200,
            "application/json",
            vec![br#"{"ok":true}"#.to_vec()],
            false,
        )),
    )
    .await;
    assert_eq!(outcome.exit(), CliExit::Ok);
    assert!(
        out.is_empty() && text(outcome.stdout()).contains("\"ok\": true"),
        "rendered by the buffered path"
    );
    for (status, kind) in [
        (403, "application/json"),
        (500, "text/csv"),
        (503, "text/event-stream"),
    ] {
        let body = br#"{"error":{"code":"refused","message":"no"}}"#.to_vec();
        let (out, outcome, _) = run(
            &args(EXPORT, None, false),
            Some(answer(status, kind, vec![body], false)),
        )
        .await;
        assert!(
            out.is_empty() && outcome.exit() != CliExit::Ok,
            "{status} {kind}: not streamed, not success"
        );
    }
    for kind in ["text/csv; charset=utf-8", "TEXT/CSV"] {
        let (out, outcome, _) = run(
            &args(EXPORT, None, false),
            Some(answer(200, kind, vec![b"a,b\n".to_vec()], false)),
        )
        .await;
        assert_eq!(
            (outcome.exit(), out),
            (CliExit::Ok, b"a,b\n".to_vec()),
            "{kind} streams"
        );
    }
}

/// R11: --limit 1 with two events in one chunk prints the first whole and
/// nothing of the second, then closes.
#[tokio::test]
async fn the_limit_prints_whole_events_only() {
    let chunk = b"data: first\n\ndata: second\n\n".to_vec();
    let (out, outcome, _) = run(
        &args(STREAM, Some(1), false),
        Some(answer(200, "text/event-stream", vec![chunk], true)),
    )
    .await;
    assert_eq!(outcome.exit(), CliExit::Ok);
    assert_eq!(text(&out), "event: message\ndata: first\n\n");
}

/// R13: a line over 16 MiB with the credential near its end is an error, and
/// nothing of it is printed; the lines before it are intact.
#[tokio::test]
async fn an_over_long_line_is_refused_unprinted() {
    let mut long = vec![b'x'; PENDING_LIMIT + 1 - TOKEN.len()];
    long.extend_from_slice(TOKEN.as_bytes());
    let reply = answer(
        200,
        "application/x-ndjson",
        vec![b"first\n".to_vec(), long],
        false,
    );
    let (out, outcome, _) = run(&args(EXPORT, None, false), Some(reply)).await;
    assert_eq!(outcome.exit(), CliExit::LocalFailure);
    assert_eq!(
        out,
        b"first\n".to_vec(),
        "no unscanned prefix of the long line"
    );
    let mut event = b"data: ".to_vec();
    event.extend(vec![b'y'; PENDING_LIMIT + 1]);
    let (out, outcome, _) = run(
        &args(STREAM, Some(1), false),
        Some(answer(200, "text/event-stream", vec![event], true)),
    )
    .await;
    assert_eq!((outcome.exit(), out.len()), (CliExit::LocalFailure, 0));
}

/// R9: a transport loss after output is the network exit with the output so
/// far intact and the pending line dropped; the stream ending early is too.
#[tokio::test]
async fn a_failure_after_output_keeps_what_was_printed() {
    let mut reply = answer(
        200,
        "text/csv",
        vec![b"one\n".to_vec(), format!("pending {TOKEN}").into_bytes()],
        false,
    );
    let lost = futures::stream::once(async {
        Err(AdminCallError {
            kind: AdminFailureKind::ResponseLost,
            detail: "connection reset".to_owned(),
            status: None,
            request_id: None,
        })
    });
    reply.body = reply.body.chain(lost).boxed();
    let (out, outcome, _) = run(&args(EXPORT, None, false), Some(reply)).await;
    assert_eq!(
        (outcome.exit(), text(&out)),
        (CliExit::Network, "one\n".to_owned())
    );
    assert!(!outcome.stderr().contains(TOKEN));
    let ended = answer(
        200,
        "text/event-stream",
        vec![b"data: a\n\n".to_vec()],
        false,
    );
    let (out, outcome, _) = run(&args(STREAM, Some(2), false), Some(ended)).await;
    assert_eq!(outcome.exit(), CliExit::Network);
    assert!(outcome.stderr().contains("1 of 2"), "{}", outcome.stderr());
    assert_eq!(text(&out), "event: message\ndata: a\n\n");
}

/// R9: a write error is the local-failure exit; a broken pipe is success.
#[tokio::test]
async fn write_failures_follow_the_buffered_rules() {
    struct Failing(std::io::ErrorKind);
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for (kind, exit) in [
        (std::io::ErrorKind::BrokenPipe, CliExit::Ok),
        (std::io::ErrorKind::Other, CliExit::LocalFailure),
    ] {
        let reply = answer(200, "text/csv", vec![b"a\n".to_vec()], false);
        let request = args(EXPORT, None, false);
        let outcome = run_streamed_with(
            &request,
            BASE,
            &LinkTls::default(),
            credential,
            Failing(kind),
            &content(),
            |_| async { Ok(reply) },
        )
        .await;
        assert_eq!(outcome.exit(), exit, "{kind:?}");
    }
}

/// Final review: what the redactor leaves is checked. A token found in every
/// marker ("d") makes it fail closed to empty output, and a token equal to
/// JSON syntax (":") survives the value redaction of a --json event; each stops
/// the run with the local-failure exit and prints nothing, rather than print
/// emptied lines or the token as a success. A token that would re-form at a
/// marker's edge ("d]z" against "Xd]zz") is masked with the next marker, and
/// the run succeeds.
#[tokio::test]
async fn tokens_the_redactor_cannot_mask_stop_the_run() {
    let export = |body: &str| answer(200, "text/csv", vec![body.as_bytes().to_vec()], false);
    let event = |data: &str| {
        answer(
            200,
            "text/event-stream",
            vec![format!("data: {data}\n\n").into_bytes()],
            true,
        )
    };
    for (request, reply, token) in [
        // The token must be present: with no match the line passes unchanged.
        (args(EXPORT, None, false), export("ad\n"), "d"),
        (args(STREAM, Some(1), false), event("ad"), "d"),
        (args(STREAM, Some(1), true), event("1"), ":"),
    ] {
        let (out, outcome, _) = run_as(&request, Some(reply), token).await;
        assert_eq!(
            (outcome.exit(), out.len()),
            (CliExit::LocalFailure, 0),
            "{} {token:?}: {}",
            request.path,
            outcome.stderr()
        );
    }
    for (request, reply) in [
        (args(EXPORT, None, false), export("Xd]zz\n")),
        (args(STREAM, Some(1), false), event("Xd]zz")),
    ] {
        let (out, outcome, _) = run_as(&request, Some(reply), "d]z").await;
        assert_eq!(outcome.exit(), CliExit::Ok, "{}", outcome.stderr());
        let printed = text(&out);
        assert!(
            !printed.contains("d]z") && printed.contains("X<removed>z"),
            "{printed:?}"
        );
    }
}

/// R13 (final review): a line over 16 MiB that arrives whole in one chunk,
/// LF included, is refused like one still pending; nothing of the chunk is
/// printed, the line before it included.
#[tokio::test]
async fn an_over_long_line_in_one_chunk_is_refused() {
    let mut chunk = b"first\n".to_vec();
    chunk.extend(vec![b'x'; PENDING_LIMIT + 1]);
    chunk.push(b'\n');
    let reply = answer(200, "application/x-ndjson", vec![chunk], false);
    let (out, outcome, _) = run(&args(EXPORT, None, false), Some(reply)).await;
    assert_eq!((outcome.exit(), out.len()), (CliExit::LocalFailure, 0));
}

/// The shared refusal on the stream's JSON events (its third caller, beside
/// `admin_call` and the buffered path): an event whose redaction would merge two
/// keys is refused, not printed short.
#[tokio::test]
async fn a_json_event_that_loses_an_entry_to_redaction_is_refused() {
    // `[redacted]` is the shared redactor's first marker: renaming the key
    // `#` to it collides with the existing key.
    let reply = answer(
        200,
        "text/event-stream",
        vec![
            br##"data: {"#":"first","[redacted]":"second"}"##.to_vec(),
            b"\n\n".to_vec(),
        ],
        true,
    );
    let (out, outcome, _) = run_as(&args(STREAM, Some(1), true), Some(reply), "#").await;
    assert_eq!(
        (outcome.exit(), out.len()),
        (CliExit::LocalFailure, 0),
        "{}",
        outcome.stderr()
    );
}

#[path = "api_stream_wait_tests.rs"]
mod waits;
