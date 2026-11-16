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
        url: None,
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

/// Short waits, so a row about a wait finishes in well under a second.
fn short() -> Deadlines {
    Deadlines {
        headers: ms(400),
        stall: ms(400),
        event: ms(400),
        stream_total: ms(1500),
        download_total: ms(1500),
        fallback_total: ms(400),
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
async fn run(request: &ApiArgs, reply: Option<AdminStream>) -> (Vec<u8>, ApiOutcome, usize) {
    run_as(request, reply, TOKEN).await
}

/// [`run`] with `token` as the credential.
async fn run_as(
    request: &ApiArgs,
    reply: Option<AdminStream>,
    token: &str,
) -> (Vec<u8>, ApiOutcome, usize) {
    let sends = AtomicUsize::new(0);
    let out = Shared::default();
    let outcome = run_streamed_with(
        request,
        BASE,
        &LinkTls::default(),
        |name: &str| (name == TOKEN_ENV).then(|| token.to_owned()),
        out.clone(),
        &short(),
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
            (outcome.exit, sends, out.len()),
            (ApiExit::Usage, 0, 0),
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
            (outcome.exit, sends, out.len()),
            (ApiExit::Usage, 0, 0),
            "{}",
            request.path
        );
        assert!(outcome.stderr.contains(named), "{}", outcome.stderr);
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
        assert_eq!(outcome.exit, ApiExit::Ok, "cut at {at}");
        assert_eq!(text(&out), expected, "cut at {at}");
    }
}

/// R6: in an event's data, id and name, in both output modes.
#[tokio::test]
async fn an_event_masks_the_credential_in_every_field() {
    let body = format!("event: e{TOKEN}\nid: i{TOKEN}\ndata: d{TOKEN}\n\n");
    for json in [false, true] {
        for at in [3, 12, body.len() / 2, body.len() - 3] {
            let reply = answer(200, "text/event-stream", split(&body, at), true);
            let (out, outcome, _) = run(&args(STREAM, Some(1), json), Some(reply)).await;
            assert_eq!(outcome.exit, ApiExit::Ok, "json {json}, cut {at}");
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
    assert_eq!((outcome.exit, out), (ApiExit::Ok, b"ok\n\xffa\n".to_vec()));
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
    assert_eq!(outcome.exit, ApiExit::LocalFailure);
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
    assert_eq!(outcome.exit, ApiExit::Ok);
    assert!(
        out.is_empty() && text(&outcome.stdout).contains("\"ok\": true"),
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
            out.is_empty() && outcome.exit != ApiExit::Ok,
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
            (outcome.exit, out),
            (ApiExit::Ok, b"a,b\n".to_vec()),
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
    assert_eq!(outcome.exit, ApiExit::Ok);
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
    assert_eq!(outcome.exit, ApiExit::LocalFailure);
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
    assert_eq!((outcome.exit, out.len()), (ApiExit::LocalFailure, 0));
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
        (outcome.exit, text(&out)),
        (ApiExit::Network, "one\n".to_owned())
    );
    assert!(!outcome.stderr.contains(TOKEN));
    let ended = answer(
        200,
        "text/event-stream",
        vec![b"data: a\n\n".to_vec()],
        false,
    );
    let (out, outcome, _) = run(&args(STREAM, Some(2), false), Some(ended)).await;
    assert_eq!(outcome.exit, ApiExit::Network);
    assert!(outcome.stderr.contains("1 of 2"), "{}", outcome.stderr);
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
        (std::io::ErrorKind::BrokenPipe, ApiExit::Ok),
        (std::io::ErrorKind::Other, ApiExit::LocalFailure),
    ] {
        let reply = answer(200, "text/csv", vec![b"a\n".to_vec()], false);
        let request = args(EXPORT, None, false);
        let outcome = run_streamed_with(
            &request,
            BASE,
            &LinkTls::default(),
            credential,
            Failing(kind),
            &short(),
            |_| async { Ok(reply) },
        )
        .await;
        assert_eq!(outcome.exit, exit, "{kind:?}");
    }
}

/// R3, R12: a stream that only sends keep-alives, however fast, ends at the
/// event wait; a body
/// that stalls ends at the stall wait; no request is repeated.
#[tokio::test]
async fn silent_answers_end_at_their_waits() {
    // Always ready: a flood of keep-alives must still end at the event wait.
    let keep_alive =
        futures::stream::repeat_with(|| Ok(bytes::Bytes::from_static(b": keep-alive\n")));
    let mut reply = answer(200, "text/event-stream", Vec::new(), false);
    reply.body = keep_alive.boxed();
    let (out, outcome, sends) = run(&args(STREAM, Some(1), false), Some(reply)).await;
    assert_eq!((outcome.exit, out.len(), sends), (ApiExit::Network, 0, 1));
    assert!(
        outcome.stderr.contains("No event arrived"),
        "{}",
        outcome.stderr
    );
    let (_, outcome, sends) = run(
        &args(EXPORT, None, false),
        Some(answer(200, "text/csv", vec![b"a\n".to_vec()], true)),
    )
    .await;
    assert_eq!((outcome.exit, sends), (ApiExit::Network, 1));
    assert!(
        outcome.stderr.contains("stopped sending"),
        "{}",
        outcome.stderr
    );
}

/// Fires when the response body it travels in is dropped: the client hung up.
struct HangUp(std::sync::Arc<tokio::sync::Notify>);

impl Drop for HangUp {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// A stand-in gateway on loopback: it answers with `events` at once, then
/// `then` after `release` fires, then keeps the stream open; it records the
/// query it was sent (where a resume cursor travels), counts requests, and
/// notices a hang-up.
struct Live {
    base: String,
    query: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    requests: std::sync::Arc<AtomicUsize>,
    hung_up: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

async fn live(
    content_type: &'static str,
    events: Vec<&'static str>,
    then: Option<&'static str>,
) -> Live {
    use std::sync::Arc;
    let gateway = Live {
        base: String::new(),
        query: Arc::default(),
        requests: Arc::default(),
        hung_up: Arc::default(),
        release: Arc::default(),
    };
    let (seen, count, hung_up, release) = (
        Arc::clone(&gateway.query),
        Arc::clone(&gateway.requests),
        Arc::clone(&gateway.hung_up),
        Arc::clone(&gateway.release),
    );
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        count.fetch_add(1, Ordering::SeqCst);
        *seen.lock().expect("seen") = uri.query().map(str::to_owned);
        let state = (
            0usize,
            HangUp(Arc::clone(&hung_up)),
            events.clone(),
            then,
            Arc::clone(&release),
        );
        let body =
            futures::stream::unfold(state, |(step, guard, events, then, release)| async move {
                if let Some(event) = events.get(step) {
                    let chunk = bytes::Bytes::from_static(event.as_bytes());
                    return Some((
                        Ok::<_, std::io::Error>(chunk),
                        (step + 1, guard, events, then, release),
                    ));
                }
                if let Some(last) = then {
                    release.notified().await;
                    let chunk = bytes::Bytes::from_static(last.as_bytes());
                    return Some((Ok(chunk), (step, guard, events, None, release)));
                }
                futures::future::pending::<()>().await;
                None
            });
        async move {
            axum::response::Response::builder()
                .header("content-type", content_type)
                .body(axum::body::Body::from_stream(body))
                .expect("response")
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    Live { base, ..gateway }
}

/// R1, R2 (test plan row T6): against a live stream that stays open,
/// `--json --limit 1` prints exactly the first event as one JSON line and
/// exits 0; the gateway sees the hang-up, receives the resume cursor in the
/// query unchanged (`?last_event_id=`, which the route resumes from),
/// and gets one request.
#[tokio::test]
async fn a_live_stream_stops_at_the_limit_and_hangs_up() {
    let gateway = live(
        "text/event-stream",
        vec!["id: 1\ndata: {\"n\":1}\n\n", "data: two\n\n"],
        None,
    )
    .await;
    let request = args("/ui/api/stream?last_event_id=0", Some(1), true);
    let out = Shared::default();
    let outcome = run_streamed_with(
        &request,
        &gateway.base,
        &LinkTls::default(),
        credential,
        out.clone(),
        &Deadlines::default(),
        send,
    )
    .await;
    assert_eq!(outcome.exit, ApiExit::Ok, "{}", outcome.stderr);
    let printed = out.bytes();
    let lines: Vec<&str> = std::str::from_utf8(&printed)
        .expect("text")
        .lines()
        .collect();
    assert_eq!(lines.len(), 1, "exactly one event: {lines:?}");
    let printed: Value = serde_json::from_str(lines[0]).expect("one JSON object");
    assert_eq!(
        printed,
        json!({"event": "message", "id": "1", "data": {"n": 1}})
    );
    // A hang guard: the hang-up arrives as soon as the response is dropped.
    tokio::time::timeout(Duration::from_secs(30), gateway.hung_up.notified())
        .await
        .expect("the gateway sees the client hang up");
    assert_eq!(
        gateway.query.lock().expect("seen").as_deref(),
        Some("last_event_id=0")
    );
    assert_eq!(
        gateway.requests.load(Ordering::SeqCst),
        1,
        "nothing is retried"
    );
}

/// R14 (round 3 HIGH; final review): a streamed request drops the total
/// limit of the options it is built from. The sender gets a 50 ms base total;
/// the stand-in withholds the second event until a buffered call limited to
/// 150 ms has timed out. A sender that kept its base total would end the
/// stream at 50 ms, before the release; the stream instead outlives it.
#[tokio::test]
async fn a_streamed_request_has_no_total_limit() {
    let gateway = live(
        "text/event-stream",
        vec!["data: one\n\n"],
        Some("data: two\n\n"),
    )
    .await;
    let request = args(STREAM, Some(2), false);
    let out = Shared::default();
    // Bound first: the streamed future is joined later, past this statement.
    let (tls, deadlines) = (LinkTls::default(), Deadlines::default());
    let streamed = run_streamed_with(
        &request,
        &gateway.base,
        &tls,
        credential,
        out.clone(),
        &deadlines,
        |request| {
            send_with(
                request,
                AdminClientOptions {
                    // A sender keeping this would end the stream first.
                    // timing: lower-bound
                    total: Some(ms(50)),
                    ..AdminClientOptions::default()
                },
            )
        },
    );
    let release_after_a_timed_out_buffered_call = async {
        let options = AdminClientOptions {
            // Longer than the sender's base total, so the release comes
            // after any stream that kept that total had already ended.
            // timing: lower-bound
            total: Some(ms(150)),
            ..AdminClientOptions::default()
        };
        let Ok(url) = api_url(&gateway.base, STREAM) else {
            panic!("the stream URL parses");
        };
        let buffered = super::super::super::dashboard_link::admin_call_url_with_options(
            reqwest::Method::GET,
            url,
            TOKEN,
            &LinkTls::default(),
            None,
            None,
            &options,
        )
        .await;
        assert!(
            buffered.is_err(),
            "a 150 ms total limit stops the buffered read of an open stream"
        );
        gateway.release.notify_one();
    };
    let (outcome, ()) = tokio::join!(streamed, release_after_a_timed_out_buffered_call);
    assert_eq!(outcome.exit, ApiExit::Ok, "{}", outcome.stderr);
    assert_eq!(
        text(&out.bytes()),
        "event: message\ndata: one\n\nevent: message\ndata: two\n\n"
    );
}

/// R5: a download is printed as it arrives: the first line is out before the
/// second chunk is sent.
#[tokio::test]
async fn a_download_prints_before_the_body_ends() {
    let printed = Shared::default();
    let (chunks, body) =
        futures::channel::mpsc::unbounded::<Result<bytes::Bytes, AdminCallError>>();
    let mut reply = answer(200, "text/csv", Vec::new(), false);
    reply.body = body.boxed();
    let request = args(EXPORT, None, false);
    // Bound first: the streamed future is joined later, past this statement.
    let (tls, deadlines) = (LinkTls::default(), short());
    let streamed = run_streamed_with(
        &request,
        BASE,
        &tls,
        credential,
        printed.clone(),
        &deadlines,
        |_| async { Ok(reply) },
    );
    let feed = async {
        chunks
            .unbounded_send(Ok(bytes::Bytes::from_static(b"first\n")))
            .expect("send");
        while printed.bytes() != b"first\n" {
            tokio::task::yield_now().await;
        }
        chunks
            .unbounded_send(Ok(bytes::Bytes::from_static(b"second\n")))
            .expect("send");
        chunks.close_channel();
    };
    let (outcome, ()) = tokio::join!(streamed, feed);
    assert_eq!(outcome.exit, ApiExit::Ok);
    assert_eq!(printed.bytes(), b"first\nsecond\n");
}

/// A sink whose writes park until the row's [`Release`] drops, as a reader
/// that stalls the pipe parks a real write; once released, it keeps what it
/// is given.
#[derive(Clone, Default)]
struct Parked(ParkState);

/// Whether the parked writes are released, what they wrote, and the wake.
type ParkState = std::sync::Arc<(std::sync::Mutex<(bool, Vec<u8>)>, std::sync::Condvar)>;

impl Write for Parked {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let (state, wake) = &*self.0;
        let mut state = state.lock().expect("parked");
        while !state.0 {
            state = wake.wait(state).expect("parked");
        }
        state.1.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Parked {
    fn bytes(&self) -> Vec<u8> {
        (self.0).0.lock().expect("parked").1.clone()
    }
}

/// Frees a [`Parked`] sink's writes when dropped, so no thread is left parked.
struct Release(Parked);

impl Drop for Release {
    fn drop(&mut self) {
        let (state, wake) = &*(self.0).0;
        state.lock().expect("parked").0 = true;
        wake.notify_all();
    }
}

/// R12 (final review HIGH): a reader that stalls the pipe cannot hold the
/// command past its overall deadline. The export's first write parks; the
/// run still ends, at the overall deadline, with the network exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_reader_ends_at_the_overall_deadline() {
    let sink = Parked::default();
    let _release = Release(sink.clone());
    let reply = answer(200, "text/csv", vec![b"a\n".to_vec()], true);
    // On a task of its own: a write that blocked the run's thread (the break
    // this row catches) would stall it there, not the row.
    let run = tokio::spawn(async move {
        run_streamed_with(
            &args(EXPORT, None, false),
            BASE,
            &LinkTls::default(),
            credential,
            sink,
            &short(),
            |_| async { Ok(reply) },
        )
        .await
    });
    // A hang guard: the run ends at its 1.5 s overall deadline.
    let outcome = tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("a parked write does not hold the run past its deadline")
        .expect("the run task");
    assert_eq!(outcome.exit, ApiExit::Network, "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("overall time limit"),
        "{}",
        outcome.stderr
    );
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
            (outcome.exit, out.len()),
            (ApiExit::LocalFailure, 0),
            "{} {token:?}: {}",
            request.path,
            outcome.stderr
        );
    }
    for (request, reply) in [
        (args(EXPORT, None, false), export("Xd]zz\n")),
        (args(STREAM, Some(1), false), event("Xd]zz")),
    ] {
        let (out, outcome, _) = run_as(&request, Some(reply), "d]z").await;
        assert_eq!(outcome.exit, ApiExit::Ok, "{}", outcome.stderr);
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
    assert_eq!((outcome.exit, out.len()), (ApiExit::LocalFailure, 0));
}

/// D4 (final review): a gateway that never sends response headers ends at
/// the headers wait with the network exit; nothing is printed.
#[tokio::test]
async fn no_response_headers_end_at_the_headers_wait() {
    let out = Shared::default();
    let outcome = run_streamed_with(
        &args(EXPORT, None, false),
        BASE,
        &LinkTls::default(),
        credential,
        out.clone(),
        &short(),
        |_| futures::future::pending::<Result<AdminStream, AdminCallError>>(),
    )
    .await;
    assert_eq!(
        (outcome.exit, out.bytes().len()),
        (ApiExit::Network, 0),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("no response headers"),
        "{}",
        outcome.stderr
    );
}

/// Final review (lead): a printing thread that outlives the deadline writes
/// nothing more. The reader stalls on the first line and the run exits at the
/// overall deadline with the network exit. When the reader resumes, at most
/// the line whose write had already begun lands (a begun write cannot be
/// withdrawn; the binary has exited by then), never a later line, and the
/// thread ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_more_is_printed_after_the_deadline() {
    let sink = Parked::default();
    let (watch, release) = (sink.clone(), Release(sink.clone()));
    // One chunk: all three lines are in hand when the first write parks, so
    // a printer that queued them would deliver the rest once released.
    let reply = answer(200, "text/csv", vec![b"a\nb\nc\n".to_vec()], true);
    let run = tokio::spawn(async move {
        run_streamed_with(
            &args(EXPORT, None, false),
            BASE,
            &LinkTls::default(),
            credential,
            sink,
            &short(),
            |_| async { Ok(reply) },
        )
        .await
    });
    // A hang guard: the run ends at its 1.5 s overall deadline.
    let outcome = tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("the run ends at its deadline")
        .expect("the run task");
    assert_eq!(outcome.exit, ApiExit::Network, "{}", outcome.stderr);
    drop(release);
    // A hang guard: once its parked write returns, the thread finds the run
    // gone and ends, dropping its copy of the sink.
    tokio::time::timeout(Duration::from_secs(30), async {
        while std::sync::Arc::strong_count(&watch.0) > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the printing thread ends after the run");
    let landed = watch.bytes();
    assert!(
        landed.is_empty() || landed == b"a\n",
        "only the write already begun may land: {:?}",
        String::from_utf8_lossy(&landed)
    );
}
