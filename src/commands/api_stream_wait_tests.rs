// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the api command's streamed path, part waits and printing: the
//! stall, event, headers, fallback and overall deadlines, live streams, and the
//! printing thread under a reader that stalls. The shared fixtures live in the
//! parent module.

use super::*;

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
        let buffered = crate::commands::dashboard_link::admin_call_url_with_options(
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
        // A hang guard: a printer that buffered the line would never show it.
        tokio::time::timeout(Duration::from_secs(30), async {
            while printed.bytes() != b"first\n" {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first line prints before the second chunk is sent");
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

/// D4 (final review): a gateway that never sends response headers ends at
/// the headers wait with the network exit; nothing is printed.
#[tokio::test]
async fn no_response_headers_end_at_the_headers_wait() {
    let out = Shared::default();
    // Bound first: the run is awaited later, past this statement.
    let (request, tls, deadlines) = (args(EXPORT, None, false), LinkTls::default(), short());
    let run = run_streamed_with(
        &request,
        BASE,
        &tls,
        credential,
        out.clone(),
        &deadlines,
        |_| futures::future::pending::<Result<AdminStream, AdminCallError>>(),
    );
    // A hang guard, far past the 400 ms headers deadline under test: without
    // that deadline the run would wait on the sender forever.
    let outcome = tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("the headers deadline ends a run whose gateway never answers");
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

/// Final review (second seat): the buffered fallback on a streamed route ends
/// at its total even when the body is always ready (endless empty chunks).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_always_ready_fallback_body_ends_at_its_total() {
    let mut reply = answer(200, "application/json", Vec::new(), false);
    reply.body = futures::stream::repeat_with(|| Ok(bytes::Bytes::new())).boxed();
    // On a task of its own: without the deadline check the read loop never
    // yields, so only another worker can notice.
    let task = tokio::spawn(async move { run(&args(EXPORT, None, false), Some(reply)).await });
    // A hang guard, far past the 400 ms fallback total under test.
    let (out, outcome, _) = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the fallback total ends an always-ready body")
        .expect("the run task");
    assert_eq!(
        (outcome.exit, out.len()),
        (ApiExit::Network, 0),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("did not finish its answer in time"),
        "{}",
        outcome.stderr
    );
}
