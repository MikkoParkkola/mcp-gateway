// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The heartbeat at the real 3.5 start sites, `Gateway::run` and
//! `Gateway::run_stdio_on`: under `DO_NOT_TRACK` neither sends (W1', W2'),
//! each start answers while its heartbeat waits on a receiver that never
//! answers (F7, F8), and the stdio task ends with the read loop (F11).
//!
//! Each row runs in a child test process whose home is a temp dir
//! (`test_hooks::in_child`): a server loads and saves its state under the
//! home. Unix only: on Windows the 3.5 line sends nothing (WIN1), so there is
//! no sending control to run there.

use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::AsyncWrite;

use super::Gateway;
use super::test_hooks::{CHILD_DONE, in_child, is_child, loopback_any_port};
use crate::heartbeat::fixtures::{Answer, Listener, nov19, test_client};
use crate::heartbeat::{Outcome, Skip, seam};

/// Poll `done` every 20 ms for up to 30 s of real time.
async fn wait_for(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: not within 30 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Make `dir` this thread's heartbeat root and give it a target at `rx`
/// through `client`, checking every 50 ms; `env` is the target's snapshot,
/// the start site's own input (an opt-out goes here, never through
/// `set_var`).
fn aim(
    dir: &Path,
    rx: &Listener,
    env: &[(&str, &str)],
    client: reqwest::Client,
) -> (seam::RootGuard, seam::Guard) {
    let root = seam::register_root(dir);
    let target = seam::register(
        dir,
        seam::Target {
            url: rx.url(),
            client,
            today: nov19,
            every: Duration::from_millis(50),
            stall: None,
        },
    );
    seam::set_env(dir, env);
    (root, target)
}

/// A client with no timeout at all: against a receiver that never answers,
/// a start that waited on its heartbeat would never answer either.
fn patient_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a client")
}

/// The opt-out W1' and W2' put in the start's snapshot.
const OPTED_OUT: &[(&str, &str)] = &[("DO_NOT_TRACK", "1")];

/// A writer that hands bytes on only when flushed, as a piped stdout does: a
/// response written but never flushed never reaches the reader.
struct FlushGated<W> {
    inner: W,
    held: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FlushGated<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().held.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.held.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.held))?;
            this.held.drain(..n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut *this).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// An HTTP gateway started through `run` on a free loopback port.
struct Http {
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<crate::Result<()>>,
    /// `/health`'s status, and the time from construction to it.
    health: u16,
    took: Duration,
}

/// Construct, start `run`, learn its port, GET `/health` (each step bounded).
async fn start_http() -> Http {
    let begun = std::time::Instant::now();
    let mut gw = Gateway::new(loopback_any_port()).await.expect("a gateway");
    let stop = gw.shutdown_trigger_for_test();
    let port_rx = gw.bound_port_for_test();
    let task = tokio::spawn(Box::pin(gw.run()));
    let port = tokio::time::timeout(Duration::from_secs(30), port_rx)
        .await
        .expect("run bound within 30 s")
        .expect("run bound before it ended");
    let get = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a client")
        .get(format!("http://127.0.0.1:{port}/health"))
        .send();
    let health = tokio::time::timeout(Duration::from_secs(30), get)
        .await
        .expect("/health answered within 30 s")
        .map_or(0, |r| r.status().as_u16());
    Http {
        stop,
        task,
        health,
        took: begun.elapsed(),
    }
}

impl Http {
    /// Pull the trigger; `run` must return Ok within 30 s.
    async fn stop(self) {
        self.stop.send(()).expect("run still holds the trigger");
        let result = tokio::time::timeout(Duration::from_secs(30), self.task)
            .await
            .expect("run returned within 30 s")
            .expect("run did not panic");
        assert!(result.is_ok(), "{result:?}");
    }
}

/// The HTTP rows' child, under its name in this test binary.
const HTTP_CHILD: &str = "gateway::server::heartbeat_start_tests::child_http_start";

/// W1' then F7, in one child with a temp home.
#[tokio::test]
#[ignore = "run only as a child of http_start_honours_do_not_track_and_never_waits"]
async fn child_http_start() {
    if !is_child() {
        return;
    }
    // W1': DO_NOT_TRACK in the start's snapshot. The check skips; nothing is
    // sent, no state is made.
    let quiet = Listener::start(Answer::NoContent).await;
    let opted = tempfile::tempdir().expect("a dir");
    {
        let _aimed = aim(opted.path(), &quiet, OPTED_OUT, test_client());
        let http = start_http().await;
        assert_eq!(http.health, 200);
        wait_for("the opted-out check", || {
            seam::outcomes(opted.path()).contains(&Outcome::Skipped(Skip::OptOut))
        })
        .await;
        assert_eq!(quiet.connections(), 0, "an opted-out HTTP start sent");
        assert!(!opted.path().join("heartbeat").exists());
        http.stop().await;
    }
    // F7, and W1''s control: no opt-out; the receiver never answers and the
    // client never gives up. /health still answers within 30 s of
    // construction, and the heartbeat reaches the receiver.
    let hang = Listener::start(Answer::Never).await;
    let open = tempfile::tempdir().expect("a dir");
    let _aimed = aim(open.path(), &hang, &[], patient_client());
    let http = start_http().await;
    assert_eq!(http.health, 200);
    assert!(http.took < Duration::from_secs(30), "{:?}", http.took);
    wait_for("the control's heartbeat", || hang.connections() == 1).await;
    http.stop().await;
    println!("{CHILD_DONE}");
}

/// W1' + F7 at `Gateway::run`.
#[tokio::test]
async fn http_start_honours_do_not_track_and_never_waits() {
    let home = tempfile::tempdir().expect("a home");
    in_child(HTTP_CHILD, home.path()).await;
}

/// A stdio gateway on pipes, through `run_stdio_on`, its stdout flush-gated.
struct Stdio {
    input: tokio::io::DuplexStream,
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::io::DuplexStream>>,
    task: tokio::task::JoinHandle<crate::Result<()>>,
}

/// Construct a default gateway and serve stdio on fresh pipes.
async fn start_stdio() -> Stdio {
    use tokio::io::AsyncBufReadExt as _;
    let gw = Gateway::new(crate::config::Config::default())
        .await
        .expect("a gateway");
    let (input, server_in) = tokio::io::duplex(64 * 1024);
    let (server_out, reader) = tokio::io::duplex(1 << 20);
    let gated = FlushGated {
        inner: server_out,
        held: Vec::new(),
    };
    let task = tokio::spawn(Box::pin(gw.run_stdio_on(server_in, gated)));
    Stdio {
        input,
        lines: tokio::io::BufReader::new(reader).lines(),
        task,
    }
}

impl Stdio {
    /// Send `ping` (id 1); whether its JSON-RPC result came back within 30 s.
    async fn ping(&mut self) -> bool {
        use tokio::io::AsyncWriteExt as _;
        let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        self.input.write_all(ping).await.expect("write");
        self.input.write_all(b"\n").await.expect("write");
        let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
            .await
            .expect("an answer within 30 s")
            .ok()
            .flatten();
        let reply: Option<serde_json::Value> = line.and_then(|l| serde_json::from_str(&l).ok());
        reply.is_some_and(|r| r.get("result").is_some() && r["id"] == 1)
    }

    /// Close stdin: the read loop ends, and `run_stdio_on` must return Ok
    /// within 30 s.
    async fn close(self) {
        drop(self.input);
        let result = tokio::time::timeout(Duration::from_secs(30), self.task)
            .await
            .expect("run_stdio_on returned within 30 s of EOF")
            .expect("run_stdio_on did not panic");
        assert!(result.is_ok(), "{result:?}");
    }
}

/// The stdio rows' child, under its name in this test binary.
const STDIO_CHILD: &str = "gateway::server::heartbeat_start_tests::child_stdio_start";

/// W2', F8, then F11, in one child with a temp home.
#[tokio::test]
#[ignore = "run only as a child of stdio_start_honours_do_not_track_and_ends_with_its_loop"]
async fn child_stdio_start() {
    if !is_child() {
        return;
    }
    // W2': DO_NOT_TRACK in the start's snapshot; ping is answered, nothing
    // is sent, no state is made.
    let quiet = Listener::start(Answer::NoContent).await;
    let opted = tempfile::tempdir().expect("a dir");
    {
        let _aimed = aim(opted.path(), &quiet, OPTED_OUT, test_client());
        let mut stdio = start_stdio().await;
        assert!(stdio.ping().await, "no answer to ping");
        wait_for("the opted-out check", || {
            seam::outcomes(opted.path()).contains(&Outcome::Skipped(Skip::OptOut))
        })
        .await;
        assert_eq!(quiet.connections(), 0, "an opted-out stdio start sent");
        assert!(!opted.path().join("heartbeat").exists());
        stdio.close().await;
    }
    // F8, and W2''s control: no opt-out, a receiver that never answers; ping
    // is still answered through the flush-gated stdout, and the heartbeat
    // reaches the receiver. Closing stdin then ends the server even though
    // that check is still in flight.
    let hang = Listener::start(Answer::Never).await;
    let open = tempfile::tempdir().expect("a dir");
    {
        let _aimed = aim(open.path(), &hang, &[], patient_client());
        let mut stdio = start_stdio().await;
        assert!(stdio.ping().await, "ping waited on the heartbeat");
        wait_for("the control's heartbeat", || hang.connections() == 1).await;
        stdio.close().await;
    }
    // F11: the task ends with the read loop. Checks run every 50 ms, so the
    // control sees the count grow over the window while the loop runs; after
    // the loop has ended, the same window sees no new check.
    let rx = Listener::start(Answer::NoContent).await;
    let ends = tempfile::tempdir().expect("a dir");
    let _aimed = aim(ends.path(), &rx, &[], test_client());
    let mut stdio = start_stdio().await;
    assert!(stdio.ping().await, "no answer to ping");
    let count = || seam::outcomes(ends.path()).len();
    wait_for("a first check", || count() > 0).await;
    let window = Duration::from_millis(500);
    let running = count();
    tokio::time::sleep(window).await;
    assert!(
        count() > running,
        "control: no check in the window while the loop ran"
    );
    stdio.close().await;
    let ended = count();
    tokio::time::sleep(window).await;
    assert_eq!(count(), ended, "a check ran after the read loop ended");
    println!("{CHILD_DONE}");
}

/// W2' + F8 + F11 at `Gateway::run_stdio_on`.
#[tokio::test]
async fn stdio_start_honours_do_not_track_and_ends_with_its_loop() {
    let home = tempfile::tempdir().expect("a home");
    in_child(STDIO_CHILD, home.path()).await;
}
