// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2147: after the shutdown signal the listener waits for open requests at
//! most `server.shutdown_timeout`, and no less.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::serve;
use crate::config::Config;

/// Every wait in these tests is bounded, so a regression fails by name
/// instead of hanging the job.
const HANG_STOP: Duration = Duration::from_secs(5);

/// Sends once when dropped: proof that a handler future was cancelled.
struct SendOnDrop(Option<oneshot::Sender<()>>);

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

/// Serve `app` on a fresh loopback port with the given shutdown timeout.
async fn start(
    app: Router,
    grace: Duration,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<crate::Result<()>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let listener = listener.into_std().expect("std listener");
    let mut config = Config::default();
    config.server.shutdown_timeout = grace;
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve(app, listener, addr, &config, async move {
            let _ = stop_rx.await;
        })
        .await
    });
    (addr, stop_tx, server)
}

#[tokio::test]
async fn a_request_that_never_ends_does_not_hold_shutdown_past_the_timeout() {
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (dropped_tx, dropped_rx) = oneshot::channel::<()>();
    let slot = Arc::new(Mutex::new(Some((started_tx, dropped_tx))));
    let app = Router::new().route(
        "/hang",
        get(move || {
            let taken = slot.lock().expect("slot").take();
            async move {
                let (started, dropped) = taken.expect("one request");
                let _guard = SendOnDrop(Some(dropped));
                let _ = started.send(());
                std::future::pending::<()>().await;
            }
        }),
    );
    let grace = Duration::from_millis(100);
    let (addr, stop, server) = start(app, grace).await;
    let client = tokio::spawn(reqwest::get(format!("http://{addr}/hang")));
    timeout(HANG_STOP, started_rx)
        .await
        .expect("the request reached its handler")
        .expect("started");

    // The request never ends, so only the shutdown deadline can return the
    // server: returning inside the hang guard is the oracle, not how long it
    // took against the grace (MIK-8222).
    stop.send(()).expect("server is running");
    let outcome = timeout(HANG_STOP, server)
        .await
        .expect("the server did not return within 5 s while a request was open");
    outcome.expect("server task").expect("serve");
    // The deadline cancels the open request, so its in-flight permit is
    // released and nothing it holds outlives the listener.
    timeout(HANG_STOP, dropped_rx)
        .await
        .expect("the open request was not cancelled at the deadline")
        .expect("guard sends on drop");
    client.abort();
}

#[tokio::test]
async fn a_request_that_ends_within_the_timeout_completes_and_no_new_one_is_accepted() {
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let slot = Arc::new(Mutex::new(Some(started_tx)));
    let release = Arc::new(Notify::new());
    let gate = Arc::clone(&release);
    let app = Router::new().route(
        "/slow",
        get(move || {
            let taken = slot.lock().expect("slot").take();
            let gate = Arc::clone(&gate);
            async move {
                let _ = taken.expect("one request").send(());
                gate.notified().await;
                "done"
            }
        }),
    );
    let (addr, stop, server) = start(app, Duration::from_secs(10)).await;
    let client = tokio::spawn(async move {
        let response = reqwest::get(format!("http://{addr}/slow")).await?;
        let status = response.status();
        response.text().await.map(|body| (status, body))
    });
    timeout(HANG_STOP, started_rx)
        .await
        .expect("the request reached its handler")
        .expect("started");

    stop.send(()).expect("server is running");
    // Shutdown has begun once the port refuses a new connection; the same
    // port served the request above, so a refusal is not a never-bound port.
    timeout(HANG_STOP, async {
        while tokio::net::TcpStream::connect(addr).await.is_ok() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the listener kept accepting connections after the shutdown signal");

    // Hold the request well past any short fixed grace: only the configured
    // 10 s may bound it.
    sleep(Duration::from_millis(1500)).await;
    assert!(
        !server.is_finished(),
        "the server stopped before its timeout with a request still open"
    );
    release.notify_one();
    let (status, body) = timeout(HANG_STOP, client)
        .await
        .expect("the open request did not finish")
        .expect("client task")
        .expect("the open request completed");
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body, "done");
    timeout(HANG_STOP, server)
        .await
        .expect("the server did not return once its last request ended")
        .expect("server task")
        .expect("serve");
}

/// `listener::serve` forwards the shutdown signal with one call to
/// `graceful_shutdown`, which may run before the accept loop first waits, or
/// between two accepts. That is safe only because `axum_server` stores the
/// signal as a flag the loop reads on every iteration (#2202). This pins that
/// property: a signal sent before the server even exists still stops it.
#[tokio::test]
async fn a_shutdown_signal_sent_before_the_server_first_waits_is_not_lost() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let handle = axum_server::Handle::<SocketAddr>::new();
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
    let server = axum_server::from_tcp(listener)
        .expect("server")
        .handle(handle)
        .serve(Router::new().into_make_service_with_connect_info::<SocketAddr>());
    timeout(HANG_STOP, server)
        .await
        .expect("a signal sent before the first poll was lost: the server kept running")
        .expect("serve");
}

/// The same through `listener::serve`: a shutdown future that is already
/// resolved still stops the listener, so the forwarding task is not lost.
#[tokio::test]
async fn an_already_resolved_shutdown_future_stops_the_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let listener = listener.into_std().expect("std listener");
    let mut config = Config::default();
    config.server.shutdown_timeout = Duration::from_secs(10);
    timeout(
        HANG_STOP,
        serve(Router::new(), listener, addr, &config, async {}),
    )
    .await
    .expect("the listener kept running after its shutdown future resolved")
    .expect("serve");
}

/// MIK-8120 (`MIK-WRITE-CANCEL.3`): a client that closes its connection while
/// its request is still being handled cancels that handler: the listener
/// drops the request's future. So a handler cannot rely on running to the
/// end once it has started; work that must finish (a config write and the
/// reload that publishes it) has to be handed to a task of its own.
#[tokio::test]
async fn a_client_disconnect_cancels_the_pending_handler() {
    use tokio::io::AsyncWriteExt;

    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (dropped_tx, dropped_rx) = oneshot::channel::<()>();
    let slot = Arc::new(Mutex::new(Some((started_tx, dropped_tx))));
    let app = Router::new().route(
        "/hang",
        get(move || {
            let taken = slot.lock().expect("slot").take();
            async move {
                let (started, dropped) = taken.expect("one request");
                let _guard = SendOnDrop(Some(dropped));
                let _ = started.send(());
                std::future::pending::<()>().await;
            }
        }),
    );
    let (addr, stop, server) = start(app, Duration::from_secs(5)).await;
    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("send the request");
    timeout(HANG_STOP, started_rx)
        .await
        .expect("the request reached its handler")
        .expect("started");

    drop(client);

    timeout(HANG_STOP, dropped_rx)
        .await
        .expect("the handler kept running after its client disconnected")
        .expect("guard sends on drop");
    let _ = stop.send(());
    let _ = timeout(HANG_STOP, server).await;
}
