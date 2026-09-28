//! #2147: after the shutdown signal the listener waits for open requests at
//! most `server.shutdown_timeout`, and no less.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

    let signalled = Instant::now();
    stop.send(()).expect("server is running");
    let served = timeout(HANG_STOP, server)
        .await
        .expect("the server did not return within 5 s while a request was open");
    let elapsed = signalled.elapsed();
    served.expect("server task").expect("serve");
    assert!(
        elapsed < Duration::from_millis(1500),
        "shutdown took {elapsed:?} with a {grace:?} timeout"
    );
    // The deadline cancels the open request, so its in-flight permit is
    // released and nothing it holds outlives the listener.
    timeout(Duration::from_secs(1), dropped_rx)
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
