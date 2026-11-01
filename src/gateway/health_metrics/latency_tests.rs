// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp_gateway_added_latency_seconds`: what the clock subtracts, and that
//! every call leaves exactly one sample. Rows run on a paused clock under a
//! local recorder built like the production one, so the waits are virtual
//! and the sums exact.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::post;
use tower::ServiceExt;

use super::clock::{Clock, backend_wait, carried};
use super::layers::{ADDED_LATENCY, StreamAccounted, latency_layer};

/// Long on the virtual clock, so a wrong subtraction cannot hide in rounding.
const BACKEND: Duration = Duration::from_secs(20);

/// Run `fut` on a paused runtime under a local recorder; return its output
/// and the text a scrape would show.
fn metered<T>(fut: impl Future<Output = T>) -> (T, String) {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        let mut rt = tokio::runtime::Builder::new_current_thread();
        rt.enable_all().start_paused(true);
        rt.build().expect("runtime").block_on(fut)
    });
    (out, handle.render())
}

/// The value of the unlabelled series `key` in `rendered`.
fn value(rendered: &str, key: &str) -> Option<f64> {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(' ')?.parse().ok())
}

fn count(rendered: &str) -> f64 {
    value(rendered, &format!("{ADDED_LATENCY}_count")).unwrap_or(0.0)
}

fn sum(rendered: &str) -> f64 {
    value(rendered, &format!("{ADDED_LATENCY}_sum")).unwrap_or(0.0)
}

fn approx(got: f64, want: Duration) {
    assert!((got - want.as_secs_f64()).abs() < 1e-3, "{got} vs {want:?}");
}

fn post_mcp() -> Request<Body> {
    Request::post("/").body(Body::empty()).expect("request")
}

/// A `POST /` route running `handler` behind the latency layer.
fn app<H, T>(handler: H) -> Router
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    Router::new()
        .route("/", post(handler))
        .layer(from_fn(latency_layer))
}

#[test]
fn a_backend_wait_is_subtracted() {
    let (status, text) = metered(async {
        let route = app(|| async {
            backend_wait(tokio::time::sleep(BACKEND)).await;
            "ok"
        });
        route.oneshot(post_mcp()).await.expect("answer").status()
    });
    assert!(status.is_success());
    assert_eq!(count(&text), 1.0, "{text}");
    approx(sum(&text), Duration::ZERO);
}

#[test]
fn a_call_with_no_backend_adds_the_whole_time() {
    let ((), text) = metered(async {
        let route = app(|| async {
            tokio::time::sleep(BACKEND).await;
            "ok"
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    assert_eq!(count(&text), 1.0, "{text}");
    approx(sum(&text), BACKEND);
}

#[test]
fn two_parallel_waits_count_once() {
    let (busy, _) = metered(async {
        let clock = Clock::start();
        Arc::clone(&clock)
            .scope(async {
                tokio::join!(
                    backend_wait(tokio::time::sleep(BACKEND)),
                    backend_wait(tokio::time::sleep(BACKEND))
                );
            })
            .await;
        clock.busy()
    });
    approx(busy.as_secs_f64(), BACKEND);
}

#[test]
fn time_held_on_a_semaphore_stays_added_latency() {
    let ((), text) = metered(async {
        let held = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::clone(&held);
        tokio::spawn(async move {
            tokio::time::sleep(BACKEND).await;
            release.add_permits(1);
        });
        let route = app(move || {
            let held = Arc::clone(&held);
            async move {
                let _permit = held.acquire().await.expect("open");
                backend_wait(tokio::time::sleep(BACKEND)).await;
                "ok"
            }
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    assert_eq!(count(&text), 1.0, "{text}");
    approx(sum(&text), BACKEND);
}

#[test]
fn a_fill_in_a_carried_task_is_subtracted_and_an_uncarried_one_is_not() {
    let fill = || async {
        backend_wait(tokio::time::sleep(BACKEND)).await;
    };
    let ((), with) = metered(async {
        let route = app(move || async move {
            tokio::spawn(carried(fill())).await.expect("joined");
            "ok"
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    let ((), without) = metered(async {
        let route = app(move || async move {
            tokio::spawn(fill()).await.expect("joined");
            "ok"
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    approx(sum(&with), Duration::ZERO);
    approx(sum(&without), BACKEND);
}

#[test]
fn a_client_that_goes_away_mid_wait_leaves_one_sample() {
    let ((), text) = metered(async {
        let route = app(|| async {
            backend_wait(tokio::time::sleep(BACKEND * 10)).await;
            "ok"
        });
        let gone = tokio::time::timeout(BACKEND, route.oneshot(post_mcp())).await;
        assert!(gone.is_err(), "the call must still be waiting");
    });
    assert_eq!(count(&text), 1.0, "{text}");
    approx(sum(&text), Duration::ZERO);
}

#[test]
fn a_buffered_sse_answer_leaves_one_sample() {
    let ((), text) = metered(async {
        let route = app(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                "data: {}\n\n",
            )
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    assert_eq!(count(&text), 1.0, "{text}");
}

#[test]
fn a_stream_accounted_answer_is_left_to_its_stream() {
    let ((), text) = metered(async {
        let route = app(|| async {
            let mut response = "ok".into_response();
            response.extensions_mut().insert(StreamAccounted);
            response
        });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    assert_eq!(count(&text), 0.0, "{text}");
}

#[test]
fn only_this_metric_renders_buckets() {
    let ((), text) = metered(async {
        telemetry_metrics::histogram!("some_other_seconds").record(1.0);
        let route = app(|| async { "ok" });
        route.oneshot(post_mcp()).await.expect("answer");
    });
    assert!(
        text.contains(&format!("{ADDED_LATENCY}_bucket{{le=\"0.001\"}}")),
        "{text}"
    );
    assert!(!text.contains("some_other_seconds_bucket"), "{text}");
}

mod streams {
    use super::*;
    use crate::gateway::outbound::{OutboundFrame, Payload, RejectionAudit, StreamJudge};
    use crate::gateway::streaming::first_event_wins_stream;
    use axum::response::Response;

    fn note() -> OutboundFrame {
        OutboundFrame::unjudged(Payload::Notification(
            crate::protocol::JsonRpcNotification {
                jsonrpc: "2.0".to_string(),
                method: "notifications/progress".to_string(),
                params: None,
            },
        ))
    }

    fn judge() -> Arc<StreamJudge> {
        Arc::new(StreamJudge::new(
            None,
            Arc::new(RejectionAudit::new(None, 1)),
            None,
        ))
    }

    fn answer() -> Response {
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        )
            .into_response()
    }

    /// A notification-first stream built inside a request clock, with its
    /// dispatch parked on `gate` after `BACKEND` of backend wait.
    async fn open(
        gate: Arc<tokio::sync::Semaphore>,
    ) -> (Response, tokio::sync::mpsc::Sender<OutboundFrame>) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(note()).await.expect("sink open");
        let response = Clock::start()
            .scope(first_event_wins_stream(
                async move {
                    backend_wait(tokio::time::sleep(BACKEND)).await;
                    let _permit = gate.acquire().await.expect("open");
                    answer()
                },
                rx,
                judge(),
            ))
            .await;
        (response, tx)
    }

    async fn read_all(response: Response) {
        let mut body = response.into_body().into_data_stream();
        while futures::StreamExt::next(&mut body).await.is_some() {}
    }

    #[test]
    fn one_sample_at_the_terminal_event_and_none_after() {
        let (accounted, text) = metered(async {
            let gate = Arc::new(tokio::sync::Semaphore::new(1));
            let (response, _tx) = open(gate).await;
            let accounted = response.extensions().get::<StreamAccounted>().is_some();
            let mut body = response.into_body().into_data_stream();
            // The first event is the notification; the terminal one comes
            // after the backend wait.
            futures::StreamExt::next(&mut body).await;
            while futures::StreamExt::next(&mut body).await.is_some() {}
            drop(body);
            accounted
        });
        assert!(accounted);
        assert_eq!(count(&text), 1.0, "{text}");
        approx(sum(&text), Duration::ZERO);
    }

    #[test]
    fn a_stream_dropped_before_its_first_poll_leaves_one_sample() {
        let ((), text) = metered(async {
            let (response, _tx) = open(Arc::new(tokio::sync::Semaphore::new(1))).await;
            drop(response);
        });
        assert_eq!(count(&text), 1.0, "{text}");
    }

    #[test]
    fn a_stream_dropped_right_after_its_terminal_event_leaves_one_sample() {
        let ((), text) = metered(async {
            let (response, _tx) = open(Arc::new(tokio::sync::Semaphore::new(1))).await;
            read_all(response).await;
        });
        assert_eq!(count(&text), 1.0, "{text}");
    }
}
