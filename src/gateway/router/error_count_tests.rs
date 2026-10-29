// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp_gateway_errors_total{kind}`: the error a client received, counted once
//! per answer from the final status and the marker the frame's funnel set.

use std::future::Future;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::json;
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, fixture};
use super::direct_guards_fixture_requests::{post_direct, send};
use super::helpers::{build_error_response, build_response};
use crate::gateway::health_metrics::layers::error_layer;
use crate::gateway::health_metrics::{Origin, RpcError, error_kind};
use crate::gateway::outbound::{OutboundFrame, Payload, to_http};
use crate::protocol::JsonRpcResponse;

/// Run `fut` on a current-thread runtime under a local recorder built like
/// the production one; return its output and what a scrape would show.
fn counted<T>(fut: impl Future<Output = T>) -> (T, String) {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        crate::gateway::health_metrics::register();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    });
    (out, handle.render())
}

/// The count of `mcp_gateway_errors_total{kind="<kind>"}`.
fn errors(rendered: &str, kind: &str) -> u64 {
    let key = format!("mcp_gateway_errors_total{{kind=\"{kind}\"}} ");
    rendered
        .lines()
        .find_map(|l| l.strip_prefix(&key)?.parse().ok())
        .unwrap_or_else(|| panic!("no {kind} series in:\n{rendered}"))
}

/// Every kind's count, in label order: auth, request, internal, backend.
fn all(rendered: &str) -> [u64; 4] {
    ["auth", "request", "internal", "backend"].map(|k| errors(rendered, k))
}

/// A `POST /` route returning `make()` behind the error layer.
fn app<F>(make: F) -> Router
where
    F: Fn() -> axum::response::Response + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", post(move || async move { make() }))
        .layer(from_fn(error_layer))
}

async fn hit(route: Router) -> StatusCode {
    let request = Request::post("/").body(Body::empty()).expect("request");
    route.oneshot(request).await.expect("answer").status()
}

#[test]
fn every_kind_is_registered_at_zero_with_its_help_text() {
    let ((), text) = counted(async {});
    assert_eq!(all(&text), [0, 0, 0, 0]);
    assert!(text.contains("client-received"), "{text}");
}

#[test]
fn a_200_with_a_rpc_error_from_build_response_counts_by_its_code() {
    let (_, text) = counted(hit(app(|| {
        let frame = JsonRpcResponse::error(None, -32601, "no such method");
        build_response(frame, "", StatusCode::OK)
    })));
    assert_eq!(all(&text), [0, 1, 0, 0]);
}

#[test]
fn a_200_with_a_rpc_error_from_build_error_response_counts_by_its_code() {
    let (_, text) = counted(hit(app(|| {
        build_error_response(None, -32603, "broke", "", StatusCode::OK)
    })));
    assert_eq!(all(&text), [0, 0, 1, 0]);
}

#[test]
fn a_backend_frame_counts_as_the_backends_whatever_its_code() {
    let (_, text) = counted(hit(app(|| {
        let mut frame = JsonRpcResponse::error(None, -32603, "backend broke");
        frame.wire_meta.from_backend = true;
        to_http(
            OutboundFrame::unjudged(Payload::Response(frame)),
            StatusCode::OK,
            "",
        )
    })));
    assert_eq!(all(&text), [0, 0, 0, 1]);
}

#[test]
fn the_gateways_own_internal_error_counts_as_internal() {
    let (_, text) = counted(hit(app(|| {
        let frame = JsonRpcResponse::error(None, -32603, "gateway broke");
        to_http(
            OutboundFrame::unjudged(Payload::Response(frame)),
            StatusCode::OK,
            "",
        )
    })));
    assert_eq!(all(&text), [0, 0, 1, 0]);
}

#[test]
fn a_replacement_carries_no_marker_from_the_answer_it_replaced() {
    let (_, text) = counted(hit(app(|| {
        let mut replaced = build_error_response(None, -32602, "bad", "", StatusCode::OK);
        let mut success = (StatusCode::OK, "fine").into_response();
        crate::gateway::outbound::carry_record(&mut replaced, &mut success);
        success
    })));
    assert_eq!(all(&text), [0, 0, 0, 0], "counted by the final answer");
}

#[test]
fn an_error_replacing_a_success_is_counted() {
    let (_, text) = counted(hit(app(|| {
        let success = JsonRpcResponse::success(crate::protocol::RequestId::Number(1), json!({}));
        let mut first = to_http(
            OutboundFrame::unjudged(Payload::Response(success)),
            StatusCode::OK,
            "",
        );
        let mut second = build_error_response(None, -32602, "bad", "", StatusCode::OK);
        crate::gateway::outbound::carry_record(&mut first, &mut second);
        second
    })));
    assert_eq!(all(&text), [0, 1, 0, 0]);
}

const KEY: &str = "k-std";

#[test]
fn a_request_with_no_credential_counts_as_auth() {
    let (status, text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let request = Request::post("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string(),
            ))
            .expect("request");
        fx.router
            .clone()
            .oneshot(request)
            .await
            .expect("answer")
            .status()
    });
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(all(&text), [1, 0, 0, 0]);
}

#[cfg(feature = "webui")]
#[test]
fn a_standard_key_on_an_admin_route_counts_as_auth() {
    let (status, text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let request = Request::get("/ui/api/gateway")
            .header("authorization", format!("Bearer {KEY}"))
            .body(Body::empty())
            .expect("request");
        fx.router
            .clone()
            .oneshot(request)
            .await
            .expect("answer")
            .status()
    });
    assert!(matches!(status.as_u16(), 401 | 403), "{status}");
    assert_eq!(all(&text), [1, 0, 0, 0]);
}

#[test]
fn an_unknown_method_on_mcp_counts_as_request() {
    let (_, text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        send(&fx, "/mcp", KEY, "no/such/method", json!({}), None).await
    });
    assert_eq!(all(&text), [0, 1, 0, 0]);
}

#[test]
fn a_direct_route_early_refusal_counts_by_its_code() {
    let (status, text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let request = Request::post("/mcp/alpha")
            .header("authorization", format!("Bearer {KEY}"))
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .expect("request");
        fx.router
            .clone()
            .oneshot(request)
            .await
            .expect("answer")
            .status()
    });
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(all(&text), [0, 1, 0, 0]);
}

#[test]
fn a_backends_verbatim_internal_error_on_the_direct_route_counts_as_backend() {
    let (_, text) = counted(async {
        let fx = fixture(Answer::RpcError(-32603), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(all(&text), [0, 0, 0, 1]);
}

#[test]
fn a_backend_timeout_counts_as_backend_not_internal() {
    let (_, text) = counted(async {
        let fx = fixture(
            Answer::FailsWith(|| crate::Error::BackendTimeout("alpha".to_string())),
            |_| {},
        )
        .await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(all(&text), [0, 0, 0, 1]);
}

#[test]
fn a_gateway_refusal_on_the_direct_route_counts_by_its_code() {
    let ((status, body), text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        post_direct(&fx, "alpha", "k-deny", "read", json!({}), None, None).await
    });
    let code = body["error"]["code"].as_i64().expect("a refusal code");
    let marker = RpcError {
        code: i32::try_from(code).expect("a code"),
        origin: Origin::Gateway,
    };
    let want = error_kind(status.as_u16(), Some(marker)).expect("a refusal is an error");
    let counts = all(&text);
    assert_eq!(counts.iter().sum::<u64>(), 1, "{counts:?}");
    assert_eq!(
        errors(&text, want.label()),
        1,
        "{counts:?}: {status} {code}"
    );
}

#[test]
fn a_successful_call_counts_no_error() {
    let (_, text) = counted(async {
        let fx = fixture(Answer::Ok, |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(all(&text), [0, 0, 0, 0]);
}

mod streams {
    use std::sync::Arc;

    use super::*;
    use crate::gateway::outbound::{RejectionAudit, StreamJudge};
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

    /// A notification-first stream whose dispatch resolves to `answer`.
    async fn open(answer: Response) -> Response {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(note()).await.expect("sink open");
        first_event_wins_stream(async move { answer }, rx, judge()).await
    }

    async fn read_all(response: Response) {
        let mut body = response.into_body().into_data_stream();
        while futures::StreamExt::next(&mut body).await.is_some() {}
    }

    #[test]
    fn a_stream_ending_in_an_error_counts_it_once() {
        let (_, text) = counted(async {
            let answer = build_error_response(None, -32602, "bad", "", StatusCode::OK);
            read_all(open(answer).await).await;
        });
        assert_eq!(all(&text), [0, 1, 0, 0]);
    }

    #[test]
    fn a_substituted_terminal_frame_counts_as_internal() {
        let (_, text) = counted(async {
            let unframeable = (StatusCode::OK, "plain text, not json").into_response();
            read_all(open(unframeable).await).await;
        });
        assert_eq!(all(&text), [0, 0, 1, 0]);
    }

    #[test]
    fn a_stream_dropped_before_its_terminal_event_counts_no_error() {
        let (_, text) = counted(async {
            let answer = build_error_response(None, -32602, "bad", "", StatusCode::OK);
            drop(open(answer).await);
        });
        assert_eq!(all(&text), [0, 0, 0, 0]);
    }

    #[test]
    fn the_error_layer_leaves_a_stream_to_count_its_own() {
        let (_, text) = counted(async {
            let route = Router::new()
                .route(
                    "/",
                    post(|| async {
                        let answer = build_error_response(None, -32602, "bad", "", StatusCode::OK);
                        open(answer).await
                    }),
                )
                .layer(from_fn(error_layer));
            let request = Request::post("/").body(Body::empty()).expect("request");
            let response = route.oneshot(request).await.expect("answer");
            read_all(response).await;
        });
        assert_eq!(all(&text), [0, 1, 0, 0], "once, not twice");
    }

    #[test]
    fn a_buffered_event_stream_keeps_the_marker() {
        let (kept, _) = counted(async {
            let answer = build_error_response(None, -32602, "bad", "", StatusCode::OK);
            let response =
                crate::gateway::streaming::request_scoped_event_stream(answer, Vec::new(), judge())
                    .await;
            response.extensions().get::<RpcError>().is_some()
        });
        assert!(kept);
    }
}
