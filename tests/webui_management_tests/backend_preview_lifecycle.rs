// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The preview's one-at-a-time guard and its teardown: who may start while a
//! preview runs, and that every exit, a disconnect and the 30 s cap
//! included, tears the server down before the guard is freed.

use super::{
    ADMIN_TOKEN, Arc, Body, Bytes, IntoResponse, Log, Method, StatusCode, Value, answer, confirmed,
    json, preview_as, router_with, serve, stub,
};

/// The request a [`hanging_stub`] never finishes answering.
#[derive(Clone, Copy)]
enum Hang {
    Initialize,
    ToolsList,
}

/// A stub whose `hang` request gets a body that never ends. The signal fires
/// when that request arrives, so a test knows where the preview is (and that
/// it holds the guard) without a timer; each stub has its own, so tests that
/// run in parallel never wake each other.
async fn hanging_stub(log: &Log, hang: Hang) -> (String, Arc<tokio::sync::Notify>) {
    let arrived = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&arrived);
    let method = match hang {
        Hang::Initialize => "initialize",
        Hang::ToolsList => "tools/list",
    };
    let url = serve(log, move |request: &Value| {
        if request.get("method").and_then(Value::as_str) != Some(method) {
            return answer(request);
        }
        signal.notify_one();
        (
            [("content-type", "application/json")],
            Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>()),
        )
            .into_response()
    })
    .await;
    (url, arrived)
}

/// T13: a failed redeem frees the busy guard at once.
#[tokio::test]
async fn a_failed_redeem_frees_the_guard_for_the_next_preview() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let body = json!({"name": "stub", "url": url, "confirm": "not-a-token"});
    let (status, answer) = preview_as(&router, Some(ADMIN_TOKEN), &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    let (status, answer) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the next preview is admitted: {answer}"
    );
}

/// T8b: a client that disconnects mid-preview does not end it: the guard
/// stays held (409) until the preview's own cap and teardown are done, and
/// the next preview is admitted only then.
#[tokio::test]
async fn a_disconnected_preview_keeps_the_guard_until_teardown() {
    let log = Log::default();
    let (hanging, arrived) = hanging_stub(&log, Hang::ToolsList).await;
    let (router, _store) = router_with(false).await;
    // The first preview is dropped, as a disconnect drops it, once the
    // server has been asked for its tools.
    let slow = json!({"name": "slow", "url": hanging});
    tokio::select! {
        (status, body) = confirmed(&router, &slow) => {
            panic!("the hanging preview answered: {status} {body}");
        }
        () = arrived.notified() => {}
    }
    let url = stub(&log).await;
    let next = json!({"name": "stub", "url": url});
    let (status, described) = preview_as(&router, Some(ADMIN_TOKEN), &next).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{described}");
    let mut next = next;
    next["confirm"] = described["confirm"].clone();
    let (status, body) = preview_as(&router, Some(ADMIN_TOKEN), &next).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "still running after the disconnect: {body}"
    );
    // A busy answer leaves the token unspent: retry until the first
    // preview's 30 s cap and its teardown have released the guard.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let (status, body) = preview_as(&router, Some(ADMIN_TOKEN), &next).await;
        if status == StatusCode::OK {
            break;
        }
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            std::time::Instant::now() < deadline,
            "the guard was never released"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// T4b: a listing cut off by the 30 s cap still tears its session down
/// (DELETE) before the 504 is sent.
#[tokio::test]
async fn a_capped_preview_tears_its_session_down_before_the_504() {
    let log = Log::default();
    let url = serve(&log, |request: &Value| {
        match request.get("method").and_then(Value::as_str) {
            Some("initialize") => {
                let mut response = answer(request);
                response
                    .headers_mut()
                    .insert("mcp-session-id", "s-1".parse().unwrap());
                response
            }
            Some("tools/list") => (
                [("content-type", "application/json")],
                Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>()),
            )
                .into_response(),
            _ => answer(request),
        }
    })
    .await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "capped", "url": url})).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    let deleted = log
        .lock()
        .unwrap()
        .iter()
        .any(|seen| seen.method == Method::DELETE);
    assert!(deleted, "no session teardown before the 504");
}

/// T8: a second confirmed preview while one runs is 409, and its token is
/// not spent: it is accepted once the first has gone.
#[tokio::test]
async fn a_second_preview_while_one_runs_is_refused_unspent() {
    let log = Log::default();
    let (hanging, arrived) = hanging_stub(&log, Hang::ToolsList).await;
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let second = json!({"name": "stub", "url": url});
    let (status, described) = preview_as(&router, Some(ADMIN_TOKEN), &second).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{described}");
    let mut second = second;
    second["confirm"] = described["confirm"].clone();
    let slow = json!({"name": "slow", "url": hanging});
    tokio::select! {
        (status, body) = confirmed(&router, &slow) => {
            panic!("the hanging preview answered: {status} {body}");
        }
        () = async {
            arrived.notified().await;
            let (status, body) = preview_as(&router, Some(ADMIN_TOKEN), &second).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            assert_eq!(body["error"], "a preview is already running");
        } => {}
    }
    let (status, body) = preview_as(&router, Some(ADMIN_TOKEN), &second).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the unspent token still works: {body}"
    );
}

/// T4: a server that never answers is a 504 at the 30 s cap, and the guard
/// is free for the next preview straight after.
#[tokio::test]
async fn an_unanswering_server_is_a_504_and_frees_the_guard() {
    let log = Log::default();
    let (silent, _arrived) = hanging_stub(&log, Hang::Initialize).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "silent", "url": silent})).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    let url = stub(&log).await;
    let (status, body) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "admitted after the 504: {body}");
}
