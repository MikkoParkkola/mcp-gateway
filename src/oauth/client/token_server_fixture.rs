// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A token endpoint that rotates refresh tokens and revokes the grant on any
//! reuse, the way an authorization server following RFC 9700 section 4.14.2
//! may. Shared by the MCP (MIK-8018) and capability (MIK-8020) refresh tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How the token server answers the next refresh request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Rotate and answer at once.
    Rotate,
    /// Rotate, then hold the answer until the test releases it.
    HoldThenRotate,
    /// Rotate, then answer 502 as a proxy in front of it would.
    RotateThen502,
    /// Rotate, then send a 200 whose body breaks off.
    RotateThenBrokenBody,
    /// Rotate, then redirect to a port nobody listens on.
    RotateThenRedirect,
    /// Rotate, then redirect to an endpoint that answers an OAuth refusal.
    RotateThenRedirectToRefusal,
    /// Answer with the refresh token sent, as a non-rotating server does;
    /// reusing it is allowed.
    Keep,
    /// As `Keep`, then send a 200 whose body breaks off.
    KeepThenBrokenBody,
}

/// A rotating token server that records every refresh it is sent.
pub(crate) struct TokenServer {
    pub(crate) base: String,
    /// The refresh token of every refresh request, in arrival order.
    pub(crate) sent: Mutex<Vec<String>>,
    /// The client id of every refresh request, in arrival order.
    pub(crate) client_ids: Mutex<Vec<String>>,
    /// The `User-Agent` of every refresh request, in arrival order.
    pub(crate) agents: Mutex<Vec<String>>,
    /// Refresh tokens already consumed; a second use revokes the grant.
    pub(crate) consumed: Mutex<Vec<String>>,
    pub(crate) revoked: AtomicBool,
    pub(crate) generation: AtomicUsize,
    pub(crate) answers: Mutex<Vec<Answer>>,
    pub(crate) arrived: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

impl TokenServer {
    /// Start one; `answers` are used in order, then `Rotate`.
    pub(crate) async fn start(answers: &[Answer]) -> Arc<Self> {
        use axum::{Form, Router, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Arc::new(Self {
            base: format!("http://{}", listener.local_addr().unwrap()),
            sent: Mutex::default(),
            client_ids: Mutex::default(),
            agents: Mutex::default(),
            consumed: Mutex::default(),
            revoked: AtomicBool::new(false),
            generation: AtomicUsize::new(1),
            answers: Mutex::new(answers.iter().rev().copied().collect()),
            arrived: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let handler = Arc::clone(&server);
        let refusal = || async {
            let body = serde_json::json!({ "error": "invalid_request" });
            (axum::http::StatusCode::BAD_REQUEST, axum::Json(body))
        };
        let app = Router::new().route("/refused", post(refusal)).route(
            "/token",
            post(
                move |headers: axum::http::HeaderMap, Form(form): Form<HashMap<String, String>>| {
                    let server = Arc::clone(&handler);
                    let agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
                    server
                        .agents
                        .lock()
                        .unwrap()
                        .push(agent.unwrap_or_default().to_string());
                    async move { server.answer(&form).await }
                },
            ),
        );
        tokio::spawn(async move { axum::serve(listener, app).await });
        server
    }

    pub(crate) async fn answer(&self, form: &HashMap<String, String>) -> axum::response::Response {
        use axum::{Json, http::StatusCode, response::IntoResponse};
        let sent = form.get("refresh_token").cloned().unwrap_or_default();
        self.sent.lock().unwrap().push(sent.clone());
        let client_id = form.get("client_id").cloned().unwrap_or_default();
        self.client_ids.lock().unwrap().push(client_id);
        self.arrived.notify_waiters();
        let answer = self.answers.lock().unwrap().pop().unwrap_or(Answer::Rotate);
        let keeps = matches!(answer, Answer::Keep | Answer::KeepThenBrokenBody);
        let reused = !keeps && {
            let mut consumed = self.consumed.lock().unwrap();
            let reused = consumed.contains(&sent);
            consumed.push(sent.clone());
            reused
        };
        if reused {
            self.revoked.store(true, Ordering::SeqCst);
        }
        if reused || self.revoked.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response();
        }
        let n = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let mut body = serde_json::json!({
            "access_token": format!("a{n}"),
            "token_type": "Bearer",
            "expires_in": 3600,
        });
        body["refresh_token"] = serde_json::Value::from(if keeps { sent } else { format!("r{n}") });
        match answer {
            Answer::HoldThenRotate => self.release.notified().await,
            Answer::RotateThen502 => return StatusCode::BAD_GATEWAY.into_response(),
            Answer::RotateThenRedirect => {
                return (
                    StatusCode::TEMPORARY_REDIRECT,
                    [("location", "http://127.0.0.1:1/token")],
                )
                    .into_response();
            }
            Answer::RotateThenRedirectToRefusal => {
                let location = format!("{}/refused", self.base);
                return (StatusCode::TEMPORARY_REDIRECT, [("location", location)]).into_response();
            }
            Answer::RotateThenBrokenBody | Answer::KeepThenBrokenBody => {
                let broken = futures::stream::iter([
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"{\"access_token\":")),
                    Err(std::io::Error::other("connection lost")),
                ]);
                return axum::response::Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from_stream(broken))
                    .unwrap();
            }
            Answer::Rotate | Answer::Keep => {}
        }
        Json(body).into_response()
    }

    /// How many refresh requests carried `token`.
    pub(crate) fn uses(&self, token: &str) -> usize {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|t| *t == token)
            .count()
    }

    pub(crate) fn requests(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Wait until `n` refresh requests have arrived, or `within` passes.
    pub(crate) async fn arrivals(&self, n: usize, within: Duration) {
        let _ = tokio::time::timeout(within, async {
            while self.requests() < n {
                self.arrived.notified().await;
            }
        })
        .await;
    }
}
