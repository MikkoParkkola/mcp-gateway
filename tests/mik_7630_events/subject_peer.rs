// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A legacy-era HTTP MCP backend that tells its callers apart.
//!
//! Each request names its caller by the subject of the bearer it carries: the
//! `sub` claim of a JWT (a gateway-signed assertion), or the part after `at.`
//! (an opaque token issued for that subject). A request with no bearer is
//! the gateway's own, subject `""`. Every subject has its own session, its own
//! catalogue (one tool and one resource named after it), its own legacy
//! subscriptions and its own GET streams, and a test pushes a notification to
//! one subject's streams only. The peer records which subject every request
//! carried, so a test can assert that no request for one user ever went out
//! as anyone else.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// One request the peer saw: the subject it carried and what it was.
#[derive(Debug, Clone)]
pub struct Request {
    pub subject: String,
    /// The JSON-RPC method, or `GET` for a stream.
    pub method: String,
}

#[derive(Default)]
struct Inner {
    seen: Vec<Request>,
    streams: Vec<(String, mpsc::UnboundedSender<String>)>,
    subscribed: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Default)]
struct State(Arc<Mutex<Inner>>);

impl State {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.0.lock().expect("subject peer"))
    }
}

/// The subject a bearer names, or `""` for none.
pub fn subject_of(headers: &HeaderMap) -> String {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return String::new();
    };
    if let Some(subject) = token.strip_prefix("at.") {
        return subject.to_owned();
    }
    token
        .split('.')
        .nth(1)
        .and_then(|claims| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| claims["sub"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unreadable>".to_owned())
}

/// The URI of the one resource `subject` sees.
pub fn resource_of(subject: &str) -> String {
    format!("file:///{subject}")
}

/// A per-subject legacy HTTP MCP backend.
pub struct SubjectPeer {
    pub url: String,
    state: State,
}

impl SubjectPeer {
    pub async fn start() -> Self {
        let state = State::default();
        let (post_state, get_state) = (state.clone(), state.clone());
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(
                move |headers: HeaderMap, axum::Json(frame): axum::Json<Value>| {
                    let state = post_state.clone();
                    async move { answer(&state, &subject_of(&headers), &frame) }
                },
            )
            .get(move |headers: HeaderMap| {
                let state = get_state.clone();
                async move { stream(&state, subject_of(&headers)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind subject peer");
        let url = format!("http://{}/", listener.local_addr().expect("peer address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state }
    }

    /// Every request so far, in arrival order.
    pub fn seen(&self) -> Vec<Request> {
        self.state.with(|s| s.seen.clone())
    }

    /// GET streams `subject` holds open.
    pub fn open_streams(&self, subject: &str) -> usize {
        self.state.with(|s| {
            s.streams.retain(|(_, tx)| !tx.is_closed());
            s.streams.iter().filter(|(who, _)| who == subject).count()
        })
    }

    /// Send `method` to `subject`'s open streams only, as the backend would
    /// when that user's view changed. A resource update goes only where that
    /// subject subscribed to the URI.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline with json!"
    )]
    pub fn push_to(&self, subject: &str, method: &str, params: Value) {
        self.state.with(|s| {
            let subscribed = s.subscribed.get(subject).cloned().unwrap_or_default();
            if method == "notifications/resources/updated"
                && !subscribed.iter().any(|u| params["uri"] == *u)
            {
                return;
            }
            let frame = json!({"jsonrpc": "2.0", "method": method, "params": params});
            for (who, tx) in &s.streams {
                if who == subject {
                    let _ = tx.send(frame.to_string());
                }
            }
        });
    }
}

fn reply(id: &Value, result: &Value) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

fn answer(state: &State, subject: &str, frame: &Value) -> Response {
    let method = frame["method"].as_str().unwrap_or_default().to_owned();
    state.with(|s| {
        s.seen.push(Request {
            subject: subject.to_owned(),
            method: method.clone(),
        });
    });
    let Some(id) = frame.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    match method.as_str() {
        "initialize" => {
            let mut response = reply(
                &id,
                &json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "resources": {"subscribe": true, "listChanged": true},
                        "tools": {"listChanged": true},
                    },
                    "serverInfo": {"name": "subject-peer", "version": "0"},
                }),
            );
            let session = format!("session-{subject}");
            if let Ok(value) = session.parse() {
                response.headers_mut().insert("mcp-session-id", value);
            }
            response
        }
        "tools/list" => reply(
            &id,
            &json!({"tools": [{"name": format!("tool_{subject}"),
                               "inputSchema": {"type": "object"}}]}),
        ),
        "resources/list" => reply(
            &id,
            &json!({"resources": [{"uri": resource_of(subject), "name": subject}]}),
        ),
        "resources/subscribe" | "resources/unsubscribe" => {
            let uri = frame["params"]["uri"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            state.with(|s| {
                let mine = s.subscribed.entry(subject.to_owned()).or_default();
                mine.retain(|u| *u != uri);
                if method == "resources/subscribe" {
                    mine.push(uri);
                }
            });
            reply(&id, &json!({}))
        }
        "prompts/list" => reply(&id, &json!({"prompts": []})),
        "ping" => reply(&id, &json!({})),
        _ => axum::Json(json!({"jsonrpc": "2.0", "id": id,
                               "error": {"code": -32601, "message": "not found"}}))
        .into_response(),
    }
}

fn stream(state: &State, subject: String) -> Response {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    state.with(|s| {
        s.seen.push(Request {
            subject: subject.clone(),
            method: "GET".to_owned(),
        });
        s.streams.push((subject, tx));
    });
    let body = async_stream::stream! {
        while let Some(frame) = rx.recv().await {
            yield Ok::<_, std::io::Error>(format!("event: message\ndata: {frame}\n\n"));
        }
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}
