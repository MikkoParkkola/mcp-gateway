// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A legacy (2024-11-05) HTTP+SSE MCP peer for the SOURCE.1 P3 rows. Each
//! `GET /sse` opens a session, names it in the `endpoint` event and keeps the
//! stream; `POST /messages?session_id=<n>` is answered 202 with the response
//! on that session's stream, as the spec transport does. Session 1 is the
//! gateway's calls session, whose path reads only the POST body, so it is
//! answered in the body; `answer_in_body` makes every session answer so.
//! Each answer on a stream follows a wrong-id error, so a reader that takes
//! the next response instead of its own fails.
//! A session refuses `resources/subscribe` before its
//! `notifications/initialized`, and every request is recorded in order.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::mpsc;

pub const URI_A: &str = "file:///a";
pub const URI_B: &str = "file:///b";

/// What the peer saw, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Get {
        session: u32,
    },
    GetClosed {
        session: u32,
    },
    Post {
        session: u32,
        method: String,
        cred: Option<String>,
    },
}

#[derive(Default)]
struct Session {
    tx: Option<mpsc::UnboundedSender<String>>,
    initialized: bool,
    subscribed: BTreeSet<String>,
}

#[derive(Clone, Default)]
struct State {
    seen: Arc<Mutex<Vec<Seen>>>,
    sessions: Arc<Mutex<BTreeMap<u32, Session>>>,
    answer_in_body: Arc<AtomicBool>,
    /// An `endpoint` value replacing the session's own message path.
    endpoint_override: Arc<Mutex<Option<String>>>,
}

pub struct SsePeer {
    /// The SSE URL, `http://127.0.0.1:<port>/sse`.
    pub url: String,
    state: State,
}

impl SsePeer {
    pub async fn start() -> Self {
        let state = State::default();
        let (get_state, post_state) = (state.clone(), state.clone());
        let app = axum::Router::new()
            .route(
                "/sse",
                axum::routing::get(move || {
                    let state = get_state.clone();
                    async move { open(&state) }
                }),
            )
            .route(
                "/messages",
                axum::routing::post(
                    move |Query(q): Query<BTreeMap<String, String>>,
                          headers: HeaderMap,
                          axum::Json(frame): axum::Json<Value>| {
                        let state = post_state.clone();
                        async move { message(&state, &q, &headers, frame) }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sse peer");
        let url = format!("http://{}/sse", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state }
    }

    pub fn answer_in_body(&self) {
        self.state.answer_in_body.store(true, Ordering::SeqCst);
    }

    /// Name `endpoint` in every later `endpoint` event after session 1's,
    /// instead of the session's own path.
    pub fn send_endpoint(&self, endpoint: &str) {
        *self.state.endpoint_override.lock().expect("override") = Some(endpoint.to_owned());
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().expect("seen").clone()
    }

    /// The methods POSTed on `session`, in order.
    pub fn methods_on(&self, session: u32) -> Vec<String> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Post {
                    session: n, method, ..
                } if n == session => Some(method),
                _ => None,
            })
            .collect()
    }

    /// The sessions on which `uri` is subscribed now.
    pub fn subscribed_on(&self, uri: &str) -> Vec<u32> {
        let sessions = self.state.sessions.lock().expect("sessions");
        sessions
            .iter()
            .filter(|(_, s)| s.subscribed.contains(uri))
            .map(|(n, _)| *n)
            .collect()
    }

    /// Sessions whose GET stream is open now.
    pub fn open_sessions(&self) -> Vec<u32> {
        let sessions = self.state.sessions.lock().expect("sessions");
        sessions
            .iter()
            .filter(|(_, s)| s.tx.as_ref().is_some_and(|tx| !tx.is_closed()))
            .map(|(n, _)| *n)
            .collect()
    }

    /// Send a notification on `session`'s stream.
    pub fn push(&self, session: u32, method: &str, params: Value) {
        let frame = json!({"jsonrpc": "2.0", "method": method, "params": params});
        send(&self.state, session, &frame);
    }

    /// End `session`'s stream, as a peer restart would.
    pub fn drop_stream(&self, session: u32) {
        if let Some(s) = self
            .state
            .sessions
            .lock()
            .expect("sessions")
            .get_mut(&session)
        {
            s.tx = None;
        }
    }
}

fn log(state: &State, seen: Seen) {
    state.seen.lock().expect("seen").push(seen);
}

fn send(state: &State, session: u32, frame: &Value) {
    let sessions = state.sessions.lock().expect("sessions");
    if let Some(tx) = sessions.get(&session).and_then(|s| s.tx.as_ref()) {
        let _ = tx.send(frame.to_string());
    }
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// `GET /sse`: a new session, named in the `endpoint` event, held open.
fn open(state: &State) -> Response {
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let session = {
        let mut sessions = state.sessions.lock().expect("sessions");
        let n = sessions.keys().next_back().map_or(1, |n| n + 1);
        sessions.insert(
            n,
            Session {
                tx: Some(tx),
                ..Session::default()
            },
        );
        n
    };
    log(state, Seen::Get { session });
    let endpoint = state
        .endpoint_override
        .lock()
        .expect("override")
        .clone()
        .filter(|_| session > 1)
        .unwrap_or_else(|| format!("/messages?session_id={session}"));
    let closed = state.clone();
    let body = async_stream::stream! {
        let _guard = OnDrop(move || log(&closed, Seen::GetClosed { session }));
        let mut rx = rx;
        yield Ok::<_, std::io::Error>(format!("event: endpoint\ndata: {endpoint}\n\n"));
        while let Some(frame) = rx.recv().await {
            yield Ok(format!("event: message\ndata: {frame}\n\n"));
        }
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

/// `POST /messages`: a notification is 202; a request's response goes on
/// the session's stream (202 here), or in the body for session 1 and
/// under `answer_in_body`.
fn message(
    state: &State,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    frame: Value,
) -> Response {
    let Some(session) = query.get("session_id").and_then(|s| s.parse::<u32>().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let method = frame["method"].as_str().unwrap_or_default().to_owned();
    let cred = headers
        .get("x-listener-cred")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    log(
        state,
        Seen::Post {
            session,
            method: method.clone(),
            cred,
        },
    );
    let Some(id) = frame.get("id").cloned() else {
        if method == "notifications/initialized"
            && let Some(s) = state.sessions.lock().expect("sessions").get_mut(&session)
        {
            s.initialized = true;
        }
        return StatusCode::ACCEPTED.into_response();
    };
    let response = match outcome(state, session, &method, &frame["params"]) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        }
    };
    if session == 1 || state.answer_in_body.load(Ordering::SeqCst) {
        return axum::Json(response).into_response();
    }
    // A wrong-id error first: only a listener that pairs by id ignores it.
    let decoy =
        json!({"jsonrpc": "2.0", "id": "decoy", "error": {"code": -32603, "message": "not yours"}});
    send(state, session, &decoy);
    send(state, session, &response);
    StatusCode::ACCEPTED.into_response()
}

fn outcome(
    state: &State,
    session: u32,
    method: &str,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let mut sessions = state.sessions.lock().expect("sessions");
    let Some(s) = sessions.get_mut(&session) else {
        return Err((-32001, "no such session".to_owned()));
    };
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "resources": {"subscribe": true, "listChanged": true},
                "prompts": {"listChanged": true},
                "tools": {"listChanged": true},
            },
            "serverInfo": {"name": "sse-peer", "version": "1"},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]})),
        "resources/list" => Ok(json!({"resources": [
            {"uri": URI_A, "name": "a"},
            {"uri": URI_B, "name": "b"},
        ]})),
        "prompts/list" => Ok(json!({"prompts": []})),
        "resources/subscribe" | "resources/unsubscribe" => {
            if !s.initialized {
                return Err((-32600, "not initialized".to_owned()));
            }
            let uri = params["uri"].as_str().unwrap_or_default().to_owned();
            if method == "resources/subscribe" {
                s.subscribed.insert(uri);
            } else {
                s.subscribed.remove(&uri);
            }
            Ok(json!({}))
        }
        _ => Err((-32601, format!("no method {method}"))),
    }
}
