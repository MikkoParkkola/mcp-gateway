// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Mock MCP backends for the I5 upstream-listener rows (T39): an HTTP peer
//! in either era and a stdio peer script. Each records what it receives and
//! lets a row push a notification as the backend would.

use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// The resources every peer lists.
pub const URI_A: &str = "file:///a";
pub const URI_B: &str = "file:///b";
pub const URI_SECRET: &str = "file:///secret";

/// Which revision a peer speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// 2026-07-28: `server/discover`, `subscriptions/listen`.
    Modern,
    /// 2025-06-18: `initialize`, `resources/subscribe`, session GET stream.
    Legacy,
}

/// One thing the peer saw, in arrival order.
#[derive(Debug, Clone)]
pub enum Seen {
    /// A posted JSON-RPC frame.
    Frame(Value),
    /// A `subscriptions/listen` stream opened (its id and filter).
    ListenOpen { id: Value, filter: Value },
    /// Its acknowledgement was written.
    ListenAcked { id: Value },
    /// Its body was dropped by the client.
    ListenClosed { id: Value },
    /// A legacy GET stream opened on `session`.
    GetOpen { session: Option<String> },
    /// A legacy GET stream was dropped by the client.
    GetClosed,
}

struct Stream {
    /// `Some` for a listen stream, `None` for a legacy GET.
    id: Option<Value>,
    filter: Value,
    tx: mpsc::UnboundedSender<String>,
}

#[derive(Clone)]
struct State {
    era: Era,
    seen: Arc<Mutex<Vec<Seen>>>,
    streams: Arc<Mutex<Vec<Stream>>>,
    subscribed: Arc<Mutex<Vec<String>>>,
    /// While set, `tools/list` answers only after a minute (MIK-7937).
    hang_tools: Arc<std::sync::atomic::AtomicBool>,
    /// Once set, the peer is a legacy HTTP+SSE server behind the same URL
    /// (see [`HttpPeer::redeploy_as_sse`]).
    sse: Arc<std::sync::atomic::AtomicBool>,
    /// SSE handshakes (`GET` naming the message endpoint) served since then.
    sse_handshakes: Arc<std::sync::atomic::AtomicUsize>,
}

/// Runs `f` when dropped: how the peer learns a client let go of a body.
struct OnDrop<F: FnMut()>(F);
impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

const SESSION: &str = "peer-session-1";

/// An HTTP MCP backend in one era.
pub struct HttpPeer {
    pub url: String,
    state: State,
}

impl HttpPeer {
    pub async fn start(era: Era) -> Self {
        let state = State {
            era,
            seen: Arc::default(),
            streams: Arc::default(),
            subscribed: Arc::default(),
            hang_tools: Arc::default(),
            sse: Arc::default(),
            sse_handshakes: Arc::default(),
        };
        let post_state = state.clone();
        let get_state = state.clone();
        let messages_state = state.clone();
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::post(move |axum::Json(frame): axum::Json<Value>| {
                    let state = post_state.clone();
                    async move {
                        if state.sse.load(std::sync::atomic::Ordering::SeqCst) {
                            log(&state, Seen::Frame(frame.clone()));
                            return redeployed_post(&frame);
                        }
                        if frame["method"] == "tools/list"
                            && state.hang_tools.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            // Logged on arrival, so a test sees the request it is
                            // holding; the answer, a minute later or on release,
                            // is logged too.
                            log(&state, Seen::Frame(frame.clone()));
                            let held = std::time::Instant::now();
                            while state.hang_tools.load(std::sync::atomic::Ordering::SeqCst)
                                && held.elapsed() < std::time::Duration::from_secs(60)
                            {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                        }
                        answer(&state, frame)
                    }
                })
                .get(move |headers: HeaderMap| {
                    let state = get_state.clone();
                    async move {
                        if state.sse.load(std::sync::atomic::Ordering::SeqCst) {
                            return sse_handshake(&state);
                        }
                        get_stream(&state, &headers)
                    }
                }),
            )
            .route(
                "/messages",
                axum::routing::post(move |axum::Json(frame): axum::Json<Value>| {
                    let state = messages_state.clone();
                    async move { answer(&state, frame) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind peer");
        let url = format!("http://{}/", listener.local_addr().expect("peer address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state }
    }

    /// Everything seen so far, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().expect("peer log").clone()
    }

    /// Posted frames whose method is `method`.
    pub fn frames(&self, method: &str) -> Vec<Value> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Frame(f) if f["method"] == method => Some(f),
                _ => None,
            })
            .collect()
    }

    /// Filters of listen streams the client still holds open.
    pub fn open_listens(&self) -> Vec<Value> {
        self.live()
            .into_iter()
            .filter_map(|(id, filter)| id.map(|_| filter))
            .collect()
    }

    /// Legacy GET streams the client still holds open.
    pub fn open_gets(&self) -> usize {
        self.live().iter().filter(|(id, _)| id.is_none()).count()
    }

    /// From now on, answer `tools/list` only after a minute.
    pub fn hang_tools_list(&self) {
        self.state
            .hang_tools
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Answer the held `tools/list` now, and every later one at once.
    pub fn release_tools_list(&self) {
        self.state
            .hang_tools
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Redeploy as a legacy HTTP+SSE server behind the same URL, leaving
    /// open streams open and quiet: every later `POST /` answers 404 (the
    /// session is gone) or, for `initialize`, 405, so a client's session
    /// recovery falls back to SSE, whose `GET /` names `/messages`.
    pub fn redeploy_as_sse(&self) {
        self.state
            .sse
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// SSE handshakes served since [`Self::redeploy_as_sse`].
    pub fn sse_handshakes(&self) -> usize {
        self.state
            .sse_handshakes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// URIs the client is subscribed to (legacy).
    pub fn subscribed(&self) -> Vec<String> {
        self.state.subscribed.lock().expect("peer subs").clone()
    }

    fn live(&self) -> Vec<(Option<Value>, Value)> {
        let mut streams = self.state.streams.lock().expect("peer streams");
        streams.retain(|s| !s.tx.is_closed());
        streams
            .iter()
            .map(|s| (s.id.clone(), s.filter.clone()))
            .collect()
    }

    /// Send `method` as the backend would: on every open listen that asked
    /// for it (tagged), or on every open GET (legacy; resource updates only
    /// for subscribed URIs).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline with json!"
    )]
    pub fn push(&self, method: &str, params: Value) {
        let subscribed = self.subscribed();
        for s in self.state.streams.lock().expect("peer streams").iter() {
            let frame = match &s.id {
                Some(id) if wants(&s.filter, method, &params) => tagged(method, &params, id),
                None if method != "notifications/resources/updated"
                    || subscribed.iter().any(|u| params["uri"] == *u) =>
                {
                    json!({"jsonrpc": "2.0", "method": method, "params": params})
                }
                _ => continue,
            };
            let _ = s.tx.send(frame.to_string());
        }
    }

    /// Send `frame` verbatim on every open stream (untagged-frame rows).
    pub fn push_raw(&self, frame: &Value) {
        for s in self.state.streams.lock().expect("peer streams").iter() {
            let _ = s.tx.send(frame.to_string());
        }
    }

    /// End every open stream from the server side, without a response.
    pub fn drop_streams(&self) {
        self.state.streams.lock().expect("peer streams").clear();
    }
}

/// Whether a listen filter asked for this notification.
pub fn wants(filter: &Value, method: &str, params: &Value) -> bool {
    let n = &filter["notifications"];
    match method {
        "notifications/resources/updated" => n["resourceSubscriptions"]
            .as_array()
            .is_some_and(|uris| uris.contains(&params["uri"])),
        "notifications/resources/list_changed" => n["resourcesListChanged"] == true,
        "notifications/prompts/list_changed" => n["promptsListChanged"] == true,
        "notifications/tools/list_changed" => n["toolsListChanged"] == true,
        _ => false,
    }
}

fn tagged(method: &str, params: &Value, id: &Value) -> Value {
    let mut params = params.clone();
    params["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": id});
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

fn log(state: &State, seen: Seen) {
    state.seen.lock().expect("peer log").push(seen);
}

fn sse(
    rx: mpsc::UnboundedReceiver<String>,
    first: Option<String>,
    guard: impl FnMut() + Send + 'static,
) -> Response {
    let body = async_stream::stream! {
        let _guard = OnDrop(guard);
        let mut rx = rx;
        if let Some(first) = first {
            yield Ok::<_, std::io::Error>(format!("event: message\ndata: {first}\n\n"));
        }
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

fn resources() -> Value {
    json!({"resources": [
        {"uri": URI_A, "name": "a"},
        {"uri": URI_B, "name": "b"},
        {"uri": "file:///c", "name": "c"},
    ]})
}

fn capabilities() -> Value {
    json!({
        "resources": {"subscribe": true, "listChanged": true},
        "prompts": {"listChanged": true},
        "tools": {},
    })
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites build the value inline with json!"
)]
fn reply(id: &Value, result: Value) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

fn refuse(id: &Value, code: i64) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": "refused"}}))
        .into_response()
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "axum hands the frame over by value"
)]
fn answer(state: &State, frame: Value) -> Response {
    log(state, Seen::Frame(frame.clone()));
    let id = frame.get("id").cloned().unwrap_or(Value::Null);
    if frame.get("id").is_none() {
        return axum::http::StatusCode::ACCEPTED.into_response();
    }
    let method = frame["method"].as_str().unwrap_or_default();
    let modern = state.era == Era::Modern;
    match method {
        "server/discover" if modern => reply(
            &id,
            json!({
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": capabilities(),
                "serverInfo": {"name": "peer", "version": "0"},
            }),
        ),
        "initialize" => {
            let mut response = reply(
                &id,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": capabilities(),
                    "serverInfo": {"name": "peer", "version": "0"},
                }),
            );
            response
                .headers_mut()
                .insert("mcp-session-id", SESSION.parse().expect("header"));
            response
        }
        "subscriptions/listen"
            if modern
                && frame["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
                    .is_string() =>
        {
            listen(state, &id, &frame)
        }
        "resources/subscribe" | "resources/unsubscribe" if !modern => {
            let uri = frame["params"]["uri"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let mut subs = state.subscribed.lock().expect("peer subs");
            subs.retain(|u| *u != uri);
            if method == "resources/subscribe" {
                subs.push(uri);
            }
            reply(&id, json!({}))
        }
        "resources/list" => reply(&id, resources()),
        "tools/list" => reply(&id, json!({"tools": []})),
        "prompts/list" => reply(&id, json!({"prompts": []})),
        "ping" if !modern => reply(&id, json!({})),
        _ => refuse(&id, -32601),
    }
}

fn listen(state: &State, id: &Value, frame: &Value) -> Response {
    let filter = frame["params"].clone();
    let (tx, rx) = mpsc::unbounded_channel();
    state.streams.lock().expect("peer streams").push(Stream {
        id: Some(id.clone()),
        filter: filter.clone(),
        tx,
    });
    log(
        state,
        Seen::ListenOpen {
            id: id.clone(),
            filter: filter.clone(),
        },
    );
    let mut ack_params = json!({"notifications": filter["notifications"].clone()});
    ack_params["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": id});
    let ack = json!({
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": ack_params,
    });
    log(state, Seen::ListenAcked { id: id.clone() });
    let (closed_state, closed_id) = (state.clone(), id.clone());
    sse(rx, Some(ack.to_string()), move || {
        log(
            &closed_state,
            Seen::ListenClosed {
                id: closed_id.clone(),
            },
        );
    })
}

/// A redeployed peer's answer to a `POST /`: the old session is gone, and a
/// new `initialize` is refused as the wrong transport.
fn redeployed_post(frame: &Value) -> Response {
    if frame["method"] == "initialize" {
        axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response()
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

/// A redeployed peer's `GET /`: the legacy SSE handshake, held open.
fn sse_handshake(state: &State) -> Response {
    state
        .sse_handshakes
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let body = async_stream::stream! {
        yield Ok::<_, std::io::Error>("event: endpoint\ndata: /messages\n\n".to_owned());
        std::future::pending::<()>().await;
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

fn get_stream(state: &State, headers: &HeaderMap) -> Response {
    if state.era == Era::Modern {
        return axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    log(state, Seen::GetOpen { session });
    let (tx, rx) = mpsc::unbounded_channel();
    state.streams.lock().expect("peer streams").push(Stream {
        id: None,
        filter: Value::Null,
        tx,
    });
    let closed_state = state.clone();
    sse(rx, None, move || log(&closed_state, Seen::GetClosed))
}

/// A stdio MCP peer (python3, stdlib only). Argument 1 is `modern` or
/// `legacy`, 2 the frame log, 3 the push directory: a file `*.json` holding
/// `{"method","params"}` dropped there is sent as the backend would (tagged
/// per open listen, or untagged for legacy subscriptions) and then deleted.
pub const STDIO_PEER: &str = r#"
import json, os, select, sys
era, log_path, push_dir = sys.argv[1], sys.argv[2], sys.argv[3]
modern = era == "modern"
listens, subscribed = {}, set()
RES = {"resources": [{"uri": u, "name": u[-1]} for u in ("file:///a", "file:///b", "file:///c")]}
CAPS = {"resources": {"subscribe": True, "listChanged": True}, "prompts": {"listChanged": True}, "tools": {}}
def out(frame):
    sys.stdout.write(json.dumps(frame) + "\n"); sys.stdout.flush()
def log(entry):
    with open(log_path, "a") as f: f.write(json.dumps(entry) + "\n")
def reply(i, result): out({"jsonrpc": "2.0", "id": i, "result": result})
def refuse(i): out({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "refused"}})
def wants(flt, method, params):
    n = flt.get("notifications", {})
    if method == "notifications/resources/updated": return params.get("uri") in n.get("resourceSubscriptions", [])
    key = {"notifications/resources/list_changed": "resourcesListChanged",
           "notifications/prompts/list_changed": "promptsListChanged",
           "notifications/tools/list_changed": "toolsListChanged"}.get(method)
    return bool(key and n.get(key))
def push(method, params):
    if modern:
        for i, flt in listens.items():
            if wants(flt, method, params):
                p = dict(params); p["_meta"] = {"io.modelcontextprotocol/subscriptionId": i}
                out({"jsonrpc": "2.0", "method": method, "params": p})
    elif method != "notifications/resources/updated" or params.get("uri") in subscribed:
        out({"jsonrpc": "2.0", "method": method, "params": params})
def handle(frame):
    log(frame)
    m, i, p = frame.get("method"), frame.get("id"), frame.get("params") or {}
    if i is None:
        if m == "notifications/cancelled":
            listens.pop(p.get("requestId"), None)
        return
    if m == "server/discover" and modern:
        reply(i, {"resultType": "complete", "supportedVersions": ["2026-07-28"], "capabilities": CAPS,
                  "serverInfo": {"name": "peer", "version": "0"}})
    elif m == "initialize":  # the gateway always handshakes a stdio child first
        reply(i, {"protocolVersion": "2025-06-18", "capabilities": CAPS, "serverInfo": {"name": "peer", "version": "0"}})
    elif m == "subscriptions/listen" and modern and "io.modelcontextprotocol/protocolVersion" in p.get("_meta", {}):
        listens[i] = p
        out({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
             "params": {"notifications": p.get("notifications", {}), "_meta": {"io.modelcontextprotocol/subscriptionId": i}}})
    elif m in ("resources/subscribe", "resources/unsubscribe") and not modern:
        (subscribed.add if m == "resources/subscribe" else subscribed.discard)(p.get("uri")); reply(i, {})
    elif m == "resources/list": reply(i, RES)
    elif m == "tools/list": reply(i, {"tools": []})
    elif m == "prompts/list": reply(i, {"prompts": []})
    elif m == "ping" and not modern: reply(i, {})
    else: refuse(i)
while True:
    ready, _, _ = select.select([sys.stdin], [], [], 0.05)
    if ready:
        line = sys.stdin.readline()
        if not line: break
        if line.strip(): handle(json.loads(line))
    for name in sorted(os.listdir(push_dir)):
        if name.endswith(".json"):
            path = os.path.join(push_dir, name)
            with open(path) as f: note = json.load(f)
            os.remove(path)
            if note["method"] == "__exit__": sys.exit(0)
            if note["method"] == "__raw__":
                out(note["params"]); continue
            push(note["method"], note.get("params", {}))
"#;

/// A stdio peer's files under `dir`: the script, its frame log and its push
/// directory. Returns the backend `command` for the gateway config.
pub fn stdio_peer(dir: &std::path::Path, era: Era) -> (String, StdioPeer) {
    std::fs::create_dir_all(dir.join("push")).expect("push dir");
    let script = dir.join("peer.py");
    std::fs::write(&script, STDIO_PEER).expect("peer script");
    let era = if era == Era::Modern {
        "modern"
    } else {
        "legacy"
    };
    let command = format!(
        "python3 {} {era} {} {}",
        script.display(),
        dir.join("frames.log").display(),
        dir.join("push").display()
    );
    (
        command,
        StdioPeer {
            dir: dir.to_path_buf(),
            pushes: 0.into(),
        },
    )
}

/// Handle on a running stdio peer's files.
pub struct StdioPeer {
    dir: std::path::PathBuf,
    pushes: std::sync::atomic::AtomicUsize,
}

impl StdioPeer {
    /// Every frame the peer has read, in order.
    pub fn frames(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("frames.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Frames whose method is `method`.
    pub fn method(&self, method: &str) -> Vec<Value> {
        self.frames()
            .into_iter()
            .filter(|f| f["method"] == method)
            .collect()
    }

    /// Ask the peer to send `method` with `params`.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline with json!"
    )]
    pub fn push(&self, method: &str, params: Value) {
        let n = self
            .pushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tmp = self.dir.join(format!("push/{n:06}.tmp"));
        std::fs::write(
            &tmp,
            json!({"method": method, "params": params}).to_string(),
        )
        .expect("push note");
        std::fs::rename(&tmp, self.dir.join(format!("push/{n:06}.json"))).expect("publish note");
    }
}

/// A legacy WebSocket MCP peer (WebSocket backends are legacy only).
pub struct WsPeer {
    pub url: String,
    seen: Arc<Mutex<Vec<Value>>>,
    pushes: tokio::sync::broadcast::Sender<(String, Value)>,
}

impl WsPeer {
    pub async fn start() -> Self {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ws peer");
        let url = format!("ws://{}/mcp", listener.local_addr().expect("ws address"));
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let (sender, _) = tokio::sync::broadcast::channel::<(String, Value)>(64);
        let (log, push_tx) = (Arc::clone(&seen), sender.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (log, mut pushed) = (Arc::clone(&log), push_tx.subscribe());
                tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let (mut write, mut read) = ws.split();
                    let mut subscribed: Vec<Value> = Vec::new();
                    loop {
                        let out = tokio::select! {
                            message = read.next() => {
                                let Some(Ok(Message::Text(text))) = message else { return };
                                let frame: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                                log.lock().expect("ws log").push(frame.clone());
                                let Some(id) = frame.get("id").cloned() else { continue };
                                let method = frame["method"].as_str().unwrap_or_default();
                                let uri = frame["params"]["uri"].clone();
                                let result = match method {
                                    "initialize" => Some(json!({
                                        "protocolVersion": frame["params"]["protocolVersion"],
                                        "capabilities": capabilities(),
                                        "serverInfo": {"name": "ws-peer", "version": "0"},
                                    })),
                                    "resources/subscribe" => { subscribed.push(uri); Some(json!({})) }
                                    "resources/unsubscribe" => { subscribed.retain(|u| *u != uri); Some(json!({})) }
                                    "resources/list" => Some(resources()),
                                    "tools/list" => Some(json!({"tools": []})),
                                    "prompts/list" => Some(json!({"prompts": []})),
                                    "ping" => Some(json!({})),
                                    _ => None,
                                };
                                match result {
                                    Some(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                                    None => json!({"jsonrpc": "2.0", "id": id,
                                        "error": {"code": -32601, "message": "method not found"}}),
                                }
                            }
                            push = pushed.recv() => {
                                let Ok((method, params)) = push else { return };
                                if method == "notifications/resources/updated"
                                    && !subscribed.contains(&params["uri"])
                                {
                                    continue;
                                }
                                json!({"jsonrpc": "2.0", "method": method, "params": params})
                            }
                        };
                        if write
                            .send(Message::Text(out.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            url,
            seen,
            pushes: sender,
        }
    }

    /// Frames the peer read whose method is `method`.
    pub fn frames(&self, method: &str) -> Vec<Value> {
        self.seen
            .lock()
            .expect("ws log")
            .iter()
            .filter(|f| f["method"] == method)
            .cloned()
            .collect()
    }

    /// Send `method` as the backend would (resource updates only for
    /// subscribed URIs).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline with json!"
    )]
    pub fn push(&self, method: &str, params: Value) {
        let _ = self.pushes.send((method.to_owned(), params));
    }
}
