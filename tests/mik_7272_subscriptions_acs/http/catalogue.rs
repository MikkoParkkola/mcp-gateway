// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-local real catalogue peer and buffered SSE reader for one row.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::test_helpers::AppState;
use serde_json::{Value, json};

pub(super) struct CatalogueMock {
    tools: Arc<Mutex<Vec<Value>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for CatalogueMock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl CatalogueMock {
    pub(super) async fn start() -> (Self, String) {
        let tools = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("VOID premise: catalogue mock binds");
        let addr = listener
            .local_addr()
            .expect("VOID premise: catalogue mock address");
        let app = Router::new()
            .route("/mcp", post(mcp_handler))
            .with_state(Arc::clone(&tools));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (Self { tools, server }, format!("http://{addr}/mcp"))
    }

    pub(super) fn show_added(&self) {
        let mut tools = self
            .tools
            .lock()
            .expect("VOID premise: catalogue mock lock");
        *tools = vec![added_tool()];
    }

    pub(super) async fn shutdown(mut self) {
        self.server.abort();
        match (&mut self.server).await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => panic!("VOID cleanup: catalogue mock server failed: {error}"),
        }
    }
}

async fn mcp_handler(
    State(tools): State<Arc<Mutex<Vec<Value>>>>,
    Json(body): Json<Value>,
) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match method {
        "initialize" => (
            [(
                header::HeaderName::from_static("mcp-session-id"),
                "catalogue-session",
            )],
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": mcp_gateway::protocol::PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "catalogue-mock", "version": "0"}
                }
            })),
        )
            .into_response(),
        "tools/list" => {
            let current = tools.lock().expect("catalogue mock lock").clone();
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": current}
            }))
            .into_response()
        }
        _ => Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response(),
    }
}

fn added_tool() -> Value {
    json!({
        "name": "added",
        "description": "added",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": true}
    })
}

pub(super) async fn register_empty_alpha(state: &Arc<AppState>, url: &str) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            passthrough: false,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    assert!(
        state.backends.register(Arc::clone(&backend)),
        "VOID premise: alpha registered"
    );
    let listed = backend
        .get_tools_shared()
        .await
        .expect("VOID premise: empty catalogue enumerates");
    let names: Vec<&str> = listed.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(
        names,
        Vec::<&str>::new(),
        "VOID premise: baseline catalogue is empty"
    );
    assert!(
        backend.has_cached_tools() && backend.cached_tools_known(),
        "VOID premise: baseline must be known-empty"
    );
    backend
}

pub(super) async fn show_added_alpha(backend: &Backend, mock: &CatalogueMock) {
    assert_eq!(
        backend.cached_tools_count(),
        0,
        "VOID premise: cache is empty before the change"
    );
    assert!(
        backend.has_cached_tools() && backend.cached_tools_known(),
        "VOID premise: cache is known-empty before the change"
    );
    mock.show_added();
    backend.invalidate_tools_cache();
    let listed = backend
        .get_tools_shared()
        .await
        .expect("VOID premise: changed catalogue re-enumerates");
    let names: Vec<&str> = listed.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["added"],
        "VOID premise: changed cache must be genuinely populated"
    );
    assert!(
        backend.has_cached_tools() && backend.cached_tools_known(),
        "VOID premise: changed cache must be known"
    );
}

pub(super) fn marker_notification() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {"_meta": {"mik7272/test-marker": "ac-sub-1"}}
    })
}

fn is_marker(event: &Value) -> bool {
    event["params"]["_meta"]["mik7272/test-marker"] == json!("ac-sub-1")
}

pub(super) struct SseReader<'a> {
    stream: &'a mut axum::body::BodyDataStream,
    pending: String,
}

impl<'a> SseReader<'a> {
    pub(super) fn new(stream: &'a mut axum::body::BodyDataStream) -> Self {
        Self {
            stream,
            pending: String::new(),
        }
    }

    pub(super) async fn next_event(&mut self, what: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(5), self.next_event_inner(what))
            .await
            .unwrap_or_else(|_| panic!("VOID: timed out waiting for {what}"))
    }

    async fn next_event_inner(&mut self, what: &str) -> Value {
        use futures::StreamExt;

        loop {
            if let Some(end) = self.pending.find('\n') {
                let line: String = self.pending.drain(..=end).collect();
                let line = line.trim_end_matches(['\n', '\r']);
                if let Some(payload) = line.strip_prefix("data: ") {
                    return serde_json::from_str(payload).unwrap_or_else(|error| {
                        panic!("VOID: {what} frame must be JSON ({error}): {payload}")
                    });
                }
                continue;
            }
            match self.stream.next().await {
                None => panic!("VOID: stream ended before {what}"),
                Some(Err(error)) => panic!("VOID: body error before {what}: {error}"),
                Some(Ok(chunk)) => {
                    let text = String::from_utf8(chunk.to_vec()).unwrap_or_else(|error| {
                        panic!("VOID: {what} frame must be UTF-8: {error}")
                    });
                    self.pending.push_str(&text);
                }
            }
        }
    }

    pub(super) async fn collect_until_marker(&mut self) -> Vec<Value> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut preceding = Vec::new();
            loop {
                let event = self.next_event_inner("the marker").await;
                if is_marker(&event) {
                    break;
                }
                preceding.push(event);
            }
            preceding
        })
        .await
        .unwrap_or_else(|_| panic!("VOID: timed out waiting for the marker"))
    }
}

#[cfg(test)]
mod tests {
    use super::{SseReader, marker_notification};
    use serde_json::json;

    #[tokio::test]
    async fn reader_preserves_split_coalesced_frames_and_retained_tails() {
        let first = json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"readerControl": "first"}
        });
        let second = json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"readerControl": "second"}
        });
        let first_frame = format!("data: {first}\n\n");
        let second_frame = format!("data: {second}\n\n");
        let marker_frame = format!("data: {}\n\n", marker_notification());

        // Precise chunk partition (all frames ASCII, offsets in bytes):
        // - chunk 1 is first_frame[..2] ("da"), splitting the first
        //   frame's "data: " prefix across the chunk boundary.
        // - chunk 2 is first_frame[2..] plus second_frame[..second_cut],
        //   where second_cut is 10 bytes into the second frame's JSON
        //   payload, so chunk 2 ends with the second frame partial.
        // - chunk 3 is second_frame[second_cut..] plus the whole marker
        //   frame, finishing the second frame coalesced with the marker.
        let second_cut = "data: ".len() + 10;
        let chunk_one = first_frame[..2].to_owned();
        let chunk_two = format!("{}{}", &first_frame[2..], &second_frame[..second_cut]);
        let chunk_three = format!("{}{}", &second_frame[second_cut..], marker_frame);

        let body = axum::body::Body::from_stream(futures::stream::iter(vec![
            Ok::<axum::body::Bytes, std::io::Error>(axum::body::Bytes::from(chunk_one)),
            Ok(axum::body::Bytes::from(chunk_two)),
            Ok(axum::body::Bytes::from(chunk_three)),
        ]));
        let mut stream = body.into_data_stream();
        let mut reader = SseReader::new(&mut stream);

        let first_event = reader.next_event("the first event").await;
        assert_eq!(
            first_event, first,
            "the reader must reassemble the first frame across the split \
             prefix and retain the partial second frame that followed it"
        );
        let preceding = reader.collect_until_marker().await;
        assert_eq!(
            preceding,
            vec![second.clone()],
            "the retained tail must complete exactly the second event \
             before the coalesced marker, with the marker excluded"
        );

        // One-chunk coalesced control: first, second, and marker frames
        // delivered in a single Bytes chunk to a separate reader.
        let coalesced = format!("{first_frame}{second_frame}{marker_frame}");
        let coalesced_body = axum::body::Body::from_stream(futures::stream::iter(vec![Ok::<
            axum::body::Bytes,
            std::io::Error,
        >(
            axum::body::Bytes::from(coalesced),
        )]));
        let mut coalesced_stream = coalesced_body.into_data_stream();
        let mut coalesced_reader = SseReader::new(&mut coalesced_stream);
        let coalesced_preceding = coalesced_reader.collect_until_marker().await;
        assert_eq!(
            coalesced_preceding,
            vec![first, second],
            "one coalesced chunk must yield exactly the first and second \
             events in order, with the marker excluded"
        );
    }

    // Expected-negative healthy control: EOF before the marker must stay
    // VOID, so this row passes only when the reader panics with the exact
    // stream-ended premise label. It is not a behaviour failure.
    #[tokio::test]
    #[should_panic(expected = "VOID: stream ended before the marker")]
    async fn reader_requires_marker_before_eof() {
        let non_marker = json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"readerControl": "non-marker"}
        });
        let frame = format!("data: {non_marker}\n\n");
        let body = axum::body::Body::from_stream(futures::stream::iter(vec![Ok::<
            axum::body::Bytes,
            std::io::Error,
        >(
            axum::body::Bytes::from(frame),
        )]));
        let mut stream = body.into_data_stream();
        let mut reader = SseReader::new(&mut stream);
        reader.collect_until_marker().await;
    }

    // Expected-negative healthy control: a body error before the marker
    // must stay VOID under its own label, distinct from the EOF label.
    #[tokio::test]
    #[should_panic(expected = "VOID: body error before the marker")]
    async fn reader_classifies_body_error_as_void() {
        let body = axum::body::Body::from_stream(futures::stream::iter(vec![Err::<
            axum::body::Bytes,
            std::io::Error,
        >(
            std::io::Error::other("reader-control"),
        )]));
        let mut stream = body.into_data_stream();
        let mut reader = SseReader::new(&mut stream);
        reader.collect_until_marker().await;
    }

    // Expected-negative healthy control: a pending stream must be bounded
    // by collect_until_marker's unchanged fixed 5s deadline and stay VOID
    // under the timeout label. This row takes about 5s by design; the
    // timeout is the validated contract, never a fault.
    #[tokio::test]
    #[should_panic(expected = "VOID: timed out waiting for the marker")]
    async fn reader_bounds_pending_marker_by_fixed_deadline() {
        let body = axum::body::Body::from_stream(futures::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let mut stream = body.into_data_stream();
        let mut reader = SseReader::new(&mut stream);
        reader.collect_until_marker().await;
    }
}
