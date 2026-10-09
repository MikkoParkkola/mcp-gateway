// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// The HTTP client harness the HTTP rows and the included gate rows share.

// ── Client harness: HTTP ────────────────────────────────────────────────────

/// The credential the HTTP rows present on every request.
///
/// Auth is on here, unlike the stdio config, and that is the point rather than
/// an incidental hardening: an explicit idempotency key is admitted against a
/// principal, and an anonymous caller has none. A harness that left auth off
/// would be refused before it ever reached the streaming behaviour these rows
/// are about.
const BEARER: &str = "sub2b-operator-token";

fn write_http_config(home: &Path, backend_url: &str, port: u16) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "tasks:\n  store_dir: tasks\nserver:\n  host: \"127.0.0.1\"\n  port: {port}\n\
             security:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n  single_user: true\n\
             backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

struct HttpSession {
    child: Child,
    client: reqwest::Client,
    url: String,
    /// The session the gateway assigned at `initialize`. A Streamable HTTP
    /// client echoes it on every later POST; a harness that dropped it would
    /// run each call on a virgin session and would be testing a client the
    /// spec does not describe.
    session: String,
    /// The gateway's stdout and stderr (MIK-8199 diagnosis).
    log: std::path::PathBuf,
}

impl HttpSession {
    /// Spawn the gateway in HTTP mode and wait until it answers `initialize`.
    async fn spawn(home: &Path, backend_url: &str) -> Self {
        // The child binds an OS-chosen port and logs it (MIK-7984).
        write_http_config(home, backend_url, gateway_bin::ANY_PORT);
        let log = home.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("serve log handle");

        let mut command = Command::from(gateway_bin::command(
            home,
            gateway_bin::Inherit::Environment,
        ));
        command
            .arg("serve")
            .current_dir(home)
            .env("RUST_LOG", "mcp_gateway=debug");
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over http");

        // Attached once, as a default header, so no POST helper can forget it:
        // an unauthenticated request reaches the gateway as `anonymous`, which
        // holds no principal and cannot be admitted for a keyed call.
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {BEARER}"))
                .expect("a bearer header"),
        );
        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .expect("build the http client");
        let ready = timeout(READ_TIMEOUT, async {
            loop {
                let Some(port) = gateway_bin::logged_port(&log) else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let url = format!("http://127.0.0.1:{port}/mcp");
                let posted = client
                    .post(&url)
                    .header("Accept", "application/json, text/event-stream")
                    .json(&initialize_request(1))
                    .send()
                    .await;
                if let Ok(response) = posted
                    && response.status() == reqwest::StatusCode::OK
                {
                    let session = response
                        .headers()
                        .get("mcp-session-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    return (session, url);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let (session, url) = ready.unwrap_or_else(|_| {
            panic!(
                "the gateway never logged a port and answered initialize:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            )
        });
        assert!(
            !session.is_empty(),
            "the gateway assigned no session at initialize; every later POST \
             would open a new one"
        );

        // The handshake is not complete until the client says so, and a call
        // made before it is a call made against a server that is still
        // initializing.
        let (status, _, body) = post_sse(
            &client,
            &url,
            &session,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        assert!(
            (200..300).contains(&status),
            "the gateway refused notifications/initialized: {status} {body}"
        );

        Self {
            child,
            client,
            url,
            session,
            log,
        }
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }
}

/// Attach the explicit idempotency key a modern mutating call must carry.
///
/// Applied inside the two HTTP POST helpers rather than in [`invoke`], because
/// only the modern HTTP surface requires one and a key on the stdio rows would
/// change what those rows exercise. Handshake frames are left alone: a key
/// belongs to an operation, and `initialize` is not one.
///
/// Keyed on the JSON-RPC id, never a constant. `S-03` holds two invocations
/// open at once, and a shared key would admit the second as a replay of the
/// first instead of letting it run its own stream — the isolation the row
/// exists to prove would be destroyed by the harness.
fn with_idempotency_key(mut message: Value) -> Value {
    const KEY: &str = mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;

    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return message;
    }
    let id = message
        .get("id")
        .and_then(Value::as_i64)
        .expect("a tools/call carries a numeric id in this harness");
    if let Some(meta) = message
        .pointer_mut("/params/_meta")
        .and_then(Value::as_object_mut)
    {
        meta.insert(KEY.to_string(), json!(format!("sub2b-{id}")));
    }
    message
}

/// POST one JSON-RPC message, offering a stream. Returns status, content type
/// and body; every failure message in the HTTP rows quotes the body, because a
/// refusal is a body and not a status.
async fn post_sse(
    client: &reqwest::Client,
    url: &str,
    session: &str,
    message: Value,
) -> (u16, String, String) {
    let message = with_idempotency_key(message);
    // Mirror whatever the body declared, and nothing when it declared nothing.
    // The gateway reads the header as well as the body and refuses the two
    // disagreeing with -32020 — including the case where only one of them
    // speaks, which is why this is derived from the message rather than set on
    // every POST: `notifications/initialized` carries no `_meta`, and a header
    // on it would be a declaration the body does not make.
    let declared = message
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str);
    let mut request = client
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", session);
    if let Some(version) = declared {
        request = request.header("MCP-Protocol-Version", version);
        // A modern POST mirrors its method too, and its name for the three
        // methods that carry one. The gateway requires both and refuses an
        // absent one with -32020, so both are derived from the same message
        // the body is built from rather than written out beside it, which is
        // how a header and a body drift apart.
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        request = request.header("Mcp-Method", method);
        if let Some(field) = mcp_name_body_field(method)
            && let Some(name) = message
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
        {
            request = request.header("Mcp-Name", encode_header_value(name));
        }
    }
    let response = request
        .json(&message)
        .send()
        .await
        .expect("POST to the gateway");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = response.text().await.expect("read the response body");
    (status, content_type, body)
}

/// The JSON frames of an SSE body, in order.
fn sse_frames(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect()
}

/// Reads one SSE body frame by frame, as the bytes arrive.
///
/// The `S-02` liveness rows need a consumer that acts on a notification before
/// the response it belongs to has ended — that is the whole assertion — so
/// they cannot buffer. Everything else here reads to the end with
/// [`post_sse`].
struct SseReader {
    stream: std::pin::Pin<Box<dyn futures::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>,
    pending: String,
}

impl SseReader {
    /// POST `message` offering a stream, and return a reader over the body
    /// alongside the status and content type of its head.
    ///
    /// The head is available before the body because the gateway commits to
    /// SSE headers before dispatch finishes; a row that never sees a head has
    /// found the buffered arm, which is the failure it exists to catch.
    async fn post(
        client: &reqwest::Client,
        url: &str,
        session: &str,
        message: Value,
    ) -> (u16, String, Self) {
        let message = with_idempotency_key(message);
        let version = message
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            .expect("an S-02 row declares its revision");
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut request = client
            .post(url)
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Session-Id", session)
            .header("MCP-Protocol-Version", version)
            .header("Mcp-Method", method);
        if let Some(field) = mcp_name_body_field(method)
            && let Some(name) = message
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
        {
            request = request.header("Mcp-Name", encode_header_value(name));
        }
        let response = request
            .json(&message)
            .send()
            .await
            .expect("POST to the gateway");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (
            status,
            content_type,
            Self {
                stream: Box::pin(response.bytes_stream()),
                pending: String::new(),
            },
        )
    }

    /// Whatever is left of the body, as text.
    ///
    /// A refusal is a body and not a status, so a row that did not get its
    /// stream reports what the gateway actually said. Bounded by
    /// [`READ_TIMEOUT`] for the same reason `next_frame` is.
    async fn drain(mut self) -> String {
        use futures::StreamExt as _;

        let collect = async {
            while let Some(Ok(chunk)) = self.stream.next().await {
                self.pending.push_str(&String::from_utf8_lossy(&chunk));
            }
        };
        let _ = tokio::time::timeout(READ_TIMEOUT, collect).await;
        self.pending
    }

    /// The next complete frame, or `None` when the body ends without one.
    ///
    /// Bounded by [`READ_TIMEOUT`] rather than left to the test harness: a row
    /// whose notification never arrives is exactly the regression being
    /// guarded against, and it must fail as an assertion rather than hang.
    async fn next_frame(&mut self) -> Option<Value> {
        use futures::StreamExt as _;

        loop {
            if let Some(split) = self.pending.find("\n\n") {
                let frame: String = self.pending.drain(..split + 2).collect();
                if let Some(data) = frame.lines().find_map(|l| l.strip_prefix("data: "))
                    && let Ok(value) = serde_json::from_str::<Value>(data)
                {
                    return Some(value);
                }
                continue;
            }
            let chunk = timeout(READ_TIMEOUT, self.stream.next())
                .await
                .expect("the response body stalled with no frame in it")?;
            let chunk = chunk.expect("read the response body");
            self.pending.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
}

/// Wait until `count` slow calls have reached the fixture and parked there.
///
/// This is the concurrency precondition of the isolation rows: two streams
/// cannot be shown to be separate unless both are open at once.
async fn parked_slow_calls(received: &Received, count: usize) -> bool {
    timeout(READ_TIMEOUT, async {
        loop {
            let parked = received
                .lock()
                .expect("fixture sink poisoned")
                .iter()
                .filter(|request| tool_name(request).as_deref() == Some(SLOW_TOOL))
                .count();
            if parked >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}
