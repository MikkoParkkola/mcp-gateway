// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Header-value encoding shapes and the reconnecting SSE GET.

use super::*;

/// The shapes a tool name can take, and what each one costs the encoder.
///
/// `transparent` is the assertion that separates a working encoder from one
/// that wraps everything: wrapping is always *correct* and always *wrong*,
/// because an operator reading `Mcp-Name` would never again see a plain name.
/// The literal-sentinel row is the inverse trap — plain ASCII that must
/// nonetheless be wrapped, which an `is_ascii()` guard gets wrong.
const NAME_SHAPES: &[(&str, bool)] = &[
    ("tools-alpha", true),
    ("työkalu", false),
    (" leading", false),
    ("trailing ", false),
    ("embedded\nnewline", false),
    ("=?base64?dG9vbA==?=", false),
];

/// MIK-7214.HEADER.4a — every name shape survives the header and comes back.
///
/// Asserted against the repository's own `decode_header_value`, not against a
/// second encoder written here: an encoder tested by its own inverse agrees
/// with itself and with nothing else.
///
/// The empty name is absent deliberately: it cannot round-trip, because
/// `decode_header_value` refuses an empty sentinel payload — and loosening that
/// parser to admit one would widen a check an attacker writes the input to. The
/// name is refused before the encoder sees it instead, which the case below
/// pins.
#[test]
fn every_name_shape_round_trips_and_only_the_safe_one_stays_plain() {
    for (name, transparent) in NAME_SHAPES {
        // GIVEN a name of this shape, WHEN encoded for a header value,
        let encoded = encode_header_value(name);
        // THEN it is legal as one,
        assert!(
            encoded.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            "{name:?} encoded to {encoded:?}, which is not a legal header value"
        );
        // and decodes back to exactly what went in,
        assert_eq!(
            decode_header_value(&encoded).as_deref(),
            Some(*name),
            "{name:?} did not survive the round trip"
        );
        // and was left alone only when it was already safe and unambiguous.
        assert_eq!(
            &encoded == name,
            *transparent,
            "{name:?} was {} and should not have been",
            if *transparent {
                "wrapped"
            } else {
                "passed through"
            }
        );
    }
}

/// An SSE-mode peer: `GET /` answers the SSE handshake with an `endpoint`
/// event naming `/message`, and `POST /message` speaks the same JSON-RPC the
/// streamable-HTTP fixtures above speak. `tools/list`'s second call expires
/// the session, the same way `spawn_expiring_peer` does, so a reconnect is
/// forced — the only way the `Modern`/`Sse` cell in
/// `docs/design/2026-09-03-header-9-era-conditional-outbound-test-plan.md` can
/// be proved: a primed first connect never reaches the code under test.
async fn spawn_sse_expiring_peer() -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let sse_recorder = Arc::clone(&recorder);
    let msg_recorder = Arc::clone(&recorder);
    let msg_calls = Arc::clone(&calls);

    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(move |headers: HeaderMap| {
                let sink = Arc::clone(&sse_recorder);
                async move {
                    sink.lock().expect("recorder poisoned").push(Wire {
                        method: "GET /".to_string(),
                        headers,
                        body: Value::Null,
                    });
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        "event: endpoint\ndata: /message\n\n".to_string(),
                    )
                }
            }),
        )
        .route(
            "/message",
            axum::routing::post(
                move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                    let sink = Arc::clone(&msg_recorder);
                    let calls = Arc::clone(&msg_calls);
                    async move {
                        let method = request
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        sink.lock().expect("recorder poisoned").push(Wire {
                            method: method.clone(),
                            headers,
                            body: request.clone(),
                        });
                        let mut out = HeaderMap::new();
                        if method != "server/discover" {
                            out.insert("Mcp-Session-Id", "s1".parse().expect("ascii"));
                        }
                        // The first ordinary response mints a session. The
                        // second expires it, forcing the reconnect this case
                        // exists to observe.
                        if method == "tools/list"
                            && calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1
                        {
                            let id = request.get("id").cloned().unwrap_or(Value::Null);
                            return (
                                out,
                                axum::Json(json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": { "code": -32015, "message": "session not found" }
                                })),
                            );
                        }
                        (out, axum::Json(answer(Peer::Modern, &request)))
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture peer must get a port");
    let url = format!("http://{}/", listener.local_addr().expect("bound address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, recorder)
}

/// MIK-7214.HEADER.9a/.9b — the `Modern`/`Sse` cell: a reconnect to a peer
/// already classified `Modern` carries the modern protocol version and no
/// session header, even though the *first* `GET` (before the era resolved)
/// stayed legacy-shaped and even though the backend is statically configured
/// with an operator-pinned `MCP-Session-Id`.
///
/// Proved by a reconnect, not a primed first connect: a primed era would make
/// the first `GET` green against a production path that only ever reaches
/// `Modern` on the session-expiry re-entry inside `request()`
/// (test-plan.md `Cases`, "The `Modern`/`Sse` cell is proved by a reconnect").
#[tokio::test]
async fn a_reconnect_to_a_modern_peer_sends_the_modern_sse_get() {
    let (url, recorder) = spawn_sse_expiring_peer().await;
    let backend = Backend::new(
        "header9-sse-fixture",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(false),
                protocol_version: None,
            },
            headers: [("MCP-Session-Id".to_string(), "operator-pinned".to_string())]
                .into_iter()
                .collect(),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );

    backend
        .request("tools/list", None)
        .await
        .expect("the first call starts the backend and mints a session");
    backend
        .request("tools/list", None)
        .await
        .expect("the retry after the forced reconnect succeeds");

    let seen = recorder.lock().expect("recorder poisoned").clone();
    let gets: Vec<&Wire> = seen.iter().filter(|w| w.method == "GET /").collect();
    assert_eq!(
        gets.len(),
        2,
        "the session expiry must force exactly one reconnect; saw {:?}",
        seen.iter().map(|w| &w.method).collect::<Vec<_>>()
    );

    assert_eq!(
        header(gets[0], "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "the era is unresolved before the first GET, which must stay legacy-shaped"
    );
    assert_eq!(
        header(gets[1], "MCP-Protocol-Version"),
        MODERN_VERSIONS[0],
        "a reconnect to a peer already classified Modern must carry the modern \
         protocol version, not the legacy handshake's"
    );
    assert!(
        gets[1].headers.get("MCP-Session-Id").is_none(),
        "MIK-7215.STATELESS.3a: a modern-classified reconnect must not emit \
         MCP-Session-Id, including one the operator statically configured; saw {:?}",
        gets[1].headers
    );
}
