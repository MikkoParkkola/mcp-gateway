// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7214.HEADER.9a / .9b — era-conditional outbound headers and `_meta`.
//!
//! Design: `docs/design/2026-09-03-header-9-era-conditional-outbound.md`.
//! Plan: the same name with `-test-plan`.
//!
//! Every assertion here reads the **captured wire request**, never
//! `build_mcp_headers`' return value. The builder is private, it merges the
//! backend's static headers inside itself, and the `Request` path merges
//! per-request `extra_headers` *after* it returns — so a case asserting on the
//! return value sees neither the operator-override question nor the body half,
//! which is where half of HEADER.9a lives.
//!
//! The era is resolved by the **production probe** rather than primed as a
//! fixture input. That is deliberate and it is this file's load-bearing choice:
//! the plan names "every other case primes the era cache, so all of them pass
//! against a lifecycle that never attaches it" as its heaviest risk. A peer
//! that answers `server/discover` with a modern discovery document is the only
//! input these cases give the era machinery; if the lifecycle never hands the
//! cache to the transport, they fail for that reason and no other.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::protocol::PROTOCOL_VERSION;
use mcp_gateway::protocol::headers::{decode_header_value, encode_header_value};
use mcp_gateway::protocol::meta::{
    KEY_CLIENT_CAPABILITIES, KEY_CLIENT_INFO, KEY_PROTOCOL_VERSION, MODERN_VERSIONS,
};
use serde_json::{Value, json};

/// One request as it arrived on the wire: what a captured assertion reads.
#[derive(Clone)]
struct Wire {
    method: String,
    headers: HeaderMap,
    body: Value,
}

type Recorder = Arc<Mutex<Vec<Wire>>>;

/// How the fixture peer answers `server/discover`.
///
/// Named rather than a bare `bool` at the call site: `spawn_peer(true)` does
/// not say which era it means.
#[derive(Clone, Copy)]
enum Peer {
    /// Answers discovery with a document naming a modern revision.
    Modern,
    /// Answers discovery `method not found`, the way a 2025 server does.
    Legacy,
    /// Answers discovery with a well-formed document that names only a 2025
    /// revision — the peer that has discovery and is still not modern.
    LegacyDiscovering,
}

/// Answer one request the way the chosen peer would.
fn answer(peer: Peer, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "server/discover" {
        return match peer {
            // `classify` requires positive evidence: a discovery document whose
            // `capabilities` is an object and whose `supportedVersions` names a
            // revision in `MODERN_VERSIONS` (`src/protocol/era.rs`).
            Peer::Modern => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "capabilities": {},
                    "supportedVersions": MODERN_VERSIONS,
                }
            }),
            // An error reads as legacy. A probe that never answers at all is
            // the one input this file does not give the era machinery: it is a
            // timeout, and asserting on one buys a slow test rather than a
            // sharper claim. Recorded as untested, not covered by these cases.
            Peer::Legacy => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" }
            }),
            // The other half of "positive evidence": a document that IS a
            // discovery document and still names no modern revision.
            Peer::LegacyDiscovering => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "capabilities": {},
                    "supportedVersions": ["2025-06-18"],
                }
            }),
        };
    }
    if method == "initialize" {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "fixture", "version": "0" }
            }
        });
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
}

/// A peer that records every request whole — headers included.
///
/// Bodies alone would answer HEADER.9a's `_meta` half and nothing about the
/// header half, and the two are emitted from different sites.
async fn spawn_peer(peer: Peer) -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorder);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().expect("recorder poisoned").push(Wire {
                        method: request
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        headers,
                        body: request.clone(),
                    });
                    // The peer issues a session the way a real server does,
                    // so the legacy path has something to be pinned against:
                    // the modern shape STRIPS `MCP-Session-Id`
                    // (MIK-7215.STATELESS.3a), which makes "the legacy request
                    // is unchanged" a claim about a header that can now move.
                    let mut out = HeaderMap::new();
                    if matches!(peer, Peer::Modern)
                        || request.get("method").and_then(Value::as_str) == Some("initialize")
                    {
                        out.insert("Mcp-Session-Id", "s1".parse().expect("ascii"));
                    }
                    (out, axum::Json(answer(peer, &request)))
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

/// A backend built the way production builds one, pointed at the fixture peer.
///
/// `Backend::new` is the real constructor and it mints the era cache itself
/// (`src/backend/lifecycle.rs`), so nothing here can hand the transport an era
/// the lifecycle would not have given it.
fn backend_at(url: &str) -> Backend {
    backend_with(url, &[])
}

/// The same backend, plus the operator-configured static headers a pinning
/// case needs.
///
/// Split from `backend_at` rather than duplicated: the pinning rows differ
/// from every other row by one field, and a second copy of the constructor is
/// a second place for the transport shape to drift.
fn backend_with(url: &str, statics: &[(&str, &str)]) -> Backend {
    Backend::new(
        "header9-fixture",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            headers: statics
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// The ordinary request whose shape every case reads, and what it recorded.
///
/// `server/discover` and `initialize` are filtered out: the probe and the
/// handshake are not the request under test, and `initialize` is required to
/// stay legacy-shaped whatever the era.
async fn ordinary_request(peer: Peer) -> Wire {
    Run::of(peer, Path::Request, "tools/list", None, &[], &[])
        .await
        .under_test("tools/list")
        .clone()
}

/// Which outbound path a case drives.
///
/// Named rather than a bare `bool`: the two paths assemble their bodies and
/// merge their headers at different sites (`mod.rs:968` / `:1045`,
/// `:846-854` / `:1051-1053`), which is the whole reason every shape is
/// driven twice.
#[derive(Clone, Copy)]
enum Path {
    Request,
    Notify,
}

/// One driven call and everything the fixture peer saw while it ran.
struct Run {
    peer: Peer,
    call_start: usize,
    seen: Vec<Wire>,
    /// The JSON-RPC code the failure maps to, and its text. The code is
    /// captured here rather than re-derived later because `Error` does not
    /// survive the borrow out of `of`, and a test that re-classified the
    /// message by matching on its words would agree with itself.
    outcome: Result<(), (i32, String)>,
}

impl Run {
    /// Drive one call against a fresh peer and capture the wire.
    async fn of(
        peer: Peer,
        path: Path,
        method: &str,
        params: Option<Value>,
        statics: &[(&str, &str)],
        extra: &[(&str, &str)],
    ) -> Self {
        let (url, recorder) = spawn_peer(peer).await;
        let backend = backend_with(&url, statics);
        // Give the modern transport a real peer-issued session on an ordinary
        // response. Discover cannot seed it: startup deliberately ignores a
        // probe's session header. Both request and notification tests therefore
        // exercise stripping with a populated session bucket.
        if matches!(peer, Peer::Modern) {
            backend
                .request("resources/list", None)
                .await
                .expect("the session-priming request succeeds");
        }
        let call_start = recorder.lock().expect("recorder poisoned").len();
        let extra: Vec<(String, String)> = extra
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        let outcome = match path {
            Path::Request => backend
                .request_with_headers(method, params, &extra, None)
                .await
                .map(|_| ()),
            Path::Notify => backend.notify_with_headers(method, params, None).await,
        };
        Self {
            peer,
            call_start,
            seen: recorder.lock().expect("recorder poisoned").clone(),
            outcome: outcome.map_err(|err| (err.to_rpc_code(), err.to_string())),
        }
    }

    /// Check discovery and session-priming order before inspecting the call.
    fn under_test(&self, method: &str) -> &Wire {
        let relative = self.seen[self.call_start..]
            .iter()
            .position(|wire| wire.method == method)
            .unwrap_or_else(|| panic!("{method} never reached the peer; saw {}", self.methods()));
        let at = self.call_start + relative;
        let discovery = self
            .seen
            .iter()
            .position(|wire| wire.method == "server/discover")
            .expect("startup must probe before dispatch");
        let handshake = self
            .seen
            .iter()
            .position(|wire| wire.method == "initialize");
        match self.peer {
            Peer::Modern => {
                assert!(handshake.is_none(), "modern startup must not initialize");
                let prime = self.seen[..self.call_start]
                    .iter()
                    .position(|wire| wire.method == "resources/list")
                    .expect("a real ordinary response must mint the session first");
                assert!(discovery < prime && prime < at);
            }
            Peer::Legacy | Peer::LegacyDiscovering => {
                assert!(
                    handshake.is_some_and(|hs| discovery < hs && hs < at),
                    "legacy startup must discover, handshake, then dispatch; saw {}",
                    self.methods()
                );
            }
        }
        &self.seen[at]
    }

    /// Assert the call failed locally and the peer never saw it.
    ///
    /// Both halves, deliberately: an implementation that sends first and
    /// errors after satisfies an `Err`-only assertion while having already put
    /// a malformed body on the wire.
    fn failed_before_sending(&self, method: &str) {
        let Err((code, error)) = &self.outcome else {
            panic!("a body this design rejects must fail the call locally, not be sent");
        };
        // The CLASS of the refusal, not merely that one happened. A caller who
        // sends `tools/call` with no usable `name` has written an invalid
        // request; reporting that as a backend transport failure misinforms the
        // caller and — because the same variant feeds the backend's failure
        // accounting — lets a handful of malformed local calls count against a
        // peer that never saw them.
        assert_eq!(
            *code, -32600,
            "a locally refused caller error is an invalid request, not a \
             backend failure; got {error}"
        );
        assert!(
            !self.seen[self.call_start..]
                .iter()
                .any(|wire| wire.method == method),
            "the rejected call must never reach the peer; it saw {}",
            self.methods()
        );
    }

    /// What the peer saw, for a failure message that names the flow.
    fn methods(&self) -> String {
        self.seen
            .iter()
            .map(|wire| wire.method.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Read one header as a string, or say which one was missing.
fn header(wire: &Wire, name: &str) -> String {
    wire.headers
        .get(name)
        .unwrap_or_else(|| panic!("{name} is absent; the peer received {:?}", wire.headers))
        .to_str()
        .expect("a header this design emits is ASCII")
        .to_string()
}

/// MIK-7214.HEADER.9b — the version comes from the negotiated envelope.
///
/// The reachability case, and the only one whose failure means "the feature is
/// unreachable in production" rather than "a value is wrong". Nothing primes
/// the era: the peer answered discovery modernly and the lifecycle must carry
/// that verdict as far as the header builder on its own.
#[tokio::test]
async fn a_modern_peer_gets_the_modern_protocol_version() {
    let wire = ordinary_request(Peer::Modern).await;
    assert_eq!(
        header(&wire, "MCP-Protocol-Version"),
        MODERN_VERSIONS[0],
        "a peer that answered discovery modernly must be sent the modern \
         revision, not the legacy handshake constant"
    );
    // The other half of the legacy pin. Same fixture, same issued session,
    // opposite outcomes by era: without this, "the modern shape strips
    // `MCP-Session-Id`" (MIK-7215.STATELESS.3a) is prose in two comments and
    // nothing here proves the legacy pin is about a header that can move.
    assert!(
        wire.headers.get("MCP-Session-Id").is_none(),
        "the modern shape is stateless and must not echo the session the peer \
         issued; it sent {:?}",
        wire.headers
    );
}

/// MIK-7214.HEADER.9a, body half — modern requests carry the required `_meta`.
///
/// Asserts the two keys the revision makes required and the absence of the one
/// this design declined to send. `clientInfo` is optional and self-asserted, so
/// emitting it would be an identity claim this change does not get to make;
/// asserting its absence is what stops it arriving later by accident.
#[tokio::test]
async fn a_modern_request_carries_the_required_meta() {
    let wire = ordinary_request(Peer::Modern).await;
    let meta = wire
        .body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .unwrap_or_else(|| panic!("no `params._meta` in {}", wire.body));
    assert_eq!(
        meta.get(KEY_PROTOCOL_VERSION).and_then(Value::as_str),
        Some(MODERN_VERSIONS[0]),
        "the required protocol-version key must name the revision being spoken"
    );
    assert_eq!(
        meta.get(KEY_CLIENT_CAPABILITIES),
        Some(&json!({})),
        "the required client-capabilities key must be present and an object, \
         matching what the legacy handshake already declares"
    );
    assert!(
        meta.get(KEY_CLIENT_INFO).is_none(),
        "clientInfo is optional and self-asserted; this design declined it"
    );
}

/// MIK-7214.HEADER.9a — a legacy peer's requests are unchanged, asserted
/// positively.
///
/// "Unchanged behaviour" is the row most easily satisfied by a fixture that
/// never reached the code: a case asserting only "no modern header" passes
/// against a transport that never built headers at all. So this asserts what a
/// legacy request *does* carry — the handshake version — as well as what it
/// does not.
#[tokio::test]
async fn a_legacy_peer_still_gets_the_handshake_version_and_no_meta() {
    let wire = ordinary_request(Peer::Legacy).await;
    assert_eq!(
        header(&wire, "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "a peer that refused discovery is legacy, and legacy is byte-for-byte \
         what this transport sent before this change"
    );
    assert!(
        wire.body
            .get("params")
            .and_then(|params| params.get("_meta"))
            .is_none(),
        "a legacy peer must not be sent a 2026 envelope; it received {}",
        wire.body
    );
    assert_eq!(
        header(&wire, "MCP-Session-Id"),
        "s1",
        "the session the peer issued must come back verbatim on the legacy \
         path; the modern shape strips this header, so \"unchanged\" is a \
         claim about a header this change can move"
    );
}

/// MIK-7214.HEADER.9a — a discovery document that names no modern revision is
/// still legacy.
///
/// The `answer` fixture asserts in prose that `classify` requires POSITIVE
/// evidence, and only the `method not found` half of that was exercised: every
/// legacy case here came from a peer with no discovery at all. A 2025 server
/// that does implement discovery is the likelier peer of the two, and it is the
/// one a loose `classify` would send a 2026 envelope to. `src/protocol/era.rs`
/// has no unit test covering this arm either.
#[tokio::test]
async fn a_discovery_document_naming_no_modern_revision_stays_legacy() {
    let wire = ordinary_request(Peer::LegacyDiscovering).await;
    assert_eq!(
        header(&wire, "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "a discovery document naming only 2025 is not positive evidence of a \
         modern peer, and must not raise the version"
    );
    assert!(
        wire.body
            .get("params")
            .and_then(|params| params.get("_meta"))
            .is_none(),
        "a peer that named no modern revision must not be sent a 2026 \
         envelope; it received {}",
        wire.body
    );
}

/// A modern peer that hands out a session and then expires it once.
///
/// The expiry is what re-enters `initialize()` (`src/transport/http/mod.rs`
/// session-expiry retry): the era cache is already `Modern` by then, which is
/// the only state in which the handshake's era-shaping can be observed. A
/// fixture that primed the era could not produce this ordering, because the
/// re-handshake has to follow a *resolved* probe, not a planted verdict.
async fn spawn_expiring_peer() -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorder);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                let calls = Arc::clone(&calls);
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
                    // The first ordinary response mints a session. The second
                    // request expires it; the retry after reinitialization succeeds.
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

/// MIK-7214.HEADER.9a — the handshake stays legacy-shaped whatever the era.
///
/// The doc comment on `ordinary_request` asserts this in prose and no case
/// tested it: `initialize` reaches the peer through `send_request`, which
/// refuses the era by construction, but its `notifications/initialized`
/// travelled through the ordinary `notify` path. On a first start that reads
/// legacy only because the probe has not landed yet — on a re-handshake it is
/// a 2026 notification sent to a peer we are still introducing ourselves to.
#[tokio::test]
async fn a_reinitialize_keeps_the_initialized_notification_legacy_shaped() {
    let (url, recorder) = spawn_expiring_peer().await;
    let backend = backend_at(&url);
    backend
        .request("tools/list", None)
        .await
        .expect("the initial modern response mints a session");
    backend
        .request("tools/list", None)
        .await
        .expect("the retry after the fresh handshake succeeds");
    let seen = recorder.lock().expect("recorder poisoned").clone();

    let handshakes: Vec<&Wire> = seen
        .iter()
        .filter(|wire| wire.method == "notifications/initialized")
        .collect();
    assert_eq!(
        handshakes.len(),
        1,
        "the session-expiry retry must have re-run the handshake; saw {:?}",
        seen.iter().map(|w| &w.method).collect::<Vec<_>>()
    );
    let methods: Vec<&str> = seen.iter().map(|wire| wire.method.as_str()).collect();
    assert_eq!(
        methods,
        vec![
            "server/discover",
            "tools/list",
            "tools/list",
            "initialize",
            "notifications/initialized",
            "tools/list"
        ],
        "a real minted-session expiry must cause exactly one handshake and retry"
    );
    let modern_request = seen
        .iter()
        .any(|wire| wire.method == "tools/list" && wire.body["params"].get("_meta").is_some());
    assert!(
        modern_request,
        "the era must be resolved Modern by the retry, or this case proves nothing"
    );

    let reinit = handshakes.last().expect("checked above");
    assert_eq!(
        header(reinit, "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "the handshake notification is part of the handshake and must stay \
         legacy-shaped, the same way `initialize` itself does"
    );
    assert!(
        reinit.body.get("params").is_none() || reinit.body["params"].get("_meta").is_none(),
        "a handshake notification must not carry a 2026 envelope; it sent {}",
        reinit.body
    );
    // The modern shape also strips `MCP-Session-Id` (MIK-7215.STATELESS.3a), so
    // a modern-shaped re-handshake would have dropped the session the peer just
    // issued. Pinning the header is what makes the third symptom observable.
    assert_eq!(
        header(reinit, "MCP-Session-Id"),
        "s1",
        "the legacy handshake keeps the session the peer issued"
    );
}

/// The three methods that must mirror a body field onto `Mcp-Name`, the field
/// each one mirrors, and a sentinel value the builder could not invent.
///
/// Distinct sentinels per method, deliberately: a presence assertion passes
/// against a header carrying any string, including one read from the wrong
/// field. An implementation that reads `params.name` for `resources/read`
/// sends the wrong sentinel and fails on the comparison rather than on
/// absence. The field per method is the production selector's own
/// (`mcp_name_body_field`, `src/protocol/headers.rs:63`), transcribed here so
/// the case disagrees with a selector that changes.
const NAMED_METHODS: &[(&str, &str, &str)] = &[
    ("tools/call", "name", "sentinel-tool-alpha"),
    ("prompts/get", "name", "sentinel-prompt-beta"),
    ("resources/read", "uri", "file:///sentinel-resource-gamma"),
];

/// Every path a shaped case is driven over.
const BOTH_PATHS: &[(Path, &str)] = &[(Path::Request, "request"), (Path::Notify, "notify")];

/// MIK-7214.HEADER.9a — a modern call names its own method.
#[tokio::test]
async fn a_modern_call_carries_its_method_on_both_paths() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, &[], &[]).await;
        assert_eq!(
            header(run.under_test("tools/list"), "Mcp-Method"),
            "tools/list",
            "the {label} path must name the method it is carrying"
        );
    }
}

/// MIK-7214.HEADER.9a — `Mcp-Name` mirrors the body field the method selects.
#[tokio::test]
async fn a_modern_named_call_mirrors_the_body_field_its_method_selects() {
    for (method, field, sentinel) in NAMED_METHODS {
        for (path, label) in BOTH_PATHS {
            let params = Some(json!({ *field: sentinel }));
            let run = Run::of(Peer::Modern, *path, method, params, &[], &[]).await;
            let wire = run.under_test(method);
            assert_eq!(
                header(wire, "Mcp-Name"),
                *sentinel,
                "on the {label} path {method} must mirror `params.{field}`, not \
                 whichever field happens to be present"
            );
        }
    }
}

/// MIK-7214.HEADER.9a — a method with no name source carries no `Mcp-Name`.
///
/// The negative half of the table. Without it, an implementation that emits
/// `Mcp-Name` unconditionally — reading any string it can find — passes every
/// row above.
#[tokio::test]
async fn a_modern_call_to_an_unnamed_method_carries_no_name_header() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({ "name": "a decoy the method does not address" }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        assert!(
            run.under_test("tools/list")
                .headers
                .get("Mcp-Name")
                .is_none(),
            "`tools/list` addresses no tool, prompt or resource, so the {label} \
             path must send no name — not the decoy beside it"
        );
    }
}

/// MIK-7214.HEADER.9a — a named method whose name source is missing or not a
/// string fails locally, before anything is sent.
#[tokio::test]
async fn a_modern_named_call_with_no_usable_name_source_fails_before_sending() {
    for (method, field, _) in NAMED_METHODS {
        // Built from the field the METHOD selects, not a hardcoded `name`: a
        // `resources/read` carrying a wrong-typed `name` is missing its `uri`
        // for the boring reason, and would pass without the check existing.
        let bad: &[Value] = &[
            json!({}),
            json!({ *field: 7 }),
            json!({ *field: null }),
            // Empty is rejected here rather than encoded: an empty header value
            // cannot round-trip back through `decode_header_value`.
            json!({ *field: "" }),
        ];
        for params in bad {
            for (path, _) in BOTH_PATHS {
                let run =
                    Run::of(Peer::Modern, *path, method, Some(params.clone()), &[], &[]).await;
                run.failed_before_sending(method);
            }
        }
    }
}

/// Read `params._meta` off a captured call, or say what the body held instead.
fn meta_of(wire: &Wire) -> &Value {
    wire.body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .unwrap_or_else(|| panic!("no `params._meta` in {}", wire.body))
}

/// MIK-7214.HEADER.9a — a modern call with no params still declares.
///
/// A builder that skips declaration when there is nothing to merge into sends
/// no `params` at all, and this fails on the object's absence.
#[tokio::test]
async fn a_modern_call_without_params_still_declares_the_envelope() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, &[], &[]).await;
        let meta = meta_of(run.under_test("tools/list"));
        let keys: Vec<&str> = meta
            .as_object()
            .unwrap_or_else(|| panic!("`_meta` must be an object on the {label} path"))
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION],
            "the {label} path must declare exactly the two required keys, and \
             `clientInfo` is not one of them"
        );
    }
}

/// MIK-7214.HEADER.9a — the caller's own params survive the merge.
#[tokio::test]
async fn a_modern_call_keeps_the_callers_params_beside_the_envelope() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({ "cursor": "caller-cursor-delta", "limit": 17 }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        let body = &run.under_test("tools/list").body;
        let sent = body
            .get("params")
            .unwrap_or_else(|| panic!("no params in {body}"));
        assert_eq!(
            sent.get("cursor").and_then(Value::as_str),
            Some("caller-cursor-delta"),
            "the {label} path must merge into the caller's params, not replace them"
        );
        assert_eq!(sent.get("limit").and_then(Value::as_i64), Some(17));
    }
}

/// MIK-7214.HEADER.9a — a caller's own `_meta` keys survive; this design's own
/// two are overwritten.
///
/// The fixture pre-sets both a foreign key and one of the two design keys to a
/// wrong value: a wholesale replace loses the first, a merge that skips keys
/// already present keeps the second.
#[tokio::test]
async fn a_modern_call_merges_into_an_existing_meta_without_losing_foreign_keys() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({
            "_meta": {
                "io.example/trace": "foreign-trace-epsilon",
                KEY_CLIENT_INFO: { "name": "a caller's own, neither inserted nor stripped" },
                KEY_PROTOCOL_VERSION: "1999-01-01",
            }
        }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        let meta = meta_of(run.under_test("tools/list"));
        assert_eq!(
            meta.get("io.example/trace").and_then(Value::as_str),
            Some("foreign-trace-epsilon"),
            "the {label} path must not drop a caller's foreign `_meta` key"
        );
        assert!(
            meta.get(KEY_CLIENT_INFO).is_some(),
            "a caller's own clientInfo is neither inserted nor stripped by this design"
        );
        assert_eq!(
            meta.get(KEY_PROTOCOL_VERSION).and_then(Value::as_str),
            Some(MODERN_VERSIONS[0]),
            "this design owns the protocol-version key and must overwrite a \
             caller's stale value on the {label} path"
        );
    }
}

/// MIK-7214.HEADER.9a — a non-object `params` fails locally, before any send.
#[tokio::test]
async fn a_modern_call_with_non_object_params_fails_before_sending() {
    let bad: &[Value] = &[json!(null), json!("a string"), json!(7), json!([1, 2])];
    for params in bad {
        for (path, _) in BOTH_PATHS {
            let run = Run::of(
                Peer::Modern,
                *path,
                "tools/list",
                Some(params.clone()),
                &[],
                &[],
            )
            .await;
            run.failed_before_sending("tools/list");
        }
    }
}

/// MIK-7214.HEADER.9a — a `_meta` that is not an object fails locally.
///
/// An implementation that overwrites destroys caller data and passes a happy
/// path; one that forwards unchanged emits no `clientCapabilities` and is
/// rejected `-32602` by a real modern peer, which no local assertion catches.
#[tokio::test]
async fn a_modern_call_with_a_non_object_meta_fails_before_sending() {
    let bad: &[Value] = &[json!(null), json!("a string"), json!(7), json!([1, 2])];
    for meta in bad {
        for (path, _) in BOTH_PATHS {
            let params = Some(json!({ "_meta": meta.clone() }));
            let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
            run.failed_before_sending("tools/list");
        }
    }
}

/// The three headers this design owns, and a custom value for each that the
/// builder could never produce.
///
/// Values chosen so a pin that leaks reads as an operator's, not as a plausible
/// gateway output: `1999-01-01` is not a revision, and neither name is a method.
const PINNED: &[(&str, &str)] = &[
    ("MCP-Protocol-Version", "1999-01-01"),
    ("Mcp-Method", "operator/override"),
    ("Mcp-Name", "operator-supplied-name"),
];

/// MIK-7214.HEADER.9b — this design's values survive operator configuration,
/// at both merge sites and on both paths.
///
/// On `Request` finalisation must run after the per-request `extra_headers`
/// merge (`mod.rs:846-854`), so an implementation inside `build_mcp_headers`
/// passes the static half and fails the per-request half. On `Notify` there is
/// no per-request merge at all (`mod.rs:1051-1053`), so an implementation that
/// finalises only in `send_request_with_headers` sends the operator's values
/// and fails every notify assertion.
#[tokio::test]
async fn this_designs_headers_outrank_operator_configuration_at_both_merge_sites() {
    let expected: &[(&str, &str)] = &[
        ("MCP-Protocol-Version", MODERN_VERSIONS[0]),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "sentinel-tool-alpha"),
    ];
    for (path, label) in BOTH_PATHS {
        // Static configuration on both paths; the per-request merge exists on
        // `Request` only, so the notify row drives statics alone.
        let extra: &[(&str, &str)] = match path {
            Path::Request => PINNED,
            Path::Notify => &[],
        };
        let params = Some(json!({ "name": "sentinel-tool-alpha" }));
        let run = Run::of(Peer::Modern, *path, "tools/call", params, PINNED, extra).await;
        let wire = run.under_test("tools/call");
        for (name, value) in expected {
            assert_eq!(
                header(wire, name),
                *value,
                "on the {label} path {name} must come from this design, not from \
                 the operator's configuration"
            );
        }
    }
}

/// MIK-7215.STATELESS.3a — a modern call sends no session header, neither the
/// minted one nor an operator's.
///
/// The prohibition is on emission, not on minting: a fixture with an empty
/// session map passes an absence assertion without the removal existing, which
/// is why a priming ordinary response mints one and `under_test` proves that
/// response preceded the call under test. The custom static value is the second half — an
/// implementation that only skips the mint still forwards the operator's.
#[tokio::test]
async fn a_modern_call_sends_neither_the_minted_nor_the_configured_session() {
    let configured: &[(&str, &str)] = &[("MCP-Session-Id", "operator-session-zeta")];
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, configured, &[]).await;
        assert!(
            run.under_test("tools/list")
                .headers
                .get("Mcp-Session-Id")
                .is_none(),
            "the {label} path must carry no session header on a modern peer; saw {:?} across {}",
            run.under_test("tools/list").headers,
            run.methods()
        );
    }
}

/// MIK-7215.STATELESS.3a — the legacy rows still carry the minted session.
///
/// The counterweight. Without it, an implementation that strips the session
/// header unconditionally passes the case above and silently breaks every
/// legacy backend.
#[tokio::test]
async fn a_legacy_call_still_carries_the_minted_session() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Legacy, *path, "tools/list", None, &[], &[]).await;
        assert_eq!(
            header(run.under_test("tools/list"), "Mcp-Session-Id"),
            "s1",
            "a legacy peer's {label} path is byte-for-byte what it was, session \
             header included"
        );
    }
}

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
