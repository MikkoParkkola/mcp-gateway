// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The listeners the MIK-8350 audience rows read: a bare legacy receiver, a
//! real GET stream, or a `subscriptions/listen` stream, each reporting the
//! `tools/list_changed` frames it was sent.

use futures::StreamExt as _;
use serde_json::{Value, json};
use tokio::sync::broadcast::Receiver;

use axum::body::Body;
use tower::ServiceExt as _;

use super::audience_fixture::{ARRIVAL, LIST_CHANGED, SENTINEL, World, asserted};
use crate::gateway::streaming::SessionFrame;

/// A listen response body read as SSE `data:` events.
pub(super) struct Events {
    pub(super) stream: std::pin::Pin<Box<axum::body::BodyDataStream>>,
    pub(super) buffer: String,
}

impl Events {
    /// The next event, or `None` if the stream ends or `ARRIVAL` passes.
    pub(super) async fn next(&mut self) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + ARRIVAL;
        self.next_by(Some(deadline)).await
    }

    /// The next event, waiting without a deadline; `None` only when the
    /// stream ends. A real client reads continuously, which is what drives
    /// the server's write loop.
    pub(super) async fn next_unbounded(&mut self) -> Option<Value> {
        self.next_by(None).await
    }

    async fn next_by(&mut self, deadline: Option<tokio::time::Instant>) -> Option<Value> {
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                if let Some(data) = block.lines().find_map(|l| l.strip_prefix("data:"))
                    && let Ok(value) = serde_json::from_str(data.trim())
                {
                    return Some(value);
                }
                continue;
            }
            let chunk = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, self.stream.next())
                    .await
                    .ok()??
                    .ok()?,
                None => self.stream.next().await?.ok()?,
            };
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
}

/// One listener: a legacy GET session, a real GET stream or a listen stream.
pub(super) enum Ear {
    /// A bare receiver of the session's queue, with the session it reads: a
    /// real stream checks the credential again as it writes a frame, so
    /// this ear does too.
    Legacy(Receiver<SessionFrame>, String),
    /// A GET stream read through the real route: the write path runs. A task
    /// reads its body continuously into `events`, as a real client does.
    Sse {
        events: tokio::sync::mpsc::UnboundedReceiver<Value>,
        session: String,
    },
    Listen(Events),
}

impl Ear {
    /// The session a GET stream belongs to.
    pub(super) fn session_id(&self) -> &str {
        match self {
            Self::Sse { session, .. } => session,
            _ => panic!("only a GET stream has a session id"),
        }
    }

    /// The methods of every frame this listener was sent since the last call,
    /// once the drain has delivered all queued changes.
    pub(super) async fn frames(&mut self, world: &World) -> Vec<String> {
        world.settle().await;
        match self {
            Self::Legacy(rx, session) => {
                let mut methods = Vec::new();
                while let Ok(frame) = rx.try_recv() {
                    if !world
                        .state
                        .multiplexer
                        .passes_write_gate(session, &frame)
                        .await
                    {
                        continue;
                    }
                    methods.push(
                        frame.data["method"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
                methods
            }
            Self::Sse { events, session } => {
                // The sentinel rides this session's own stream, past the same
                // write check as every frame, so everything queued before it
                // is read first. A stream the write check closed ends here.
                world.state.multiplexer.send_to_session(
                    session,
                    crate::gateway::streaming::TaggedNotification {
                        source: "gateway".to_string(),
                        event_type: "message".to_string(),
                        data: json!({ "jsonrpc": "2.0", "method": SENTINEL }),
                        event_id: None,
                    },
                );
                let mut methods = Vec::new();
                while let Ok(Some(event)) = tokio::time::timeout(ARRIVAL, events.recv()).await {
                    let method = event["method"].as_str().unwrap_or_default().to_string();
                    if method == SENTINEL {
                        return methods;
                    }
                    // The stream's own `connected` event carries no method.
                    if !method.is_empty() {
                        methods.push(method);
                    }
                }
                methods
            }
            Self::Listen(events) => {
                // Every listener receives every sentinel, so each call marks
                // its own: another ear's older one, still queued here, is not
                // the end of this read.
                static MARK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let mark = MARK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                world.state.subscriptions.publish(json!({
                    "jsonrpc": "2.0", "method": SENTINEL, "params": { "mark": mark }
                }));
                let mut methods = Vec::new();
                while let Some(event) = events.next().await {
                    let method = event["method"].as_str().unwrap_or_default().to_string();
                    if method == SENTINEL {
                        if event["params"]["mark"] == json!(mark) {
                            return methods;
                        }
                        continue;
                    }
                    methods.push(method);
                }
                panic!("the listen stream ended before its sentinel: {methods:?}");
            }
        }
    }

    /// Whether a listen stream has been closed by the server: after the
    /// sentinel is published, the stream ends before the sentinel arrives.
    pub(super) async fn closed(&mut self, world: &World) -> bool {
        let Self::Listen(events) = self else {
            panic!("closed() reads a listen stream");
        };
        world.settle().await;
        world.state.subscriptions.publish(json!({
            "jsonrpc": "2.0", "method": SENTINEL, "params": { "mark": u64::MAX }
        }));
        while let Some(event) = events.next().await {
            if event["params"]["mark"] == json!(u64::MAX) {
                return false;
            }
        }
        true
    }

    /// How many `tools/list_changed` frames this listener was sent.
    pub(super) async fn told(&mut self, world: &World) -> usize {
        self.frames(world)
            .await
            .iter()
            .filter(|m| *m == LIST_CHANGED)
            .count()
    }
}

impl World {
    /// A gateway whose `/mcp` is a public path.
    pub(super) async fn start_public() -> Self {
        let key_server = std::sync::Arc::new(crate::key_server::KeyServer::new(
            crate::config::KeyServerConfig::default(),
        ));
        Self::start_on(
            key_server,
            None,
            |meta| meta,
            super::audience_access::McpAccess::PublicPath,
        )
        .await
    }

    /// A gateway whose mTLS policy admits a presented certificate to `alpha`.
    pub(super) async fn start_mtls() -> Self {
        let key_server = std::sync::Arc::new(crate::key_server::KeyServer::new(
            crate::config::KeyServerConfig::default(),
        ));
        Self::start_on(
            key_server,
            None,
            |meta| meta,
            super::audience_access::McpAccess::MtlsCert,
        )
        .await
    }

    /// A gateway with agent auth on; callers present [`agent_token`].
    pub(super) async fn start_agent() -> Self {
        let key_server = std::sync::Arc::new(crate::key_server::KeyServer::new(
            crate::config::KeyServerConfig::default(),
        ));
        Self::start_on(
            key_server,
            None,
            |meta| meta,
            super::audience_access::McpAccess::AgentToken,
        )
        .await
    }

    /// A GET stream that presents no credential: the route's status, and the
    /// stream when it opened.
    pub(super) async fn anonymous_sse(&self) -> (axum::http::StatusCode, Option<Ear>) {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .body(Body::empty())
            .expect("a request");
        let response = self.router.clone().oneshot(request).await.expect("served");
        let status = response.status();
        if !status.is_success() {
            return (status, None);
        }
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .expect("the stream names its session")
            .to_string();
        let mut body = Events {
            stream: Box::pin(response.into_body().into_data_stream()),
            buffer: String::new(),
        };
        let (tx, events) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(event) = body.next_unbounded().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });
        (status, Some(Ear::Sse { events, session }))
    }

    /// As [`Self::legacy`], owned as the router owns it, so a POST under
    /// `bearer` may carry its session id ([`Self::post_in`]).
    pub(super) async fn legacy_owned(&self, id: &str, bearer: &str) -> Ear {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().expect("a header value"),
        );
        let held = crate::gateway::auth::live::held_credential(&headers);
        let owner = crate::gateway::router::tests::audience_owner(&self.state, held.as_ref()).await;
        let (minted, rx) =
            self.state
                .multiplexer
                .get_or_create_session_scoped(Some(id), &owner, held);
        self.state
            .multiplexer
            .take_baseline(
                &minted,
                &crate::gateway::router::tests::view_judge_for(&self.state),
            )
            .await;
        self.minted
            .borrow_mut()
            .insert(id.to_string(), minted.clone());
        Ear::Legacy(rx, minted)
    }

    /// A legacy GET session opened with exactly these request headers.
    pub(super) async fn legacy_with(&self, id: &str, presented: &[(&str, String)]) -> Ear {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in presented {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                value.parse().expect("a header value"),
            );
        }
        let held = crate::gateway::auth::live::held_credential(&headers);
        let owner = crate::gateway::session_id::SessionOwner::Credential(id.to_string());
        let (minted, rx) =
            self.state
                .multiplexer
                .get_or_create_session_scoped(Some(id), &owner, held);
        // As the GET handler does when a stream attaches (MIK-8350).
        self.state
            .multiplexer
            .take_baseline(
                &minted,
                &crate::gateway::router::tests::view_judge_for(&self.state),
            )
            .await;
        self.minted
            .borrow_mut()
            .insert(id.to_string(), minted.clone());
        Ear::Legacy(rx, minted)
    }
}

impl World {
    /// A 2026 `subscriptions/listen` stream held by `bearer`, past its
    /// acknowledgement, through the real route.
    pub(super) async fn listen(&self, bearer: &str) -> Ear {
        self.listen_as(bearer, None).await
    }

    /// As [`Self::listen`], with an Open `WebUI` `assertion`.
    pub(super) async fn listen_as(&self, bearer: &str, assertion: Option<&str>) -> Ear {
        let mut ear = self.listen_undrained(bearer, assertion).await;
        // The constant attach hint (M-B10) is not a change: rows count what a
        // change sends after attach, so it is read here and set aside.
        let Ear::Listen(events) = &mut ear else {
            unreachable!("a listen stream")
        };
        events
            .next()
            .await
            .expect("the attach hint follows the acknowledgement");
        ear
    }

    /// As [`Self::listen_as`], stopping at the acknowledgement: the attach
    /// hint is still unread.
    pub(super) async fn listen_undrained(&self, bearer: &str, assertion: Option<&str>) -> Ear {
        self.listen_request(bearer, assertion, ("/mcp", None), |_| {})
            .await
    }

    /// As [`Self::listen`], with `extend` applied to the request first: the
    /// request extensions the TLS layer would insert (a client certificate,
    /// its `notAfter`), for MIK-8377's identity-liveness rows.
    pub(super) async fn listen_with(
        &self,
        bearer: &str,
        extend: impl FnOnce(&mut axum::http::Request<Body>),
    ) -> Ear {
        let mut ear = self
            .listen_request(bearer, None, ("/mcp", None), extend)
            .await;
        let Ear::Listen(events) = &mut ear else {
            unreachable!("a listen stream")
        };
        events.next().await.expect("the attach hint");
        ear
    }

    /// A listen at `uri`, inside legacy session `session` (its minted id)
    /// when given, past its attach hint.
    pub(super) async fn listen_at(&self, bearer: &str, uri: &str, session: Option<&str>) -> Ear {
        let minted = session.map(|id| self.minted.borrow().get(id).cloned().expect("a session"));
        let mut ear = self
            .listen_request(bearer, None, (uri, minted.as_deref()), |_| {})
            .await;
        let Ear::Listen(events) = &mut ear else {
            unreachable!("a listen stream")
        };
        events.next().await.expect("the attach hint");
        ear
    }

    async fn listen_request(
        &self,
        bearer: &str,
        assertion: Option<&str>,
        (uri, session): (&str, Option<&str>),
        extend: impl FnOnce(&mut axum::http::Request<Body>),
    ) -> Ear {
        let body = json!({
            "jsonrpc": "2.0", "id": "listen", "method": "subscriptions/listen",
            "params": {
                "notifications": { "toolsListChanged": true, "resourcesListChanged": true },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "subscriptions/listen")
            .header("accept", "application/json, text/event-stream");
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        let request = request
            .body(Body::from(body.to_string()))
            .expect("a request");
        let mut request = request;
        asserted(&mut request, assertion);
        extend(&mut request);
        let response = self.router.clone().oneshot(request).await.expect("served");
        assert!(
            response.status().is_success(),
            "listen refused: {}",
            response.status()
        );
        let mut events = Events {
            stream: Box::pin(response.into_body().into_data_stream()),
            buffer: String::new(),
        };
        events
            .next()
            .await
            .expect("the acknowledgement opens the stream");
        Ear::Listen(events)
    }
}
