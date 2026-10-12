// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The listeners the MIK-8350 audience rows read: a bare legacy receiver, a
//! real GET stream, or a `subscriptions/listen` stream, each reporting the
//! `tools/list_changed` frames it was sent.

use futures::StreamExt as _;
use serde_json::{Value, json};
use tokio::sync::broadcast::Receiver;

use super::audience_fixture::{ARRIVAL, LIST_CHANGED, SENTINEL, World};
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
    async fn next_unbounded(&mut self) -> Option<Value> {
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
    Legacy(Receiver<SessionFrame>),
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
            Self::Legacy(rx) => {
                let mut methods = Vec::new();
                while let Ok(frame) = rx.try_recv() {
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
                &*crate::gateway::router::tests::view_judge_for(&self.state),
            )
            .await;
        self.minted.borrow_mut().insert(id.to_string(), minted);
        Ear::Legacy(rx)
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
                &*crate::gateway::router::tests::view_judge_for(&self.state),
            )
            .await;
        self.minted.borrow_mut().insert(id.to_string(), minted);
        Ear::Legacy(rx)
    }
}
