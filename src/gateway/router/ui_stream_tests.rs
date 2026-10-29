// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U3: `GET /ui/api/stream` through `create_router`, so the real
//! auth layer decides every caller. Time is the runtime's own paused clock and
//! session age is moved with `backdate`: no test sleeps.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, BodyDataStream};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use futures::StreamExt;
use tower::ServiceExt;

use super::tests::{http_backend_at, test_router_app_state_with_auth_and_key_server};
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
use crate::gateway::ui::stream::{MAX_PER_CREDENTIAL, MAX_UI_STREAMS};

const BEARER: &str = "u3-bearer";
const KEY: &str = "u3-standard-key";
const STREAM: &str = "/ui/api/stream";
const STATUS: &str = "/ui/api/status";
const GUARD: Duration = Duration::from_secs(30);
/// A revocation must end a stream within a few 1 s re-check ticks.
const REVOKED_WITHIN: Duration = Duration::from_secs(3);

fn standard_key() -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(KEY.as_bytes())),
        name: KEY.to_string(),
        backends: vec!["*".to_string()],
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// The built gateway with the clock still running. A test that bounds time
/// calls `tokio::time::pause()` itself right after, so its virtual clock is
/// visible where the bound is asserted.
async fn fixture_unpaused() -> (Arc<AppState>, impl Sized) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![standard_key()],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

/// The built gateway with time stopped; real I/O is done by then.
async fn fixture() -> (Arc<AppState>, impl Sized) {
    let made = fixture_unpaused().await;
    tokio::time::pause();
    made
}

/// How a request presents itself.
#[derive(Clone, Copy)]
enum Who<'a> {
    Nobody,
    Bearer(&'a str),
    Cookie(&'a str),
    /// A bearer with a session cookie beside it.
    Both(&'a str, &'a str),
}

fn request(uri: &str, who: Who<'_>, last_event_id: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))));
    b = match who {
        Who::Nobody => b,
        Who::Bearer(t) => b.header(header::AUTHORIZATION, format!("Bearer {t}")),
        Who::Cookie(h) => b.header(header::COOKIE, format!("{SESSION_COOKIE}={h}")),
        Who::Both(t, h) => b
            .header(header::AUTHORIZATION, format!("Bearer {t}"))
            .header(header::COOKIE, format!("{SESSION_COOKIE}={h}")),
    };
    if let Some(id) = last_event_id {
        b = b.header("last-event-id", id);
    }
    b.body(Body::empty()).expect("request builds")
}

/// One frame as the browser would see it.
#[derive(Debug)]
struct Frame {
    event: String,
    id: Option<String>,
    data: String,
    retry: Option<u64>,
}

impl Frame {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.data).unwrap_or_default()
    }
    /// The composite id's part `tag` (`s`, `r`, `q`, `b`, `i`, `g`).
    fn part(&self, tag: char) -> Option<String> {
        let id = self.id.as_deref()?;
        id.split('.')
            .find_map(|p| p.strip_prefix(tag).map(str::to_owned))
    }
}

struct Open {
    status: StatusCode,
    headers: HeaderMap,
    body: BodyDataStream,
    buf: String,
}

async fn open(state: &Arc<AppState>, req: Request<Body>) -> Open {
    let resp = create_router(Arc::clone(state))
        .oneshot(req)
        .await
        .expect("infallible");
    Open {
        status: resp.status(),
        headers: resp.headers().clone(),
        body: resp.into_body().into_data_stream(),
        buf: String::new(),
    }
}

impl Open {
    /// The next frame; `None` when the stream ended. Comments come back with
    /// the event `comment`.
    async fn next(&mut self) -> Option<Frame> {
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let raw: String = self.buf.drain(..end + 2).collect();
                return Some(parse(&raw));
            }
            let chunk = tokio::time::timeout(GUARD * 200, self.body.next())
                .await
                .ok()??;
            self.buf.push_str(&String::from_utf8_lossy(&chunk.ok()?));
        }
    }

    /// The next frame whose event is `event`, skipping the others.
    async fn until(&mut self, event: &str) -> Frame {
        for _ in 0..1000 {
            let f = self.next().await.expect("the stream is still open");
            if f.event == event {
                return f;
            }
        }
        panic!("no `{event}` frame");
    }

    /// Ended, and within `bound` on the runtime's clock.
    async fn ended_within(&mut self, bound: Duration) -> bool {
        let began = tokio::time::Instant::now();
        self.ended().await && began.elapsed() <= bound
    }

    async fn ended(&mut self) -> bool {
        for _ in 0..1000 {
            if self.next().await.is_none() {
                return true;
            }
        }
        false
    }
}

fn parse(raw: &str) -> Frame {
    let mut f = Frame {
        event: "comment".to_owned(),
        id: None,
        data: String::new(),
        retry: None,
    };
    for line in raw.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            v.trim().clone_into(&mut f.event);
        } else if let Some(v) = line.strip_prefix("id:") {
            f.id = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("retry:") {
            f.retry = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("data:") {
            f.data.push_str(v.trim());
        }
    }
    f
}

fn limits(state: &AppState) -> SessionLimits {
    SessionLimits::from(&state.live_config.get().auth.dashboard_session)
}

fn issue(state: &AppState) -> String {
    state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits(state))
}

async fn yield_until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if done() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    done()
}

mod auth;
mod backpressure;
mod frames;
mod generations;
mod handover;
mod identity;
mod load;
