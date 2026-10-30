// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events listener's own session on a legacy HTTP+SSE backend
//! (MIK-8835.SSE.1): GET the SSE endpoint, take `endpoint` and keep the stream,
//! POST `initialize` (answered in the body or paired by id on the stream),
//! POST `notifications/initialized`, and only then let the legacy subscribe
//! walk run. It is separate from the calls' session, has its own
//! [`SseChannel`], and sends every request with its [`ListenerCredential`].

use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use reqwest::header;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::extra_headers::merge_extra_headers;
use super::listen::{STREAM_TIMEOUT, unsolicited_frame};
use super::sse_channel::{Sink, SseChannel};
use super::{HeaderMode, HttpTransport};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::security::http_diagnostics::safe_request_error;
use crate::transport::upstream_tap::{
    FrameStream, LegacyPin, ListenerCredential, Refused, Requested, TAP_CAPACITY, UpstreamListen,
    Watched, interest_method,
};
use crate::{Error, Result};

/// One listener run's session. Single use: one handshake, then the stream;
/// a reconnect builds a new session (design §1.1).
pub(crate) struct SseListenSession {
    transport: Weak<HttpTransport>,
    credential: ListenerCredential,
    channel: Mutex<Option<Arc<SseChannel>>>,
}

impl HttpTransport {
    /// A listener session over this transport's endpoint (design §1.3).
    pub(super) fn sse_listen_session(
        self: &Arc<Self>,
        credential: ListenerCredential,
    ) -> SseListenSession {
        SseListenSession {
            transport: Arc::downgrade(self),
            credential,
            channel: Mutex::new(None),
        }
    }
}

impl SseListenSession {
    fn transport(&self) -> Result<Arc<HttpTransport>> {
        self.transport
            .upgrade()
            .ok_or_else(|| Error::Transport("transport gone".to_owned()))
    }

    /// Headers for one request of this session: the transport's configured
    /// ones, without the calls' session id (this session's is in its URL).
    async fn headers(&self, t: &HttpTransport, mode: HeaderMode<'_>) -> Result<header::HeaderMap> {
        // The bucket is the lending source's identity when there is one.
        let identity = self
            .credential
            .source
            .as_ref()
            .and_then(|s| s.identity_key())
            .or(self.credential.identity_key.as_deref());
        // A lent credential's session carries protocol headers and the
        // source's only: never the gateway's own.
        let mut headers = if self.credential.source.is_some() {
            t.build_lent_headers(mode, identity).await?
        } else {
            t.build_mcp_headers(mode, identity, &[]).await?
        };
        headers.remove("mcp-session-id");
        Ok(headers)
    }

    /// Send what `build` makes, with the credential's headers merged in. A
    /// source that refuses means nothing is sent (design B11).
    async fn send(
        &self,
        mut headers: header::HeaderMap,
        build: impl FnOnce(header::HeaderMap) -> reqwest::RequestBuilder + Send,
    ) -> Result<reqwest::Response> {
        let Some(source) = self.credential.source.as_ref() else {
            return build(headers)
                .send()
                .await
                .map_err(|e| safe_request_error("listener request", &e));
        };
        source
            .with_credential(Box::new(move |extra| {
                Box::pin(async move {
                    merge_extra_headers(&mut headers, &extra);
                    build(headers)
                        .send()
                        .await
                        .map_err(|e| safe_request_error("listener request", &e))
                })
            }))
            .await
    }

    fn channel(&self) -> Result<Arc<SseChannel>> {
        self.channel
            .lock()
            .clone()
            .filter(|c| !c.is_closed())
            .ok_or_else(|| Error::Transport("listener SSE stream ended".to_owned()))
    }

    /// [`Self::request_unscrubbed`], its answer and error scrubbed of the
    /// backend's injected values: this path does not pass `read_answer`
    /// (MIK-9035).
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let needles = self.transport().ok().and_then(|t| t.needles.get().cloned());
        let answer = self.request_unscrubbed(method, params).await;
        match needles {
            Some(needles) => crate::security::needles::scrub_answer(&needles, answer),
            None => answer,
        }
    }

    /// One request on this session: its place on the stream first, then the
    /// POST; the answer from the body, or from the stream when the body is
    /// empty.
    async fn request_unscrubbed(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        let t = self.transport()?;
        let channel = self.channel()?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: t.next_id(),
            method: method.to_owned(),
            params,
        };
        let waiting = channel.register(&request.id)?;
        if channel.is_closed() {
            return Err(Error::Transport("listener SSE stream ended".to_owned()));
        }
        let headers = self.headers(&t, HeaderMode::Request { method }).await?;
        let endpoint = channel.endpoint().to_owned();
        let response = self
            .send(headers, |h| {
                t.client.post(endpoint).headers(h).json(&request)
            })
            .await?;
        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "listener {method} returned HTTP {}",
                response.status()
            )));
        }
        let accepted = response.status() == reqwest::StatusCode::ACCEPTED;
        let body = response
            .bytes()
            .await
            .map_err(|e| safe_request_error("listener response", &e))?;
        // 202 is "the answer comes on the stream" whatever its body.
        if accepted || body.iter().all(u8::is_ascii_whitespace) {
            return tokio::time::timeout(t.timeout, waiting.response())
                .await
                .map_err(|_| Error::Transport(format!("listener {method}: no answer in time")))?;
        }
        serde_json::from_slice(&body)
            .map_err(|e| Error::Protocol(super::parse_failure("listener answer", &e)))
    }

    async fn notify(&self, method: &str) -> Result<()> {
        let t = self.transport()?;
        let endpoint = self.channel()?.endpoint().to_owned();
        let headers = self.headers(&t, HeaderMode::Notify).await?;
        let body = json!({"jsonrpc": "2.0", "method": method});
        let response = self
            .send(headers, |h| t.client.post(endpoint).headers(h).json(&body))
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Transport(format!(
                "listener {method} returned HTTP {}",
                response.status()
            )))
        }
    }

    /// GET, `endpoint`, initialize, initialized (design §3).
    async fn handshake(&self, watched: Watched) -> std::result::Result<FrameStream, Refused> {
        if self.channel.lock().is_some() {
            return Err(Refused::Failed(Error::Transport(
                "a listener session opens once".to_owned(),
            )));
        }
        let t = self.transport()?;
        let headers = self.headers(&t, HeaderMode::Sse).await?;
        let base = t.base_url.clone();
        let response = self
            .send(headers, |h| {
                t.client.get(base).headers(h).timeout(STREAM_TIMEOUT)
            })
            .await?;
        match response.status().as_u16() {
            405 => return Err(Refused::Unsupported),
            404 => return Err(Refused::Expired),
            status if !(200..300).contains(&status) => {
                return Err(Refused::Failed(Error::Transport(format!(
                    "listener SSE GET returned HTTP {status}"
                ))));
            }
            _ => {}
        }
        let (tx, rx) = mpsc::channel(TAP_CAPACITY);
        // Watched on the note as sent, then scrubbed (DELTA-5, MIK-9035).
        let needles = t.needles.get().cloned();
        let sink = Sink {
            tx,
            map: Box::new(move |data| {
                unsolicited_frame(data)
                    .filter(|note| watched.admits(note))
                    .and_then(|note| super::listen::scrubbed(needles.as_deref(), note))
            }),
        };
        let channel = SseChannel::open(
            response,
            |data| t.resolve_message_url(data),
            Some(sink),
            t.body_budget.get().cloned(),
        )
        .await?;
        *self.channel.lock() = Some(Arc::clone(&channel));
        let version = t.protocol_version.read().clone();
        let initialized = self
            .request(
                "initialize",
                Some(json!({
                    "protocolVersion": version.unwrap_or_else(|| crate::protocol::PROTOCOL_VERSION.to_owned()),
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": env!("CARGO_PKG_VERSION")},
                })),
            )
            .await?;
        if let Some(error) = initialized.error {
            return Err(Refused::Failed(Error::Transport(format!(
                "listener initialize refused: {}",
                error.message
            ))));
        }
        self.notify("notifications/initialized").await?;
        // The stream is the session: its end ends the listener's run.
        Ok(FrameStream::guarded(rx, channel))
    }
}

#[async_trait::async_trait]
impl UpstreamListen for SseListenSession {
    async fn listen(
        self: Arc<Self>,
        _requested: Requested,
    ) -> std::result::Result<FrameStream, Refused> {
        Err(Refused::Unsupported)
    }

    async fn unsolicited(
        self: Arc<Self>,
        watched: Watched,
    ) -> std::result::Result<FrameStream, Refused> {
        self.handshake(watched).await
    }

    /// The holder is this session's endpoint (its session id is in the URL),
    /// so a new handshake is a new holder.
    fn legacy_pin(&self) -> LegacyPin {
        use std::hash::{Hash, Hasher};
        let endpoint = self
            .channel
            .lock()
            .as_ref()
            .map(|c| c.endpoint().to_owned());
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        endpoint.hash(&mut hasher);
        LegacyPin {
            holder: hasher.finish(),
            session: None,
        }
    }

    async fn legacy_interest(
        self: Arc<Self>,
        _pin: LegacyPin,
        uri: &str,
        subscribe: bool,
    ) -> Result<JsonRpcResponse> {
        self.request(interest_method(subscribe), Some(json!({ "uri": uri })))
            .await
    }

    fn detected_streamable(&self) -> Option<bool> {
        Some(false)
    }
}

#[cfg(test)]
#[path = "sse_listen_tests.rs"]
mod tests;
