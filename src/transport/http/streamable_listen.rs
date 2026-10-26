// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user listener's own session on a Streamable HTTP transport:
//! every request it sends (its `initialize`, the
//! listen POST, the session GET and legacy interest) carries its
//! subscriber's credential, on its own session bucket, and nothing of the
//! gateway's (C6).

use std::sync::{Arc, Weak};

use serde_json::{Value, json};

use super::listen::{OpenAs, refused_as};
use super::{HeaderMode, HttpTransport};
use crate::protocol::era::{EraCache, PeerEra, ProbeOutcome};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::transport::upstream_tap::{
    CredentialSource, FrameStream, LegacyPin, ListenerCredential, Refused, Requested,
    UpstreamListen, Watched, interest_method,
};
use crate::{Error, Result};

pub(crate) struct StreamableListenSession {
    transport: Weak<HttpTransport>,
    /// The subscriber's session bucket: their observation.
    bucket: String,
    source: Arc<dyn CredentialSource>,
    /// Held across a handshake, so concurrent opens share one.
    handshake: tokio::sync::Mutex<()>,
}

impl HttpTransport {
    /// A Streamable HTTP listener session sending as `credential`'s
    /// subscriber; `None` without a source to lend it, or a bucket to keep
    /// its session in.
    pub(super) fn streamable_listen_session(
        self: &Arc<Self>,
        credential: ListenerCredential,
    ) -> Option<StreamableListenSession> {
        let source = credential.source?;
        let bucket = source
            .identity_key()
            .map(str::to_owned)
            .or(credential.identity_key)?;
        Some(StreamableListenSession {
            transport: Arc::downgrade(self),
            bucket,
            source,
            handshake: tokio::sync::Mutex::new(()),
        })
    }
}

impl HttpTransport {
    /// A per-user listener's session on its own transport (built by
    /// `Backend::listener_transport`), and the era it speaks: the SSE
    /// handshake, legacy, when the backend is configured for it; Streamable
    /// HTTP otherwise, its era probed with the subscriber's credential into a
    /// cache of this transport's own. `None` without a credential to lend.
    pub(crate) async fn per_user_session(
        self: &Arc<Self>,
        backend: &str,
        credential: ListenerCredential,
    ) -> Option<(Arc<dyn UpstreamListen>, PeerEra)> {
        credential.source.as_ref()?;
        if self.streamable() == Some(false) {
            let session = Arc::new(self.sse_listen_session(credential));
            return Some((session, PeerEra::Legacy));
        }
        let session = self.streamable_listen_session(credential)?;
        let era = Arc::new(EraCache::for_slot(backend, "listener"));
        self.attach_era(Arc::clone(&era));
        let era = era.resolve_with(|| session.probe()).await;
        Some((Arc::new(session), era))
    }
}

impl StreamableListenSession {
    fn transport(&self) -> Result<Arc<HttpTransport>> {
        self.transport
            .upgrade()
            .ok_or_else(|| Error::Transport("transport gone".to_owned()))
    }

    fn who(&self) -> OpenAs<'_> {
        OpenAs::Lent {
            bucket: &self.bucket,
            source: &self.source,
        }
    }

    /// One request on this session, its answer read as a call's is.
    async fn call(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let t = self.transport()?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: t.next_id(),
            method: method.to_owned(),
            params,
        };
        let headers = self
            .who()
            .headers(&t, HeaderMode::Request { method })
            .await?;
        let url = t.get_message_url();
        let response = self
            .who()
            .send(headers, |h| {
                t.client.post(url.clone()).headers(h).json(&request)
            })
            .await?;
        t.read_answer(&request, response, &url, Some(&self.bucket), None)
            .await
    }

    /// `server/discover` as the subscriber, read as the start path's probe
    /// is; the meaning of the answer stays in `classify`.
    async fn probe(&self) -> ProbeOutcome {
        let Ok(answer) = self.call("server/discover", None).await else {
            return ProbeOutcome::NoAnswer;
        };
        if let Some(error) = answer.error {
            return ProbeOutcome::Error(error.code);
        }
        answer
            .result
            .map_or(ProbeOutcome::NoAnswer, ProbeOutcome::Result)
    }

    async fn notify(&self, method: &str) -> Result<()> {
        let t = self.transport()?;
        let headers = self.who().headers(&t, HeaderMode::Notify).await?;
        let body = json!({"jsonrpc": "2.0", "method": method});
        let url = t.get_message_url();
        let response = self
            .who()
            .send(headers, |h| t.client.post(url).headers(h).json(&body))
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

    /// The subscriber's own handshake, when the peer keeps sessions (the
    /// legacy era) and their bucket holds none: once at the start, and again
    /// after a 404 dropped it. A modern peer is sessionless.
    async fn ensure_session(&self) -> Result<()> {
        let t = self.transport()?;
        if t.outbound_era() == Some(PeerEra::Modern) {
            return Ok(());
        }
        let _held = self.handshake.lock().await;
        let has = t
            .sessions
            .read()
            .contains_key(HttpTransport::bucket_key(Some(&self.bucket)));
        if has {
            return Ok(());
        }
        let version = t
            .protocol_version
            .read()
            .clone()
            .unwrap_or_else(|| crate::protocol::PROTOCOL_VERSION.to_owned());
        let answer = self
            .call(
                "initialize",
                Some(json!({
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-gateway", "version": env!("CARGO_PKG_VERSION")},
                })),
            )
            .await?;
        if answer.error.is_some() {
            return Err(Error::Transport("listener initialize refused".to_owned()));
        }
        // The server selects; its choice governs this session's
        // `MCP-Protocol-Version` from here on, as on a slot's handshake.
        let selection = crate::protocol::negotiate::Selectable::Legacy;
        if let Some(selected) =
            crate::protocol::negotiate::checked_selection(answer.result.as_ref(), selection)?
        {
            *t.protocol_version.write() = Some(selected.to_string());
        }
        self.notify("notifications/initialized").await
    }
}

#[async_trait::async_trait]
impl UpstreamListen for StreamableListenSession {
    async fn listen(
        self: Arc<Self>,
        requested: Requested,
    ) -> std::result::Result<FrameStream, Refused> {
        self.ensure_session().await?;
        let t = self.transport()?;
        let opened = t.open_listen_as(requested, &self.who()).await?;
        refused_as("listen", opened.map(FrameStream::new))
    }

    async fn unsolicited(
        self: Arc<Self>,
        watched: Watched,
    ) -> std::result::Result<FrameStream, Refused> {
        self.ensure_session().await?;
        let t = self.transport()?;
        let opened = t.open_session_stream_as(watched, &self.who()).await?;
        refused_as("session stream", opened.map(FrameStream::new))
    }

    fn detected_streamable(&self) -> Option<bool> {
        Some(true)
    }

    /// The holder is the subscriber's own session: a new handshake is a new
    /// holder.
    fn legacy_pin(&self) -> LegacyPin {
        use std::hash::{Hash, Hasher};
        let session = self.transport.upgrade().and_then(|t| {
            t.sessions
                .read()
                .get(HttpTransport::bucket_key(Some(&self.bucket)))
                .cloned()
        });
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.hash(&mut hasher);
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
        self.ensure_session().await?;
        self.call(interest_method(subscribe), Some(json!({ "uri": uri })))
            .await
    }
}

#[cfg(test)]
#[path = "streamable_listen_tests.rs"]
mod tests;
