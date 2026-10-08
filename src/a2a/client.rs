// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A2A 1.0 JSON-RPC client over the backend's guarded HTTP client.
//!
//! The `reqwest::Client` is built by the caller from
//! `transport::http::guarded_client`, so pinned resolution and the redirect
//! policy (same origin, SSRF-clean) apply to every request made here. This
//! module adds the one rule the HTTP transport never needed: the endpoint an
//! Agent Card advertises is agent-supplied and must share the configured
//! origin, so configured credentials never leave it.

use serde_json::{Value, json};
use url::Url;

use super::types::{AgentCard, DEFAULT_CARD_PATH, Message, PROTOCOL_VERSION, SendMessageResponse};
use crate::security::{diagnostic_url, safe_request_error, safe_reqwest_message};
use crate::{Error, Result};

/// The A2A 1.0 version header. `.json()` sets `Content-Type` itself.
const VERSION_HEADER: &str = "A2A-Version";

/// The JSON-RPC interface a call goes to, chosen from the card. Its URL can
/// carry the operator's `a2a_url` credentials, so it never prints them.
#[derive(Clone)]
pub(crate) struct Endpoint {
    pub url: String,
    pub tenant: Option<String>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("url", &diagnostic_url(&self.url))
            .field("tenant", &self.tenant)
            .finish()
    }
}

/// What one `SendMessage` came back as.
pub(crate) enum Reply {
    /// A `{task}` or `{message}` result.
    Answer(Box<SendMessageResponse>),
    /// The agent's own JSON-RPC error, passed on as the agent's.
    AgentError { code: i32, message: String },
}

pub(crate) struct A2aClient {
    http: reqwest::Client,
    origin: Url,
    card_url: String,
    headers: Vec<(String, String)>,
}

impl A2aClient {
    /// `a2a_url` must parse; `card_path` must be a path, never a URL.
    pub(crate) fn new(
        a2a_url: &str,
        card_path: Option<&str>,
        headers: Vec<(String, String)>,
        http: reqwest::Client,
    ) -> Result<Self> {
        let origin = Url::parse(a2a_url).map_err(|e| {
            Error::Config(format!(
                "a2a_url {} is not a URL: {e}",
                diagnostic_url(a2a_url)
            ))
        })?;
        let path = card_path.unwrap_or(DEFAULT_CARD_PATH);
        if !path.starts_with('/') || path.contains("://") {
            return Err(Error::Config(format!(
                "a2a_agent_card_path must be a path starting with '/', got {path:?}"
            )));
        }
        // The card lives at a path on the agent's origin, whatever path,
        // query or fragment `a2a_url` itself carries.
        let mut card_url = origin.clone();
        card_url.set_path(path);
        card_url.set_query(None);
        card_url.set_fragment(None);
        let card_url = card_url.to_string();
        Ok(Self {
            http,
            origin,
            card_url,
            headers,
        })
    }

    /// The configured target, credentials removed, for diagnostics.
    pub(crate) fn target(&self) -> String {
        diagnostic_url(self.origin.as_str())
    }

    /// Fetch the Agent Card (also the liveness probe).
    pub(crate) async fn fetch_card(&self) -> Result<AgentCard> {
        let request = self.with_headers(self.http.get(&self.card_url), &[]);
        let response = request.send().await.map_err(|e| {
            safe_request_error(
                &format!("A2A Agent Card fetch from {} failed", self.target()),
                &e,
            )
        })?;
        if !response.status().is_success() {
            return Err(Error::Protocol(format!(
                "A2A Agent Card at {} returned HTTP {}",
                diagnostic_url(&self.card_url),
                response.status()
            )));
        }
        let card = read_capped_json(response, "A2A Agent Card").await?;
        serde_json::from_value(card)
            .map_err(|e| Error::Protocol(format!("A2A Agent Card is malformed: {e}")))
    }

    /// The first JSON-RPC 1.x interface of `card`, held to the configured
    /// origin.
    pub(crate) fn endpoint(&self, card: &AgentCard) -> Result<Endpoint> {
        let Some(interface) = card.supported_interfaces.iter().find(|i| i.is_jsonrpc_v1()) else {
            let offered: Vec<String> = card
                .supported_interfaces
                .iter()
                .map(|i| format!("{} {}", i.protocol_binding, i.protocol_version))
                .collect();
            return Err(Error::Protocol(format!(
                "A2A agent at {} offers no JSONRPC 1.x interface (offered: [{}]); \
                 this gateway speaks A2A {PROTOCOL_VERSION}",
                self.target(),
                offered.join(", ")
            )));
        };
        let same_origin =
            Url::parse(&interface.url).is_ok_and(|url| url.origin() == self.origin.origin());
        if !same_origin {
            return Err(Error::Protocol(format!(
                "A2A agent card advertises endpoint {} on another origin than the configured {}; \
                 refusing to send configured credentials there",
                diagnostic_url(&interface.url),
                self.target()
            )));
        }
        Ok(Endpoint {
            url: with_credentials(&interface.url, &self.origin),
            tenant: interface.tenant.clone(),
        })
    }

    /// One blocking `SendMessage`.
    pub(crate) async fn send_message(
        &self,
        endpoint: &Endpoint,
        message: Message,
        extra_headers: &[(String, String)],
    ) -> Result<Reply> {
        let mut params = json!({
            "message": message,
            "configuration": {"acceptedOutputModes": ["text/plain", "application/json"]},
        });
        if let Some(tenant) = &endpoint.tenant {
            params["tenant"] = json!(tenant);
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "SendMessage",
            "params": params,
        });
        let request = self.with_headers(self.http.post(&endpoint.url).json(&body), extra_headers);
        let response = request.send().await.map_err(|e| {
            safe_request_error(
                &format!(
                    "A2A SendMessage to {} failed",
                    diagnostic_url(&endpoint.url)
                ),
                &e,
            )
        })?;
        if !response.status().is_success() {
            return Err(Error::Protocol(format!(
                "A2A SendMessage to {} returned HTTP {}",
                diagnostic_url(&endpoint.url),
                response.status()
            )));
        }
        decode_reply(&read_capped_json(response, "A2A SendMessage reply").await?)
    }

    /// Configured headers, then this request's own, then the protocol version.
    /// A per-request header replaces a configured one of the same name: a
    /// propagated identity must not travel beside the static credential.
    fn with_headers(
        &self,
        mut request: reqwest::RequestBuilder,
        extra_headers: &[(String, String)],
    ) -> reqwest::RequestBuilder {
        let overridden = |name: &str| {
            extra_headers
                .iter()
                .any(|(extra, _)| extra.eq_ignore_ascii_case(name))
        };
        // The protocol version is the bridge's to state: a configured or
        // per-request `A2A-Version` would put a second, conflicting one on
        // the wire.
        let version = |name: &str| name.eq_ignore_ascii_case(VERSION_HEADER);
        for (name, value) in self
            .headers
            .iter()
            .filter(|(name, _)| !overridden(name) && !version(name))
        {
            request = request.header(name.as_str(), value.as_str());
        }
        for (name, value) in extra_headers.iter().filter(|(name, _)| !version(name)) {
            request = request.header(name.as_str(), value.as_str());
        }
        request.header(VERSION_HEADER, PROTOCOL_VERSION)
    }
}

/// `endpoint` with the credentials `a2a_url` carries, when it carries none
/// of its own. The HTTP client sends URL credentials as `Authorization:
/// Basic`, so an operator who writes them into `a2a_url`, as curl takes them,
/// authenticates the card and the calls alike. The endpoint already shares
/// the configured origin, so the credentials go nowhere else.
fn with_credentials(endpoint: &str, origin: &Url) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_owned();
    };
    if url.username().is_empty() && url.password().is_none() && !origin.username().is_empty() {
        // Same origin: setting userinfo on it cannot fail.
        let _ = url.set_username(origin.username());
        let _ = url.set_password(origin.password());
    }
    url.to_string()
}

/// The largest card or reply this bridge reads, the default stdio frame
/// limit: an agent cannot make the gateway buffer an unbounded body.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Read `response` as JSON, refusing a body over [`MAX_BODY_BYTES`] as soon
/// as it is exceeded, before it is buffered whole.
async fn read_capped_json(mut response: reqwest::Response, what: &str) -> Result<Value> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Protocol(safe_reqwest_message(&format!("{what} read failed"), &e)))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(Error::Protocol(format!(
                "{what} exceeds {MAX_BODY_BYTES} bytes; refused"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| Error::Protocol(format!("{what} is not JSON: {e}")))
}

/// A JSON-RPC envelope as the agent's error or its `SendMessage` result.
fn decode_reply(envelope: &Value) -> Result<Reply> {
    // `"error": null` beside a result is a success some agents send; only an
    // error object is the agent's error.
    if let Some(error) = envelope.get("error").filter(|error| !error.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or(-32603);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("the agent returned an error without a message")
            .to_owned();
        return Ok(Reply::AgentError { code, message });
    }
    let result = envelope
        .get("result")
        .cloned()
        .ok_or_else(|| Error::Protocol("A2A reply has neither result nor error".into()))?;
    let reply: SendMessageResponse = serde_json::from_value(result)
        .map_err(|e| Error::Protocol(format!("A2A SendMessage result is malformed: {e}")))?;
    if reply.task.is_some() == reply.message.is_some() {
        return Err(Error::Protocol(
            "A2A SendMessage result must hold exactly one of task and message".into(),
        ));
    }
    Ok(Reply::Answer(Box::new(reply)))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
