// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The A2A agent as a backend [`Transport`].
//!
//! A `Transport`, not a separate provider path: every backend call already runs
//! through `Backend` and the invoke funnel (tool policy, firewall, budgets,
//! audit, relay detection, response gates), so an agent reached this way is
//! governed exactly like any tool backend without a second set of gates.
//!
//! What it answers, as a legacy-era MCP peer offering one tool:
//! `initialize` (synthetic), `ping` (a live card fetch), `tools/list` (the card
//! as one tool) and `tools/call` (one `SendMessage`). Everything else is
//! `-32601`, `server/discover` included, so the era probe settles on legacy.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::watch;

use super::client::{A2aClient, Endpoint, Reply};
use super::translator::{TOOL_NAME, card_to_tool, reply_to_result};
use super::types::{AgentCard, Message};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::ssrf::DestinationPolicy;
use crate::transport::Transport;
use crate::{Error, Result};

/// The MCP revision the synthetic `initialize` reports: the legacy one, since
/// this peer has no modern `_meta` channel.
const REPORTED_PROTOCOL_VERSION: &str = "2025-06-18";

pub(crate) struct A2aTransport {
    client: A2aClient,
    endpoint: Endpoint,
    card: AgentCard,
    /// `true` once closed. Every in-flight call watches it, so `close` aborts
    /// a pending HTTP request instead of letting it run to the timeout.
    closed: watch::Sender<bool>,
}

impl A2aTransport {
    /// Check the configured address, build the guarded client, read the card
    /// and choose its endpoint. Fails like any backend that cannot initialise.
    pub(crate) async fn start(
        a2a_url: &str,
        card_path: Option<&str>,
        headers: &HashMap<String, String>,
        timeout: Duration,
        destination: DestinationPolicy,
    ) -> Result<Arc<Self>> {
        let origin = url::Url::parse(a2a_url).map_err(|e| {
            Error::Config(format!(
                "a2a_url {} is not a URL: {e}",
                crate::security::diagnostic_url(a2a_url)
            ))
        })?;
        destination.check_literal(&origin)?;
        let http = crate::transport::guarded_client(
            origin,
            timeout,
            destination,
            Arc::new(AtomicU64::new(0)),
        )?;
        let headers = headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let client = A2aClient::new(a2a_url, card_path, headers, http)?;
        let card = client.fetch_card().await?;
        let endpoint = client.endpoint(&card)?;
        Ok(Arc::new(Self {
            client,
            endpoint,
            card,
            closed: watch::channel(false).0,
        }))
    }

    /// Run `call` unless the transport is, or becomes, closed.
    async fn unless_closed<T>(&self, call: impl Future<Output = Result<T>>) -> Result<T> {
        let mut closed = self.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|closed| *closed) => {
                Err(Error::Transport("A2A backend closed".into()))
            }
            outcome = call => outcome,
        }
    }

    async fn dispatch(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        let id = RequestId::Number(0);
        match method {
            "initialize" => Ok(JsonRpcResponse::success(
                id,
                json!({
                    "protocolVersion": REPORTED_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": self.card.name,
                        "version": self.card.version.as_deref().unwrap_or("unknown"),
                    },
                }),
            )),
            "ping" => {
                self.unless_closed(self.client.fetch_card()).await?;
                Ok(JsonRpcResponse::success(id, json!({})))
            }
            "tools/list" => {
                let card = self.unless_closed(self.client.fetch_card()).await?;
                Ok(JsonRpcResponse::success(
                    id,
                    json!({"tools": [card_to_tool(&card)]}),
                ))
            }
            "tools/call" => self.call_tool(id, params.as_ref(), extra_headers).await,
            other => Ok(JsonRpcResponse::error(
                Some(id),
                -32601,
                format!("Method not found: an A2A agent does not answer `{other}`"),
            )),
        }
    }

    async fn call_tool(
        &self,
        id: RequestId,
        params: Option<&Value>,
        extra_headers: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
        if name != Some(TOOL_NAME) {
            return Ok(JsonRpcResponse::error(
                Some(id),
                -32602,
                format!("Unknown tool {name:?}: an A2A agent offers only `{TOOL_NAME}`"),
            ));
        }
        let Some(text) = params
            .and_then(|p| p.pointer("/arguments/message"))
            .and_then(Value::as_str)
        else {
            return Ok(JsonRpcResponse::error(
                Some(id),
                -32602,
                format!("`{TOOL_NAME}` requires a `message` string argument"),
            ));
        };
        let reply = self
            .unless_closed(self.client.send_message(
                &self.endpoint,
                Message::user_text(text),
                extra_headers,
            ))
            .await?;
        Ok(match reply {
            Reply::Answer(answer) => JsonRpcResponse::success(id, reply_to_result(&answer)),
            Reply::AgentError { code, message } => {
                JsonRpcResponse::error(Some(id), code, format!("A2A agent error: {message}"))
            }
        })
    }
}

#[async_trait]
impl Transport for A2aTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.dispatch(method, params, &[]).await
    }

    /// Per-request headers (a propagated end-user credential) go on this one
    /// request and are never stored: tenant isolation (IDP.3).
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> Result<JsonRpcResponse> {
        self.dispatch(method, params, extra_headers).await
    }

    fn carries_identity_headers(&self) -> bool {
        true
    }

    /// A2A has no notification channel.
    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !*self.closed.borrow()
    }

    async fn close(&self) -> Result<()> {
        self.closed.send_replace(true);
        Ok(())
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
