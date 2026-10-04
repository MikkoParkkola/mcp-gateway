// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The WebSocket upgrade under a backend destination policy.
//!
//! `Configured` connects as today. `Public` resolves the name once, checks
//! every answer, opens TCP to a checked address, and only then runs TLS and
//! the upgrade with the ORIGINAL request, so SNI and `Host` keep the name the
//! operator configured while no second lookup can move the connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::{Request, Response};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async_tls, connect_async};

use crate::security::ssrf::{DestinationPolicy, HostResolver, SSRF_BLOCKED};
use crate::{Error, Result};

impl super::WebSocketTransport {
    pub(super) fn build(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        protocol_version: Option<String>,
        destination: DestinationPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            url: url.to_string(),
            headers,
            timeout,
            protocol_version,
            inner: super::Inner::new(),
            destination,
        })
    }

    /// [`Self::start`] under a backend destination policy.
    pub(crate) async fn start_with_destination(
        url: &str,
        headers: &HashMap<String, String>,
        timeout: Duration,
        protocol_version: Option<String>,
        destination: DestinationPolicy,
    ) -> Result<Arc<Self>> {
        let transport = Self::build(url, headers.clone(), timeout, protocol_version, destination);
        // Boxed: the TLS upgrade future is large, and inlining it would grow
        // every future that can start a backend (clippy::large_futures).
        Box::pin(transport.connect()).await?;
        Ok(transport)
    }

    /// The upgrade request for `url` carrying `headers`, built without touching
    /// the network: an error here means the target can never be connected to.
    /// No error carries more of the URL than that it is invalid, or a header
    /// value, which may be a credential.
    pub(crate) fn upgrade_request(url: &str, headers: &HashMap<String, String>) -> Result<Request> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

        let mut request = url
            .into_client_request()
            .map_err(|_| Error::Transport("WebSocket connect failed: invalid ws_url".into()))?;
        if !matches!(request.uri().scheme_str(), Some("ws" | "wss"))
            || request.uri().host().is_none()
        {
            return Err(Error::Transport(
                "WebSocket connect failed: invalid ws_url".into(),
            ));
        }
        for (name, value) in headers {
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                // The value is a credential; name the header only.
                return Err(Error::Transport(format!(
                    "WebSocket connect failed: header `{name}` is not a valid HTTP header"
                )));
            };
            request.headers_mut().insert(name, value);
        }
        Ok(request)
    }
}

/// An upgraded connection, as `connect_async` returns it.
pub(super) type Upgraded = (WebSocketStream<MaybeTlsStream<TcpStream>>, Response);

/// Open the upgrade for `request` under `destination`.
pub(super) async fn connect(
    request: Request,
    destination: DestinationPolicy,
    resolver: &impl HostResolver,
) -> Result<Upgraded> {
    match destination {
        DestinationPolicy::Configured => connect_async(request).await.map_err(|e| failed(&e)),
        DestinationPolicy::Public | DestinationPolicy::Private => {
            connect_pinned(request, destination, resolver).await
        }
    }
}

/// Resolve once through `resolver`, refuse any answer `check` denies, connect
/// TCP to a checked address, then TLS and upgrade with the original request.
pub(super) async fn connect_pinned(
    request: Request,
    check: DestinationPolicy,
    resolver: &impl HostResolver,
) -> Result<Upgraded> {
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| Error::Transport("WebSocket URL has no host".to_string()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let addresses = match host.parse::<IpAddr>() {
        Ok(literal) => vec![literal],
        Err(_) => resolver
            .lookup(&host)
            .await
            .map_err(|e| Error::Transport(format!("WebSocket connect failed: {e}")))?,
    };
    if let Some(denied) = addresses.iter().find(|ip| check.denies(**ip)) {
        // As the HTTP pin: the address is logged, never sent to the caller.
        tracing::warn!(host = %host, address = %denied, "SSRF pin refused a resolved address");
        return Err(Error::Protocol(format!(
            "{SSRF_BLOCKED}: '{host}' resolves to a private/reserved address"
        )));
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect((address, port)).await {
            // The original request: SNI and `Host` stay the configured name.
            Ok(stream) => {
                return client_async_tls(request, stream)
                    .await
                    .map_err(|e| failed(&e));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(Error::Transport(format!(
        "WebSocket connect failed: {}",
        last_error.map_or_else(|| "no address".to_string(), |e| e.to_string())
    )))
}

fn failed(error: &tokio_tungstenite::tungstenite::Error) -> Error {
    Error::Transport(format!(
        "WebSocket connect failed: {}",
        super::connect_error(error)
    ))
}

#[cfg(test)]
#[path = "websocket_pinned_tests.rs"]
mod tests;
