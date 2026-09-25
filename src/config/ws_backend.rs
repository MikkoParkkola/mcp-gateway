// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config rules for `ws_url` backends (F17): URL constructors and load checks.

use super::{BackendConfig, Config, TransportConfig};
use crate::secret_injection::InjectTarget;
use crate::{Error, Result};

impl TransportConfig {
    /// Build the transport a bare URL selects: `ws`/`wss` (any case) is a
    /// WebSocket backend, anything else HTTP. Every site that turns a pasted
    /// or discovered URL into a backend goes through here, so a `wss://` URL
    /// can never become a broken HTTP backend.
    pub(crate) fn for_url(url: &str) -> Self {
        let scheme = url.split_once("://").map_or("", |(scheme, _)| scheme);
        if scheme == "ws" || scheme == "wss" {
            return Self::WebSocket {
                ws_url: url.to_string(),
                protocol_version: None,
            };
        }
        Self::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        }
    }
}

/// First protocol revision with no `initialize` handshake. Revisions are ISO
/// dates, so string order is date order.
const FIRST_STATELESS_REVISION: &str = "2026-07-28";

impl Config {
    /// Load checks for one `ws_url` backend. No message echoes the URL: it is
    /// the one that may carry userinfo or a token (MIK-7221).
    pub(super) fn validate_ws_backend(
        name: &str,
        backend: &BackendConfig,
        ws_url: &str,
        protocol_version: Option<&str>,
    ) -> Result<()> {
        let refuse = |why: String| Err(Error::ConfigValidation(format!("Backend '{name}' {why}")));
        if ws_url.is_empty() {
            return refuse("has an empty ws_url".into());
        }
        let url = match url::Url::parse(ws_url) {
            Ok(url) => url,
            Err(e) => return refuse(format!("has an invalid ws_url: {e}")),
        };
        if !matches!(url.scheme(), "ws" | "wss") {
            return refuse("has a ws_url whose scheme is not ws:// or wss://".into());
        }
        Self::reject_cleartext_credentials(name, backend, &url)?;
        if backend.oauth.is_some() {
            return refuse(
                "sets oauth on a ws_url: oauth needs a per-request bearer the WebSocket \
                 transport cannot refresh mid-connection; put a static token in `headers` \
                 or use `http_url`"
                    .into(),
            );
        }
        if backend
            .secrets
            .iter()
            .any(|rule| matches!(rule.inject_as, InjectTarget::Header | InjectTarget::Query))
        {
            return refuse(
                "has secrets injected as a header or query on a ws_url: the WebSocket \
                 transport sends headers only on the upgrade, so they would be dropped; \
                 use `headers` or `inject_as: argument`"
                    .into(),
            );
        }
        if let Some(version) = protocol_version.filter(|v| *v >= FIRST_STATELESS_REVISION) {
            return refuse(format!(
                "sets protocol_version {version} on a ws_url; the WebSocket transport speaks \
                 only the `initialize` handshake, so it needs a revision before \
                 {FIRST_STATELESS_REVISION}"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "ws_backend_tests.rs"]
mod tests;
