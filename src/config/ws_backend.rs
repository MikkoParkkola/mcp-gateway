// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config rules for `ws_url` backends (F17): URL constructors and load checks.

use super::{BackendConfig, Config, TransportConfig};
use crate::Result;

impl TransportConfig {
    /// Build the transport a bare URL selects: `ws`/`wss` (any case) is a
    /// WebSocket backend, anything else HTTP.
    pub(crate) fn for_url(url: &str) -> Self {
        Self::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        }
    }
}

impl Config {
    pub(super) fn validate_ws_backend(
        _name: &str,
        _backend: &BackendConfig,
        _ws_url: &str,
        _protocol_version: Option<&str>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "ws_backend_tests.rs"]
mod tests;
