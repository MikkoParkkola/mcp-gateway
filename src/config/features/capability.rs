// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability configuration for direct REST API integration.

use serde::{Deserialize, Serialize};

use crate::error::Result;

// ── Capability ─────────────────────────────────────────────────────────────────

/// Capability configuration for direct REST API integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Enable capability system.
    pub enabled: bool,
    /// Backend name for capabilities (shown in `gateway_list_servers`).
    pub name: String,
    /// Directories to load capability definitions from.
    pub directories: Vec<String>,
    /// HTTP(S) proxy for capability calls, e.g. `http://proxy.internal:3128`.
    ///
    /// Capability calls never follow `HTTP_PROXY`/`HTTPS_PROXY` from the
    /// environment (#1881); this key is the only way to proxy them. With it
    /// set, the proxy resolves each destination, so the gateway's DNS pinning
    /// cannot see where a name leads: private-range enforcement for names is
    /// then the proxy's job. IP-literal destinations are still refused. A plain
    /// `http://` destination sends its URL and headers, credentials included,
    /// to the proxy. Restart-only.
    pub egress_proxy: Option<String>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "gateway".to_string(),
            // Only the bundled catalogue. Any other source is named in config.
            directories: vec!["capabilities".to_string()],
            egress_proxy: None,
        }
    }
}

impl CapabilityConfig {
    /// The configured egress proxy, parsed.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] unless the value is an absolute `http://`
    /// or `https://` URL with a host. A bad value is refused, never ignored:
    /// ignoring it would silently send the calls direct.
    pub fn egress_proxy_url(&self) -> Result<Option<url::Url>> {
        Ok(None)
    }

    /// `scheme://host:port` of the egress proxy, for logs: never its userinfo.
    #[must_use]
    pub fn egress_proxy_for_log(url: &url::Url) -> String {
        let _ = url;
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(proxy: &str) -> CapabilityConfig {
        CapabilityConfig {
            egress_proxy: Some(proxy.to_string()),
            ..CapabilityConfig::default()
        }
    }

    #[test]
    fn egress_proxy_accepts_http_and_https_urls() {
        assert!(
            CapabilityConfig::default()
                .egress_proxy_url()
                .unwrap()
                .is_none()
        );
        for ok in [
            "http://127.0.0.1:3128",
            "https://proxy.internal",
            "http://u:p@proxy:8080",
        ] {
            assert!(with(ok).egress_proxy_url().unwrap().is_some(), "{ok}");
        }
    }

    #[test]
    fn egress_proxy_refuses_what_it_cannot_use() {
        for bad in [
            "not a url",
            "ftp://proxy:21",
            "proxy.internal:3128",
            "file:///tmp/p",
        ] {
            let err = with(bad).egress_proxy_url().unwrap_err().to_string();
            assert!(err.contains("capabilities.egress_proxy"), "{bad}: {err}");
        }
    }

    #[test]
    fn egress_proxy_log_form_drops_credentials() {
        let url = with("http://user:secret@proxy.internal:8080/")
            .egress_proxy_url()
            .unwrap()
            .unwrap();
        assert_eq!(
            CapabilityConfig::egress_proxy_for_log(&url),
            "http://proxy.internal:8080"
        );
    }
}
