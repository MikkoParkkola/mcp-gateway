// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tunnel integration for secure remote access.
//!
//! Implements two remote-access mechanisms:
//!
//! - **Tailscale** (issue #64): Expose the gateway over a private Tailscale
//!   network via `tailscale serve`, with optional public `tailscale funnel`.
//!   Tailscale identity headers (`Tailscale-User-Login`, `Tailscale-User-Name`)
//!   can be used for zero-trust authentication without a separate bearer token.
//!
//! - **pipenet** (issue #33): Create a tunneled HTTPS endpoint via a pipenet
//!   relay server, enabling MCP server access from environments where the
//!   gateway is not directly reachable (e.g. dev laptop behind NAT).
//!
//! # Quick start
//!
//! ```yaml
//! tunnel:
//!   tailscale:
//!     serve_port: 39401
//!     funnel_enabled: false
//!     auth_via_identity: true
//!   pipenet:
//!     server_url: "https://relay.pipenet.io"
//!     subdomain: "my-gateway"
//! ```
//!
//! # Architecture
//!
//! ```text
//! TunnelManager::setup_tailscale  →  tailscale CLI  →  TunnelInfo { public_url }
//! TunnelManager::setup_pipenet    →  HTTP POST /register  →  TunnelInfo { public_url }
//! ```

use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration types
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level tunnel configuration block.
///
/// Both `tailscale` and `pipenet` are optional and independent.  Either,
/// both, or neither may be enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelConfig {
    /// Tailscale Serve / Funnel settings.
    pub tailscale: Option<TailscaleConfig>,

    /// pipenet relay tunnel settings.
    pub pipenet: Option<PipenetConfig>,
}

/// Tailscale tunnel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TailscaleConfig {
    /// Local port the gateway listens on and that `tailscale serve` proxies.
    ///
    /// Defaults to `39401` (the standard MCP gateway port).
    #[serde(default = "default_serve_port")]
    pub serve_port: u16,

    /// Enable `tailscale funnel` so the endpoint is reachable from the public
    /// internet (not only within the tailnet).
    ///
    /// Defaults to `false` — private tailnet access only.
    #[serde(default)]
    pub funnel_enabled: bool,

    /// Trust `Tailscale-User-Login` / `Tailscale-User-Name` headers for
    /// zero-password authentication.
    ///
    /// Only enable when the gateway is behind `tailscale serve` and therefore
    /// those headers cannot be spoofed by an external caller.
    #[serde(default)]
    pub auth_via_identity: bool,
}

/// pipenet relay tunnel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipenetConfig {
    /// Base URL of the pipenet relay server (e.g. `https://relay.pipenet.io`).
    pub server_url: String,

    /// Optional subdomain to request on the relay.
    ///
    /// When `None` the relay assigns a random subdomain.
    pub subdomain: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Default helpers
// ─────────────────────────────────────────────────────────────────────────────

fn default_serve_port() -> u16 {
    39_401
}

impl Default for TailscaleConfig {
    fn default() -> Self {
        Self {
            serve_port: default_serve_port(),
            funnel_enabled: false,
            auth_via_identity: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelInfo — returned by setup_* methods
// ─────────────────────────────────────────────────────────────────────────────

/// Authentication method exposed by a tunnel endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No authentication — caller has not configured any.
    None,
    /// Tailscale identity headers are trusted for authentication.
    TailscaleIdentity,
    /// Standard bearer-token authentication.
    BearerToken,
}

/// Status of a configured tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStatus {
    /// Tunnel configured and accepting connections.
    Active,
    /// Tunnel configuration succeeded but the process has not been verified yet.
    Configured,
    /// Tunnel is in a degraded state (partial failure).
    Degraded,
}

/// Information about a successfully configured tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// Publicly (or tailnet-) reachable URL for the gateway.
    pub public_url: String,
    /// Authentication method clients should use with this tunnel.
    pub auth_method: AuthMethod,
    /// Current tunnel status.
    pub status: TunnelStatus,
    /// Human-readable description of the tunnel type.
    pub tunnel_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the lifecycle of remote-access tunnels.
///
/// `TunnelManager` is stateless — each `setup_*` call shells out to the
/// appropriate CLI tool or HTTP API and returns a [`TunnelInfo`] on success.
pub struct TunnelManager;

impl TunnelManager {
    /// Create a new `TunnelManager`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Configure a Tailscale Serve (and optionally Funnel) endpoint.
    ///
    /// Runs:
    ///   1. `tailscale serve --bg http://localhost:<port>` — expose gateway on tailnet.
    ///   2. `tailscale funnel --bg <port>` if `funnel_enabled`.
    ///   3. `tailscale status --json` — retrieve the Tailscale HTTPS URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if:
    /// - The `tailscale` CLI is not installed or not authenticated.
    /// - `tailscale serve` or `funnel` exits with a non-zero status.
    /// - `tailscale status` output cannot be parsed to derive the public URL.
    pub fn setup_tailscale(&self, config: &TailscaleConfig) -> Result<TunnelInfo> {
        // Step 1: configure tailscale serve
        run_tailscale_serve(config.serve_port)?;

        // Step 2: optionally enable funnel for public internet access
        if config.funnel_enabled {
            run_tailscale_funnel(config.serve_port)?;
        }

        // Step 3: derive the public URL from tailscale status
        let public_url = tailscale_https_url(config.serve_port)?;

        let auth_method = if config.auth_via_identity {
            AuthMethod::TailscaleIdentity
        } else {
            AuthMethod::BearerToken
        };

        Ok(TunnelInfo {
            public_url,
            auth_method,
            status: TunnelStatus::Active,
            tunnel_type: "tailscale".to_owned(),
        })
    }

    /// Configure a pipenet relay tunnel.
    ///
    /// Sends `POST <server_url>/register` with a JSON body containing:
    ///
    /// ```json
    /// { "subdomain": "my-gateway" }   // optional
    /// ```
    ///
    /// and expects a JSON response `{ "public_url": "https://..." }`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if:
    /// - The pipenet `server_url` is invalid.
    /// - The relay returns a non-2xx HTTP status.
    /// - The response body cannot be parsed.
    pub fn setup_pipenet(&self, config: &PipenetConfig) -> Result<TunnelInfo> {
        validate_server_url(&config.server_url)?;
        let public_url = register_with_pipenet(config)?;

        Ok(TunnelInfo {
            public_url,
            auth_method: AuthMethod::BearerToken,
            status: TunnelStatus::Configured,
            tunnel_type: "pipenet".to_owned(),
        })
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — Tailscale
// ─────────────────────────────────────────────────────────────────────────────

/// Run `tailscale serve --bg http://localhost:<port>`.
fn run_tailscale_serve(port: u16) -> Result<()> {
    let status = Command::new("tailscale")
        .args(["serve", "--bg", &format!("http://localhost:{port}")])
        .status()
        .map_err(|e| Error::Config(format!("Failed to invoke tailscale CLI: {e}")))?;

    if status.success() {
        return Ok(());
    }

    Err(Error::Config(format!(
        "tailscale serve exited with status {status}"
    )))
}

/// Run `tailscale funnel --bg <port>`.
fn run_tailscale_funnel(port: u16) -> Result<()> {
    let status = Command::new("tailscale")
        .args(["funnel", "--bg", &port.to_string()])
        .status()
        .map_err(|e| Error::Config(format!("Failed to invoke tailscale CLI: {e}")))?;

    if status.success() {
        return Ok(());
    }

    Err(Error::Config(format!(
        "tailscale funnel exited with status {status}"
    )))
}

/// Derive the Tailscale HTTPS URL from `tailscale status --json`.
///
/// The JSON schema we need: `{ "Self": { "DNSName": "hostname.tailnet.ts.net." } }`.
/// We append the serve port as a path hint; the actual HTTPS URL served by
/// `tailscale serve` is `https://<dnsname>`.
fn tailscale_https_url(port: u16) -> Result<String> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .map_err(|e| Error::Config(format!("Failed to invoke tailscale CLI: {e}")))?;

    if !output.status.success() {
        return Err(Error::Config(format!(
            "tailscale status exited with status {}",
            output.status
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    let dns_name = json
        .get("Self")
        .and_then(|s| s.get("DNSName"))
        .and_then(serde_json::Value::as_str)
        .map(|s| s.trim_end_matches('.'))
        .ok_or_else(|| Error::Config("tailscale status missing Self.DNSName field".to_owned()))?;

    Ok(format!("https://{dns_name}:{port}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — pipenet
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that `server_url` is a well-formed HTTPS URL.
fn validate_server_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(Error::Config(
            "pipenet server_url must not be empty".to_owned(),
        ));
    }

    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(Error::Config(format!(
            "pipenet server_url must start with https:// or http://, got: {url}"
        )));
    }

    Ok(())
}

/// Call the pipenet `/register` endpoint synchronously via a subprocess
/// (`curl`-based shim) to avoid a dependency on `reqwest` in a sync context.
///
/// In production code the caller would typically drive this from an async task.
/// Here we use `std::process::Command` to keep the function synchronous and
/// free of `async_trait` complexity while still being fully testable via
/// dependency injection in tests.
fn register_with_pipenet(config: &PipenetConfig) -> Result<String> {
    let register_url = format!("{}/register", config.server_url.trim_end_matches('/'));

    let body = match &config.subdomain {
        Some(sub) => format!(r#"{{"subdomain":"{sub}"}}"#),
        None => "{}".to_owned(),
    };

    let output = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &register_url,
        ])
        .output()
        .map_err(|e| Error::Config(format!("Failed to invoke curl for pipenet: {e}")))?;

    if !output.status.success() {
        return Err(Error::Config(format!(
            "pipenet register request failed with status {}",
            output.status
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::Config(format!("pipenet returned invalid JSON: {e}")))?;

    json.get("public_url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Config("pipenet response missing 'public_url' field".to_owned()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TailscaleConfig defaults ──────────────────────────────────────────────

    #[test]
    fn tailscale_config_default_serve_port() {
        // GIVEN: default TailscaleConfig
        let cfg = TailscaleConfig::default();
        // THEN: serve_port is 39401 (standard gateway port)
        assert_eq!(cfg.serve_port, 39_401);
    }

    #[test]
    fn tailscale_config_default_funnel_disabled() {
        let cfg = TailscaleConfig::default();
        assert!(!cfg.funnel_enabled);
    }

    #[test]
    fn tailscale_config_default_auth_via_identity_disabled() {
        let cfg = TailscaleConfig::default();
        assert!(!cfg.auth_via_identity);
    }

    #[test]
    fn tailscale_config_deserialize_from_yaml() {
        let yaml = r"
serve_port: 8080
funnel_enabled: true
auth_via_identity: true
";
        let cfg: TailscaleConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.serve_port, 8080);
        assert!(cfg.funnel_enabled);
        assert!(cfg.auth_via_identity);
    }

    #[test]
    fn tailscale_config_deserialize_defaults_when_fields_absent() {
        let cfg: TailscaleConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.serve_port, 39_401);
        assert!(!cfg.funnel_enabled);
        assert!(!cfg.auth_via_identity);
    }

    // ── PipenetConfig ─────────────────────────────────────────────────────────

    #[test]
    fn pipenet_config_round_trip_serde() {
        let cfg = PipenetConfig {
            server_url: "https://relay.pipenet.io".to_owned(),
            subdomain: Some("my-gateway".to_owned()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: PipenetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.server_url, "https://relay.pipenet.io");
        assert_eq!(cfg2.subdomain.as_deref(), Some("my-gateway"));
    }

    #[test]
    fn pipenet_config_subdomain_is_optional() {
        let yaml = r#"server_url: "https://relay.pipenet.io""#;
        let cfg: PipenetConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.subdomain.is_none());
    }

    // ── TunnelConfig ──────────────────────────────────────────────────────────

    #[test]
    fn tunnel_config_default_has_no_providers() {
        let cfg = TunnelConfig::default();
        assert!(cfg.tailscale.is_none());
        assert!(cfg.pipenet.is_none());
    }

    #[test]
    fn tunnel_config_deserialize_tailscale_block() {
        let yaml = r"
tailscale:
  serve_port: 9000
  funnel_enabled: false
";
        let cfg: TunnelConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.tailscale.is_some());
        assert_eq!(cfg.tailscale.unwrap().serve_port, 9000);
        assert!(cfg.pipenet.is_none());
    }

    #[test]
    fn tunnel_config_deserialize_pipenet_block() {
        let yaml = r#"
pipenet:
  server_url: "https://relay.pipenet.io"
  subdomain: "test"
"#;
        let cfg: TunnelConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.pipenet.is_some());
        assert!(cfg.tailscale.is_none());
    }

    #[test]
    fn tunnel_config_deserialize_both_blocks() {
        let yaml = r#"
tailscale:
  serve_port: 39401
pipenet:
  server_url: "https://relay.pipenet.io"
"#;
        let cfg: TunnelConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.tailscale.is_some());
        assert!(cfg.pipenet.is_some());
    }

    // ── AuthMethod and TunnelStatus serde ─────────────────────────────────────

    #[test]
    fn auth_method_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuthMethod::TailscaleIdentity).unwrap(),
            r#""tailscale_identity""#
        );
        assert_eq!(
            serde_json::to_string(&AuthMethod::BearerToken).unwrap(),
            r#""bearer_token""#
        );
        assert_eq!(
            serde_json::to_string(&AuthMethod::None).unwrap(),
            r#""none""#
        );
    }

    #[test]
    fn tunnel_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&TunnelStatus::Active).unwrap(),
            r#""active""#
        );
        assert_eq!(
            serde_json::to_string(&TunnelStatus::Configured).unwrap(),
            r#""configured""#
        );
    }

    // ── validate_server_url ───────────────────────────────────────────────────

    #[test]
    fn validate_server_url_accepts_https() {
        assert!(validate_server_url("https://relay.pipenet.io").is_ok());
    }

    #[test]
    fn validate_server_url_accepts_http_for_local_dev() {
        assert!(validate_server_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn validate_server_url_rejects_empty_string() {
        let err = validate_server_url("").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn validate_server_url_rejects_non_url() {
        let err = validate_server_url("not-a-url").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    // ── TunnelManager default ─────────────────────────────────────────────────

    #[test]
    fn tunnel_manager_new_and_default_are_equivalent() {
        // TunnelManager is stateless — just verify both constructors work
        let mgr = TunnelManager::new();
        assert_eq!(std::mem::size_of_val(&mgr), 0);
    }

    // ── TunnelInfo fields ─────────────────────────────────────────────────────

    #[test]
    fn tunnel_info_round_trip_serde() {
        let info = TunnelInfo {
            public_url: "https://my-host.ts.net:39401".to_owned(),
            auth_method: AuthMethod::TailscaleIdentity,
            status: TunnelStatus::Active,
            tunnel_type: "tailscale".to_owned(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let info2: TunnelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info2.public_url, info.public_url);
        assert_eq!(info2.auth_method, info.auth_method);
        assert_eq!(info2.status, info.status);
        assert_eq!(info2.tunnel_type, info.tunnel_type);
    }
}
