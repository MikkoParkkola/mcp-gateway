// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server, transport-security and idempotency configuration (split from `mod.rs`).

use super::{Deserialize, Duration, EnvOverlay, SecretRef, Serialize, humantime_serde};

// ── Server ────────────────────────────────────────────────────────────────────

/// Server configuration. `Debug` is manual so `metrics_token` is redacted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Serve requests written against MCP revision 2026-07-28.
    ///
    /// **On by default.** The gateway serves the latest revision and negotiates
    /// down to the highest revision a client declares, so a legacy peer is
    /// unaffected by the default.
    ///
    /// Setting it to `false` is the operator escape hatch NFR.OBS.5 hangs its
    /// revertibility clause on: a request declaring 2026-07-28 is then refused
    /// with `UnsupportedProtocolVersion` — the answer a client can act on — and
    /// `server/discover` stops advertising the revision. The revert is
    /// restart-scoped, because the whole `server` section is restart-required
    /// (`pending_restart_fields`, `src/config_reload/mod.rs`).
    ///
    /// No field-level `#[serde(default)]` here, deliberately: it would resolve
    /// to `bool::default()` and shadow the container-level `#[serde(default)]`
    /// on `ServerConfig`, so a config file with a `server:` section that omits
    /// the flag would silently deserialize to `false`.
    pub modern_protocol: bool,
    /// Host to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Graceful shutdown timeout: how long the HTTP listener gives open
    /// requests after the signal before it cuts them, and then how long the
    /// in-flight drain may wait (#2147).
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Maximum request body size (bytes) on every route. Read once at startup:
    /// an oversize body gets HTTP 413.
    pub max_body_size: usize,
    /// Externally reachable base URL of this gateway (scheme + host + optional
    /// port), e.g. `https://mcp.your-domain.tld`. Set this when the gateway
    /// runs behind a TLS-terminating reverse proxy so RFC 9728
    /// protected-resource metadata advertises the real public HTTPS origin
    /// instead of the raw bind address. When unset, metadata falls back to the
    /// bind `host:port` only for a loopback bind (local / development use); a
    /// non-loopback bind without this set cannot be named honestly, so the
    /// metadata endpoint returns `503` until it is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// Serve HTTP on a non-loopback address with authentication disabled.
    ///
    /// Default false, and the gateway refuses to start in that combination:
    /// every caller that reaches the address can invoke each configured backend
    /// with the credentials this gateway holds.
    ///
    /// Set this only where authentication terminates in front of the gateway —
    /// a sidecar, a service mesh, or a reverse proxy that authenticates before
    /// forwarding. Naming that use makes the setting reviewable: a reader can
    /// ask whether the fronting layer actually exists. It is logged at WARN on
    /// every start while it remains set.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unauthenticated_network_bind: bool,
    /// Whether a modern `tools/call` must carry `_meta`
    /// `io.mcp-gateway/idempotency-key` (ADR-012 addendum, UPGRADING-4.0 §28).
    pub idempotency_key: IdempotencyKeyMode,
    /// Bearer token a scraper presents to `/metrics` (UPGRADING-4.0 §33): a
    /// literal or `env:VAR`, resolved by [`ServerConfig::resolve_metrics_token`].
    /// Under `server`, not `auth`, because a mesh deployment has no `auth`
    /// section and still needs scraping. The admin bearer never opens
    /// `/metrics`, and this token never opens anything else. It serializes only
    /// for the config-file round trip (`config_persistence::write_config`),
    /// which must keep it; any new export of this struct must redact it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_token: Option<String>,
    /// How many processes serve this config: DECLARED, not observed. Nothing
    /// in a pod can see its replica count, and `kubectl scale` or an HPA
    /// changes it without touching config, so the Helm chart writes it from
    /// `replicaCount`. Above 1, startup refuses the per-process state
    /// (`support::replica_state_refusal`, UPGRADING-4.0 §37).
    pub replicas: u32,
    /// Whether plain HTTP may carry credentials on a network bind (C3,
    /// UPGRADING-4.0). See [`CleartextHttp`].
    #[serde(default, skip_serializing_if = "CleartextHttp::is_refuse")]
    pub cleartext_http: CleartextHttp,
    /// The Kubernetes cluster domain `cleartext_http: cluster_internal` accepts
    /// after `.svc`. Unset means `cluster.local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_domain: Option<String>,
}

/// `server.cleartext_http`: who protects credentials sent over plain HTTP on a
/// network bind. Every value but `refuse` is logged at WARN on each start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleartextHttp {
    /// Refuse to serve: enable `mtls` or pick a value below.
    #[default]
    Refuse,
    /// A reverse proxy terminates TLS in front of this gateway.
    TlsTerminatedUpstream,
    /// Callers reach the pod only over the cluster network, by its Service
    /// name; `public_url` must be that name.
    ClusterInternal,
    /// A container binds `0.0.0.0` and the host publishes it on loopback only.
    HostLocalPublish,
}

impl CleartextHttp {
    /// `true` for the default, so an unset value is not serialized.
    #[must_use]
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's skip_serializing_if passes a reference"
    )]
    pub fn is_refuse(&self) -> bool {
        *self == Self::Refuse
    }
}

/// `server.idempotency_key`: see [`ServerConfig::idempotency_key`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyKeyMode {
    /// Admit an un-keyed modern call unprotected.
    #[default]
    Optional,
    /// Refuse an un-keyed modern call to a tool not marked read-only.
    Required,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            // The latest revision is what a gateway serves unless an operator
            // reverts it; older peers are reached by negotiating down.
            modern_protocol: true,
            host: "127.0.0.1".to_string(),
            port: 39400,
            shutdown_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024,
            public_url: None,
            allow_unauthenticated_network_bind: false,
            idempotency_key: IdempotencyKeyMode::Optional,
            metrics_token: None,
            cleartext_http: CleartextHttp::Refuse,
            cluster_domain: None,
            replicas: 1,
        }
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("modern_protocol", &self.modern_protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("max_body_size", &self.max_body_size)
            .field("public_url", &self.public_url)
            .field(
                "allow_unauthenticated_network_bind",
                &self.allow_unauthenticated_network_bind,
            )
            .field("idempotency_key", &self.idempotency_key)
            .field(
                "metrics_token",
                &self.metrics_token.as_ref().map(|_| "<redacted>"),
            )
            .field("cleartext_http", &self.cleartext_http)
            .field("cluster_domain", &self.cluster_domain)
            .field("replicas", &self.replicas)
            .finish()
    }
}

impl ServerConfig {
    /// The `/metrics` scrape token; `None` admits no scraper. Never an error,
    /// unlike `auth.bearer_token`: a scrape credential must not be able to
    /// stop startup, so a missing or empty `env:` variable logs a WARN and
    /// yields `None`. The unresolved `env:` spelling is never returned.
    #[must_use]
    pub fn resolve_metrics_token(&self, overlay: &EnvOverlay) -> Option<String> {
        let raw = self.metrics_token.as_deref()?;
        match SecretRef::parse(raw) {
            SecretRef::Literal(text) => (!text.is_empty()).then(|| text.to_string()),
            SecretRef::Env(var) => {
                let value = overlay.resolve(var).filter(|v| !v.is_empty());
                if value.is_none() {
                    tracing::warn!(
                        field = "server.metrics_token",
                        variable = var,
                        "server.metrics_token references an unset or empty environment variable; \
                         /metrics answers 401 until it is set and the gateway restarted"
                    );
                }
                value
            }
            // Same contract as `env:`: a scrape credential never stops startup.
            reference @ SecretRef::File(_) => {
                match reference.resolve("server.metrics_token", overlay) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(
                            field = "server.metrics_token",
                            "{error}; /metrics answers 401 until it is fixed and the gateway restarted"
                        );
                        None
                    }
                }
            }
        }
    }
}
