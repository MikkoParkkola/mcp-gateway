//! Mutual TLS (mTLS) authenticated tool access.
//!
//! This module implements RFC-0051: certificate-based authentication and
//! fine-grained tool access control for the MCP Gateway.
//!
//! # Architecture
//!
//! ```text
//! TCP connection
//!   → TLS handshake  (rustls verifies client cert against CA)
//!   → CertIdentity extracted from peer certificate
//!   → Injected into request extensions
//!   → [Existing auth middleware runs]
//!   → [MtlsPolicy check on tool invocation]
//! ```
//!
//! # Modules
//!
//! - [`config`] — YAML configuration types (`MtlsConfig`, `PolicyRuleConfig`, …)
//! - [`identity`] — X.509 certificate field extraction (`CertIdentity`)
//! - [`access_control`] — Policy evaluation (`MtlsPolicy`, `PolicyDecision`)
//! - [`cert_manager`] — rustls config building and certificate generation CLI helpers
//!
//! # Quick start
//!
//! ```yaml
//! mtls:
//!   enabled: true
//!   server_cert: "/etc/mcp-gateway/tls/server.crt"
//!   server_key:  "/etc/mcp-gateway/tls/server.key"
//!   ca_cert:     "/etc/mcp-gateway/tls/ca.crt"
//!   require_client_cert: true
//!   policies:
//!     - match:
//!         ou: "engineering"
//!       allow:
//!         backends: ["*"]
//!         tools: ["*"]
//!     - match: { any: true }
//!       deny:
//!         backends: ["*"]
//!         tools: ["*"]
//! ```

pub mod access_control;
pub mod cert_manager;
pub mod config;
pub mod identity;

pub use access_control::{MtlsPolicy, PolicyDecision};
pub use cert_manager::{
    CaParams, CertGenerator, GeneratedCert, LeafCertParams, build_tls_config, load_certs,
    load_private_key,
};
pub use config::MtlsConfig;
pub use identity::CertIdentity;
