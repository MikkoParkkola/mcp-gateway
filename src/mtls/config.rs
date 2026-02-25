//! mTLS configuration types.
//!
//! Defines the YAML-deserialisable configuration for mutual TLS:
//! server certificate paths, CA trust store, CRL, and certificate-based
//! tool access policies.
//!
//! # Example YAML
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
//!     - match:
//!         any: true
//!       deny:
//!         backends: ["*"]
//!         tools: ["*"]
//! ```

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Top-level mTLS config
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level mTLS configuration block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MtlsConfig {
    /// Enable mTLS support.
    ///
    /// When `false` (default) the gateway starts a plain HTTP/TCP listener
    /// exactly as before.  No other fields have effect.
    pub enabled: bool,

    /// Path to the PEM-encoded server certificate file.
    pub server_cert: String,

    /// Path to the PEM-encoded server private key file.
    pub server_key: String,

    /// Path to the PEM-encoded CA certificate used to verify client certs.
    pub ca_cert: String,

    /// When `true` (recommended), clients that do not present a valid
    /// certificate signed by `ca_cert` are rejected at the TLS handshake.
    ///
    /// When `false`, the TLS layer provides encryption but does not enforce
    /// client authentication.  This is useful during a migration window.
    #[serde(default = "default_require_client_cert")]
    pub require_client_cert: bool,

    /// Optional path to a PEM-encoded Certificate Revocation List.
    ///
    /// When set, revoked certificates are rejected at the TLS handshake.
    #[serde(default)]
    pub crl_path: Option<String>,

    /// Ordered list of certificate-based tool access policies.
    ///
    /// Evaluated in order; the **first matching rule wins**.  If no rule
    /// matches, all tool invocations are denied by default.
    #[serde(default)]
    pub policies: Vec<PolicyRuleConfig>,
}

fn default_require_client_cert() -> bool {
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy rule config
// ─────────────────────────────────────────────────────────────────────────────

/// One rule in the mTLS policy list.
///
/// A rule consists of a **match** criterion and an **allow** / **deny** scope.
/// The first rule whose `match` criterion satisfies the client certificate
/// is applied.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PolicyRuleConfig {
    /// Certificate attributes to match on.
    #[serde(rename = "match")]
    pub match_criteria: CertMatchConfig,

    /// Tools / backends to allow when this rule fires.
    #[serde(default)]
    pub allow: ToolScopeConfig,

    /// Tools / backends to deny when this rule fires (evaluated first).
    #[serde(default)]
    pub deny: ToolScopeConfig,
}

/// Certificate matching criteria.
///
/// All non-`None` fields must match for the rule to fire.
/// If `any: true` is set, the rule matches every valid certificate
/// (and even unauthenticated connections when `require_client_cert: false`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CertMatchConfig {
    /// Exact or glob match on the certificate Common Name.
    pub cn: Option<String>,

    /// Exact or glob match on the Organizational Unit.
    pub ou: Option<String>,

    /// Glob match on a SAN URI value (e.g. `"spiffe://company.com/agent/*"`).
    pub san_uri: Option<String>,

    /// Glob match on a SAN DNS name.
    pub san_dns: Option<String>,

    /// When `true`, this rule matches every certificate (catch-all / default).
    pub any: Option<bool>,
}

/// A scope of tools and backends that a policy rule allows or denies.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ToolScopeConfig {
    /// Backend name patterns.  Supports `"*"` wildcard and glob variants.
    pub backends: Vec<String>,

    /// Tool name patterns.  Supports `"*"` wildcard and glob variants.
    pub tools: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mtls_config_is_disabled() {
        // GIVEN: default-constructed config
        let cfg = MtlsConfig::default();
        // THEN: mTLS is off so existing plain-HTTP behaviour is preserved
        assert!(!cfg.enabled);
    }

    #[test]
    fn default_require_client_cert_is_true() {
        // GIVEN: config with enabled=true, no explicit require_client_cert
        let yaml = "enabled: true\nserver_cert: a\nserver_key: b\nca_cert: c";
        let cfg: MtlsConfig = serde_yaml::from_str(yaml).unwrap();
        // THEN: strict mode is the default
        assert!(cfg.require_client_cert);
    }

    #[test]
    fn require_client_cert_can_be_overridden_to_false() {
        // GIVEN: explicit require_client_cert: false
        let yaml =
            "enabled: true\nserver_cert: a\nserver_key: b\nca_cert: c\nrequire_client_cert: false";
        let cfg: MtlsConfig = serde_yaml::from_str(yaml).unwrap();
        // THEN: optional client cert mode
        assert!(!cfg.require_client_cert);
    }

    #[test]
    fn crl_path_defaults_to_none() {
        let cfg = MtlsConfig::default();
        assert!(cfg.crl_path.is_none());
    }

    #[test]
    fn policies_default_to_empty_vec() {
        let cfg = MtlsConfig::default();
        assert!(cfg.policies.is_empty());
    }

    #[test]
    fn full_policy_rule_deserialises_from_yaml() {
        // GIVEN: a complete policy rule in YAML
        let yaml = r#"
match:
  cn: "github-actions-ci"
allow:
  backends: ["tavily", "brave"]
  tools: ["*_search*", "*_list*"]
deny:
  tools: ["*_write*", "*_delete*"]
"#;
        let rule: PolicyRuleConfig = serde_yaml::from_str(yaml).unwrap();
        // THEN: fields parsed correctly
        assert_eq!(rule.match_criteria.cn.as_deref(), Some("github-actions-ci"));
        assert_eq!(rule.allow.backends, &["tavily", "brave"]);
        assert_eq!(rule.allow.tools.len(), 2);
        assert_eq!(rule.deny.tools.len(), 2);
    }

    #[test]
    fn catch_all_rule_uses_any_true() {
        let yaml = "match:\n  any: true\ndeny:\n  backends: [\"*\"]\n  tools: [\"*\"]";
        let rule: PolicyRuleConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.match_criteria.any, Some(true));
        assert_eq!(rule.deny.backends, &["*"]);
    }

    #[test]
    fn tool_scope_defaults_to_empty_lists() {
        let scope = ToolScopeConfig::default();
        assert!(scope.backends.is_empty());
        assert!(scope.tools.is_empty());
    }

    #[test]
    fn cert_match_config_all_fields_optional() {
        // GIVEN: empty match block
        let yaml = "{}";
        let m: CertMatchConfig = serde_yaml::from_str(yaml).unwrap();
        // THEN: all None / false
        assert!(m.cn.is_none());
        assert!(m.ou.is_none());
        assert!(m.san_uri.is_none());
        assert!(m.san_dns.is_none());
        assert!(m.any.is_none());
    }

    #[test]
    fn spiffe_san_uri_preserved_in_config() {
        let yaml =
            "match:\n  san_uri: \"spiffe://company.com/agent/*\"\nallow:\n  tools: [\"*\"]";
        let rule: PolicyRuleConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            rule.match_criteria.san_uri.as_deref(),
            Some("spiffe://company.com/agent/*")
        );
    }
}
