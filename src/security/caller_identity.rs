// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.caller_identity`: where a caller's end-user identity may come
//! from besides its credential, and the load checks that keep a caller from
//! choosing its own subject.

use serde::{Deserialize, Serialize};

use crate::config::{Config, KeyServerConfig};

/// Where a caller's end-user identity may come from, besides the credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerIdentityMode {
    /// No identity header is read. Default.
    #[default]
    Off,
    /// `X-Gateway-Identity-Subject`/`-Label`, honoured only from a peer in
    /// `trusted_proxies`, under the configured `authority`.
    TrustedProxy,
    /// A verified `Cf-Access-Jwt-Assertion` only.
    CloudflareAccess,
}

/// Cloudflare Access assertion verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudflareAccessConfig {
    /// Bare team host, e.g. `acme.cloudflareaccess.com`.
    pub team_domain: String,
    /// Access application AUD tags the assertion must carry.
    pub audiences: Vec<String>,
}

/// Caller identity headers (`security.caller_identity`).
///
/// A sibling of `identity_grants`, not part of it: the subject also keys the
/// response cache and idempotency.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CallerIdentityConfig {
    /// Which identity source is honoured. Default: `off`.
    pub mode: CallerIdentityMode,
    /// Exact peer IPs of the proxies allowed to send identity headers.
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// The grant authority every `trusted_proxy` subject is placed under.
    pub authority: String,
    /// Access team and audiences for `cloudflare_access`.
    pub cloudflare_access: CloudflareAccessConfig,
}

impl CallerIdentityConfig {
    /// Refuse a caller-identity config that would let a caller choose its
    /// own subject or collide with another authority.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ConfigValidation`] for the first violation.
    pub fn validate(&self, auth_enabled: bool, key_server: &KeyServerConfig) -> crate::Result<()> {
        let refuse = |reason: String| {
            crate::Error::ConfigValidation(format!("security.caller_identity: {reason}"))
        };
        let team_domain = self.cloudflare_access.team_domain.trim();
        match self.mode {
            CallerIdentityMode::Off => {}
            CallerIdentityMode::TrustedProxy => {
                if self.trusted_proxies.is_empty() {
                    return Err(refuse(
                        "trusted_proxy needs at least one trusted_proxies entry".into(),
                    ));
                }
                // Canonical first, so `::ffff:127.0.0.1` meets the loopback
                // rule and `::ffff:0.0.0.0` the unspecified one.
                for entry in self
                    .trusted_proxies
                    .iter()
                    .map(std::net::IpAddr::to_canonical)
                {
                    if entry.is_unspecified() {
                        return Err(refuse(format!(
                            "trusted_proxies entry {entry} is unspecified, which would trust any peer"
                        )));
                    }
                    if entry.is_loopback() && !auth_enabled {
                        return Err(refuse(format!(
                            "trusted_proxies entry {entry} is loopback; with auth.enabled = false \
                             every local process could choose its subject. Enable auth, or use \
                             mode: cloudflare_access for a same-host cloudflared"
                        )));
                    }
                }
                let authority = self.authority.trim();
                let access_issuer =
                    (!team_domain.is_empty()).then(|| format!("https://{team_domain}"));
                if authority.is_empty() {
                    return Err(refuse("trusted_proxy needs a non-blank authority".into()));
                }
                if ["mtls", "agent_oauth", "api_key"].contains(&authority)
                    || key_server.oidc.iter().any(|p| p.issuer.trim() == authority)
                    || access_issuer.as_deref() == Some(authority)
                {
                    return Err(refuse(format!(
                        "authority '{authority}' is reserved or an OIDC issuer; a header subject \
                         under it would collide with that authority's grants"
                    )));
                }
            }
            CallerIdentityMode::CloudflareAccess => {
                let bare_host = !team_domain.is_empty()
                    && !team_domain.contains(['/', ':', '?', '#', '@'])
                    && team_domain == self.cloudflare_access.team_domain;
                if !bare_host {
                    return Err(refuse(
                        "cloudflare_access.team_domain must be a bare host, for example \
                         acme.cloudflareaccess.com (no scheme, path, port or trailing slash)"
                            .into(),
                    ));
                }
                if !self
                    .cloudflare_access
                    .audiences
                    .iter()
                    .any(|a| !a.trim().is_empty())
                {
                    return Err(refuse(
                        "cloudflare_access.audiences needs at least one non-empty AUD tag".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Config {
    /// Key-server issuers, then caller identity, whose authority must not
    /// collide with any of them.
    pub(crate) fn validate_identity_sources(&self) -> crate::Result<()> {
        self.key_server.validate()?;
        self.security
            .caller_identity
            .validate(self.auth.enabled, &self.key_server)
    }
}

/// A8: `security.caller_identity` load checks.
#[cfg(test)]
mod caller_identity_config_tests {
    use super::*;
    use crate::config::KeyServerProviderConfig;

    fn proxy(entries: &[&str], authority: &str) -> CallerIdentityConfig {
        CallerIdentityConfig {
            mode: CallerIdentityMode::TrustedProxy,
            trusted_proxies: entries.iter().map(|e| e.parse().unwrap()).collect(),
            authority: authority.to_string(),
            ..CallerIdentityConfig::default()
        }
    }

    fn access(team_domain: &str, audiences: &[&str]) -> CallerIdentityConfig {
        CallerIdentityConfig {
            mode: CallerIdentityMode::CloudflareAccess,
            cloudflare_access: CloudflareAccessConfig {
                team_domain: team_domain.to_string(),
                audiences: audiences.iter().map(ToString::to_string).collect(),
            },
            ..CallerIdentityConfig::default()
        }
    }

    fn key_server_with_issuer(issuer: &str) -> KeyServerConfig {
        KeyServerConfig {
            oidc: vec![KeyServerProviderConfig {
                issuer: issuer.to_string(),
                jwks_uri: None,
                discovery_url: None,
                auto_discover: true,
                audiences: vec!["client".to_string()],
                allowed_domains: Vec::new(),
            }],
            ..KeyServerConfig::default()
        }
    }

    /// A8-T11: each unsafe shape is a load error.
    #[test]
    fn config_rejects_unsafe_caller_identity() {
        let issuer = "https://accounts.google.com";
        let ks = key_server_with_issuer(issuer);
        let cases = [
            ("empty proxies", proxy(&[], "corp-sso"), true),
            ("blank authority", proxy(&["10.0.0.5"], " "), true),
            (
                "authority with leading space",
                proxy(&["10.0.0.5"], " corp-sso"),
                true,
            ),
            (
                "authority with trailing space",
                proxy(&["10.0.0.5"], "corp-sso "),
                true,
            ),
            (
                "authority is an OIDC issuer",
                proxy(&["10.0.0.5"], issuer),
                true,
            ),
            ("authority mtls", proxy(&["10.0.0.5"], "mtls"), true),
            (
                "authority agent_oauth",
                proxy(&["10.0.0.5"], "agent_oauth"),
                true,
            ),
            ("authority api_key", proxy(&["10.0.0.5"], "api_key"), true),
            (
                "authority is the Access issuer",
                proxy(&["10.0.0.5"], "https://acme.cloudflareaccess.com"),
                true,
            ),
            ("unspecified v4", proxy(&["0.0.0.0"], "corp-sso"), true),
            ("unspecified v6", proxy(&["::"], "corp-sso"), true),
            (
                "mapped unspecified",
                proxy(&["::ffff:0.0.0.0"], "corp-sso"),
                true,
            ),
            (
                "unspecified with auth on",
                proxy(&["0.0.0.0"], "corp-sso"),
                false,
            ),
            (
                "loopback v4, auth off",
                proxy(&["127.0.0.1"], "corp-sso"),
                true,
            ),
            ("loopback v6, auth off", proxy(&["::1"], "corp-sso"), true),
            ("no team domain", access("", &["aud"]), true),
            (
                "no audience",
                access("acme.cloudflareaccess.com", &[" "]),
                true,
            ),
            (
                "team domain with scheme",
                access("https://acme.cloudflareaccess.com", &["aud"]),
                true,
            ),
            (
                "team domain with path",
                access("acme.cloudflareaccess.com/x", &["aud"]),
                true,
            ),
            (
                "team domain with port",
                access("acme.cloudflareaccess.com:443", &["aud"]),
                true,
            ),
            (
                "team domain trailing slash",
                access("acme.cloudflareaccess.com/", &["aud"]),
                true,
            ),
        ];
        for (name, config, auth_off) in cases {
            let mut cfg = config;
            if name == "authority is the Access issuer" {
                cfg.cloudflare_access.team_domain = "acme.cloudflareaccess.com".to_string();
            }
            assert!(cfg.validate(!auth_off, &ks).is_err(), "{name} loaded");
        }
        let mut whole = crate::config::Config::default();
        whole.security.caller_identity = proxy(&["0.0.0.0"], "corp-sso");
        assert!(
            whole.validate().is_err(),
            "Config::validate skips caller_identity"
        );
    }

    /// A8-T11b (positive control): loopback is allowed once auth is on, and
    /// the documented shapes load.
    #[test]
    fn loopback_proxy_allowed_with_auth_on() {
        let ks = KeyServerConfig::default();
        proxy(&["127.0.0.1"], "corp-sso")
            .validate(true, &ks)
            .unwrap();
        proxy(&["10.0.0.5"], "corp-sso")
            .validate(false, &ks)
            .unwrap();
        access("acme.cloudflareaccess.com", &["aud"])
            .validate(false, &ks)
            .unwrap();
        CallerIdentityConfig::default()
            .validate(false, &ks)
            .unwrap();
    }

    /// A8-T11c: the removed boolean fails to parse and the error names it.
    #[test]
    fn removed_trust_flag_is_a_load_error() {
        let yaml = "identity_grants:\n  trust_caller_identity_headers: true\n";
        let err = serde_yaml::from_str::<crate::config::SecurityConfig>(yaml)
            .expect_err("the removed key loaded silently")
            .to_string();
        assert!(err.contains("trust_caller_identity_headers"), "{err}");
    }

    /// A8-T11d: a mapped loopback entry is loopback (checked after
    /// canonicalising).
    #[test]
    fn mapped_loopback_entry_refused_with_auth_off() {
        let err = proxy(&["::ffff:127.0.0.1"], "corp-sso")
            .validate(false, &KeyServerConfig::default())
            .expect_err("a mapped loopback proxy loaded with auth off");
        assert!(err.to_string().contains("loopback"), "{err}");
    }
}
