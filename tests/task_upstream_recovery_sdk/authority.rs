// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's real authentication and authorization configuration for the
//! SDK vertical.
//!
//! The shared synthetic fixture runs auth-disabled and honestly says so. This
//! target instead enables the production credential path: `auth.enabled`, a
//! configured OIDC provider on the temporary HTTPS issuer, and delegated
//! bearers verified by `key_server::OidcVerifier`. Owners are then whoever the
//! verified subject says they are — no injected `VerifiedIdentity`, no static
//! API key, no test bypass.
//!
//! The current grant per owner is ordinary key-server policy, which is also the
//! revocation surface: rewriting one owner's `scopes.backends` and restarting
//! changes what that SAME verified subject may invoke NOW.

use std::path::{Path, PathBuf};

use mcp_gateway::config::{
    Config, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig, PolicyScopesConfig,
};

use crate::issuer::{AUDIENCE, Issuer};

/// One authenticated person: a verified subject and the bearer they present.
/// The subject is minted into the bearer; matching here is by email.
pub struct Owner {
    pub email: String,
    pub token: String,
}

impl Owner {
    pub fn new(issuer: &Issuer, subject: &str, email: &str) -> Self {
        Self {
            email: email.to_string(),
            token: issuer.mint(subject, email),
        }
    }
}

/// What one owner may invoke right now.
pub struct Grant<'a> {
    pub owner: &'a Owner,
    /// Written verbatim to `scopes.backends`. Naming another backend is the
    /// revocation case: the same subject, authenticated exactly as before, no
    /// longer holds a grant for the original call's backend.
    pub backends: Vec<String>,
}

/// Enable authentication and explicitly configure the pinned SDK's supported
/// upstream protocol revision. This journey does not test auto-negotiation.
pub fn write_authenticated_config(
    root: &Path,
    base: &Path,
    name: &str,
    issuer: &Issuer,
    grants: &[Grant<'_>],
) -> PathBuf {
    let yaml = std::fs::read_to_string(base).expect("the shared fixture wrote a base config");
    let mut config: Config =
        serde_yaml::from_str(&yaml).expect("the gateway's own config type reloads its own YAML");

    let backend = config
        .backends
        .get_mut(crate::helper::BACKEND)
        .expect("the fixture backend is configured");
    let mcp_gateway::config::TransportConfig::Http {
        protocol_version, ..
    } = &mut backend.transport
    else {
        panic!("the SDK fixture uses HTTP");
    };
    *protocol_version = Some(crate::helper::PROTOCOL_VERSION.to_string());

    config.auth.enabled = true;
    // `/health` only, so `/mcp` demands a credential and an unauthenticated
    // caller cannot fall through to the public identity.
    config.auth.public_paths = vec!["/health".to_string()];

    config.key_server.enabled = true;
    // The production delegated path: a raw OIDC bearer verified against the
    // configured provider by `key_server_credential`.
    config.key_server.delegated_bearer = true;
    // The vertical spans several restarts; the tokens stay the ones minted for
    // it rather than being reissued to dodge the replay window.
    config.key_server.max_oidc_token_age_secs = 3_600;
    config.key_server.oidc = vec![KeyServerProviderConfig {
        issuer: issuer.url.clone(),
        jwks_uri: None,
        // Discovery, then JWKS, both over the issuer's real TLS.
        discovery_url: None,
        auto_discover: true,
        audiences: vec![AUDIENCE.to_string()],
        allowed_domains: Vec::new(),
    }];
    config.key_server.policies = grants
        .iter()
        .map(|grant| KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                email: Some(grant.owner.email.clone()),
                issuer: Some(issuer.url.clone()),
                ..PolicyMatchConfig::default()
            },
            scopes: PolicyScopesConfig {
                backends: grant.backends.clone(),
                // Tool scope is left open so a refusal below can only be the
                // backend grant, and so `tasks/get` itself stays available.
                tools: vec!["*".to_string()],
                rate_limit: 0,
            },
        })
        .collect();

    let path = root.join(name);
    let rendered = serde_yaml::to_string(&config).expect("the amended config serializes");
    std::fs::write(&path, rendered).expect("the config is written inside the test's own temp root");
    path
}
