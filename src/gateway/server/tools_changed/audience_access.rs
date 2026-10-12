// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the audience fixture's `/mcp` route is guarded: which credentials the
//! rows present and which identity checks the gateway runs (MIK-8350 D16).

use std::sync::Arc;

use crate::config::AuthConfig;
use crate::gateway::router::AppState;

/// Whether the fixture's `/mcp` route needs a credential.
pub(super) enum McpAccess {
    Authenticated,
    /// `/mcp` is a public path: a caller that presents nothing is admitted
    /// anonymously.
    PublicPath,
    /// An mTLS policy admits any presented certificate to `alpha` and
    /// nothing else: a caller that presents none is shown nothing.
    MtlsCert,
    /// Agent auth is on: a caller is its OAuth agent token ([`agent_token`]),
    /// scoped to `alpha`, and is shown nothing without that identity.
    AgentToken,
}

const AGENT_ID: &str = "agent-r7";
const AGENT_SECRET: &str = "agent-r7-secret-0123456789-0123456789";

/// A bearer the fixture's agent registry validates under [`McpAccess::AgentToken`].
pub(super) fn agent_token() -> String {
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({ "sub": AGENT_ID, "exp": now + 3600, "iat": now }),
        &jsonwebtoken::EncodingKey::from_secret(AGENT_SECRET.as_bytes()),
    )
    .expect("sign agent token")
}

pub(super) fn public_paths(access: &McpAccess) -> Vec<String> {
    match access {
        McpAccess::PublicPath => vec!["/mcp".to_string()],
        _ => AuthConfig::default().public_paths,
    }
}

/// Shape the state's identity checks for `access`.
pub(super) fn apply(st: &mut AppState, access: &McpAccess) {
    match access {
        McpAccess::MtlsCert => {
            st.mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
                &crate::mtls::MtlsConfig {
                    enabled: true,
                    policies: vec![crate::mtls::config::PolicyRuleConfig {
                        match_criteria: crate::mtls::config::CertMatchConfig {
                            any: Some(true),
                            ..Default::default()
                        },
                        allow: crate::mtls::config::ToolScopeConfig {
                            backends: vec!["alpha".to_string()],
                            tools: vec!["*".to_string()],
                        },
                        deny: Default::default(),
                    }],
                    ..Default::default()
                },
            ));
        }
        McpAccess::AgentToken => {
            let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
            registry.register(crate::gateway::oauth::AgentDefinition {
                client_id: AGENT_ID.to_string(),
                name: AGENT_ID.to_string(),
                hs256_secret: Some(AGENT_SECRET.to_string()),
                rs256_public_key: None,
                scopes: vec!["tools:alpha:*:execute".to_string()],
                issuer: None,
                audience: None,
            });
            st.agent_auth = crate::gateway::oauth::AgentAuthState::new(true, registry);
        }
        McpAccess::Authenticated | McpAccess::PublicPath => {}
    }
}
