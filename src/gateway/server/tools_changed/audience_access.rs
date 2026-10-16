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
    /// An mTLS policy admits a certificate whose OU is this one to `alpha`,
    /// and every other certificate to nothing (MIK-8377).
    MtlsOu(&'static str),
    /// Agent auth is on: a caller is its OAuth agent token ([`agent_token`]),
    /// scoped to `alpha`, and is shown nothing without that identity.
    AgentToken,
    /// Gateway auth is off and agent auth is on against this registry, which
    /// a row may change while streams are open (MIK-8377): a caller is its
    /// agent token alone, which is no API key.
    AgentOnly(Arc<crate::gateway::oauth::AgentRegistry>),
}

/// The two agents the fixture registers under [`McpAccess::AgentToken`]. Both
/// share one display name, so they are one principal and two proven agent ids.
pub(super) const AGENT_A: &str = "agent-a";
pub(super) const AGENT_B: &str = "agent-b";
const AUDIENCE: &str = "audience-fixture";

fn agent_secret(id: &str) -> String {
    format!("{id}-secret-0123456789-0123456789")
}

/// A bearer the fixture's agent registry validates for `id`. Deterministic, so
/// the same string is also an API key ([`agent_api_keys`]): the gateway runs
/// its API-key layer before the agent layer.
pub(super) fn agent_token(id: &str) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({ "sub": id, "exp": 4_102_444_800_u64, "iat": 1_700_000_000_u64, "aud": AUDIENCE }),
        &jsonwebtoken::EncodingKey::from_secret(agent_secret(id).as_bytes()),
    )
    .expect("sign agent token")
}

/// The agents' tokens as API keys, both under the one display name `shared`.
pub(super) fn agent_api_keys(access: &McpAccess) -> Vec<crate::config::ApiKeyConfig> {
    match access {
        McpAccess::AgentToken => [AGENT_A, AGENT_B]
            .map(|id| super::audience_fixture::api_key_for("shared", agent_token(id).as_bytes()))
            .to_vec(),
        _ => Vec::new(),
    }
}

/// The agent registry `access` turns agent auth on against, if any. Handed
/// to the state builder, so the listener registry and the request middleware
/// re-validate against one registry.
pub(super) fn agent_registry(
    access: &McpAccess,
) -> Option<Arc<crate::gateway::oauth::AgentRegistry>> {
    match access {
        McpAccess::AgentToken => {
            let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
            for id in [AGENT_A, AGENT_B] {
                registry.register(crate::gateway::oauth::AgentDefinition {
                    client_id: id.to_string(),
                    name: "shared".to_string(),
                    hs256_secret: Some(agent_secret(id)),
                    rs256_public_key: None,
                    scopes: vec!["tools:alpha:*:*".to_string(), "tools:caps:*:*".to_string()],
                    issuer: None,
                    audience: Some(AUDIENCE.to_string()),
                });
            }
            Some(registry)
        }
        McpAccess::AgentOnly(registry) => Some(Arc::clone(registry)),
        _ => None,
    }
}

pub(super) fn public_paths(access: &McpAccess) -> Vec<String> {
    match access {
        McpAccess::PublicPath => vec!["/mcp".to_string()],
        _ => AuthConfig::default().public_paths,
    }
}

/// Shape the state's identity checks for `access`.
pub(super) fn apply(st: &mut AppState, access: &McpAccess) {
    // The agent registry is the state builder's ([`agent_registry`]); only
    // the certificate policy is set here.
    let admitted = match access {
        McpAccess::MtlsCert => crate::mtls::config::CertMatchConfig {
            any: Some(true),
            ..Default::default()
        },
        McpAccess::MtlsOu(ou) => crate::mtls::config::CertMatchConfig {
            ou: Some((*ou).to_string()),
            ..Default::default()
        },
        McpAccess::Authenticated
        | McpAccess::PublicPath
        | McpAccess::AgentToken
        | McpAccess::AgentOnly(_) => return,
    };
    st.mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig {
            enabled: true,
            policies: vec![crate::mtls::config::PolicyRuleConfig {
                match_criteria: admitted,
                allow: crate::mtls::config::ToolScopeConfig {
                    backends: vec!["alpha".to_string()],
                    tools: vec!["*".to_string()],
                },
                deny: crate::mtls::config::ToolScopeConfig::default(),
            }],
            ..Default::default()
        },
    ));
}
