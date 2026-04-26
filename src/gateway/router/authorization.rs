//! Shared authorization for backend tool invocations.

use axum::http::StatusCode;
use serde_json::Value;
use tracing::warn;

use super::AppState;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::{
    Action, AgentIdentity as OAuthAgentIdentity, check_agent_scope_and_audit_reason,
};
use crate::mtls::{CertIdentity, PolicyDecision};
use crate::security::{validate_tool_name, validate_url_not_ssrf};

pub(super) struct OwnedToolTarget {
    pub server: String,
    pub tool: String,
    pub arguments: Value,
}

#[derive(Clone, Copy)]
pub(super) struct ToolTarget<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub arguments: &'a Value,
}

impl OwnedToolTarget {
    pub(super) fn as_target(&self) -> ToolTarget<'_> {
        ToolTarget {
            server: &self.server,
            tool: &self.tool,
            arguments: &self.arguments,
        }
    }
}

pub(super) struct AuthorizationError {
    pub code: i32,
    pub status: StatusCode,
    pub message: String,
}

impl AuthorizationError {
    fn forbidden(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
}

pub(super) fn backend_tool_targets_for_call(
    meta_mcp: &MetaMcp,
    tool_name: &str,
    arguments: &Value,
) -> Vec<OwnedToolTarget> {
    if let Some(server) = meta_mcp.surfaced_tool_server(tool_name) {
        return vec![OwnedToolTarget {
            server: server.to_string(),
            tool: tool_name.to_string(),
            arguments: arguments.clone(),
        }];
    }

    match tool_name {
        "gateway_invoke" => target_from_invoke_arguments(arguments)
            .into_iter()
            .collect(),
        "gateway_execute" => targets_from_code_mode_arguments(arguments),
        _ => Vec::new(),
    }
}

pub(super) fn is_admin_meta_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "gateway_kill_server"
            | "gateway_revive_server"
            | "gateway_set_profile"
            | "gateway_set_state"
            | "gateway_reload_config"
            | "gateway_reload_capabilities"
    )
}

pub(super) fn require_admin_tool_access(
    client: Option<&AuthenticatedClient>,
    tool_name: &str,
) -> Result<(), AuthorizationError> {
    if client.is_some_and(|client| client.admin) {
        return Ok(());
    }

    Err(AuthorizationError::forbidden(
        -32600,
        format!("Tool '{tool_name}' requires admin access"),
    ))
}

pub(super) fn authorize_tool_target(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
    cert_identity: Option<&CertIdentity>,
    target: ToolTarget<'_>,
) -> Result<(), AuthorizationError> {
    if target.server.is_empty() || target.tool.is_empty() {
        return Ok(());
    }

    validate_tool_name(target.tool)
        .map_err(|e| AuthorizationError::forbidden(-32600, e.clone()))?;

    if let Some(client) = client
        && !client.can_access_backend(target.server)
    {
        return Err(AuthorizationError::forbidden(
            -32003,
            format!(
                "Client '{}' not authorized for backend '{}'",
                client.name, target.server
            ),
        ));
    }

    state
        .tool_policy
        .check(target.server, target.tool)
        .map_err(|e| AuthorizationError::forbidden(-32600, e.to_string()))?;

    if let Some(client) = client {
        client
            .check_tool_scope(target.server, target.tool)
            .map_err(|e| AuthorizationError::forbidden(-32600, e))?;
    }

    if !state.mtls_policy.is_empty() {
        let decision = state
            .mtls_policy
            .evaluate(cert_identity, target.server, target.tool);
        if decision == PolicyDecision::Deny {
            let identity_label =
                cert_identity.map_or("<unauthenticated>", |id| id.display_name.as_str());
            warn!(
                server = target.server,
                tool = target.tool,
                identity = identity_label,
                "Tool invocation denied by mTLS policy"
            );
            return Err(AuthorizationError::forbidden(
                -32600,
                format!(
                    "Tool '{}' on server '{}' is blocked by certificate policy",
                    target.tool, target.server
                ),
            ));
        }
    }

    if state.agent_auth.enabled {
        let identity = oauth_agent_identity.ok_or_else(|| {
            AuthorizationError::forbidden(
                -32600,
                "Agent authentication is enabled but no validated agent identity was found",
            )
        })?;
        check_agent_scope_and_audit_reason(identity, target.server, target.tool, &Action::Execute)
            .map_err(|e| AuthorizationError::forbidden(-32600, e))?;
    }

    if state.ssrf_protection
        && let Some(backend) = state.backends.get(target.server)
        && let Some(url) = backend.transport_url()
    {
        validate_url_not_ssrf(url)
            .map_err(|e| AuthorizationError::forbidden(-32600, e.to_string()))?;
    }

    Ok(())
}

fn target_from_invoke_arguments(arguments: &Value) -> Option<OwnedToolTarget> {
    Some(OwnedToolTarget {
        server: arguments.get("server")?.as_str()?.to_string(),
        tool: arguments.get("tool")?.as_str()?.to_string(),
        arguments: arguments
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    })
}

fn targets_from_code_mode_arguments(arguments: &Value) -> Vec<OwnedToolTarget> {
    if let Some(chain) = arguments.get("chain").and_then(Value::as_array) {
        return chain
            .iter()
            .filter_map(|step| {
                let tool_ref = step.get("tool")?.as_str()?;
                let (server, tool) = parse_qualified_tool_ref(tool_ref)?;
                Some(OwnedToolTarget {
                    server: server.to_string(),
                    tool: tool.to_string(),
                    arguments: step
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                })
            })
            .collect();
    }

    let Some(tool_ref) = arguments.get("tool").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Some((server, tool)) = parse_qualified_tool_ref(tool_ref) else {
        return Vec::new();
    };

    vec![OwnedToolTarget {
        server: server.to_string(),
        tool: tool.to_string(),
        arguments: arguments
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    }]
}

fn parse_qualified_tool_ref(tool_ref: &str) -> Option<(&str, &str)> {
    let (server, tool) = tool_ref.split_once(':')?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    Some((server, tool))
}
