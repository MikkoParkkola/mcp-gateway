//! Slack app manifest validation (SLACKCTL.SCOPE.1).
//!
//! The manifest file at `manifests/slack_app_manifest.yaml` declares the Slack
//! app configuration including Socket Mode, required bot scopes, and event
//! subscriptions. This module validates that the committed manifest contains
//! the required fields.

use std::path::Path;

use serde::Deserialize;

/// Parsed Slack app manifest.
#[derive(Debug, Deserialize)]
pub struct SlackAppManifest {
    /// Display name of the Slack app.
    pub display_name: String,
    /// Socket Mode configuration.
    pub socket_mode: SocketModeConfig,
    /// OAuth scopes requested.
    pub oauth_scopes: OAuthScopes,
    /// Event subscriptions.
    pub event_subscriptions: EventSubscriptions,
}

/// Socket Mode configuration.
#[derive(Debug, Deserialize)]
pub struct SocketModeConfig {
    /// Whether Socket Mode is enabled.
    pub enabled: bool,
    /// App-level token environment variable reference (xapp-...).
    pub app_token_env: String,
}

/// OAuth scopes.
#[derive(Debug, Deserialize)]
pub struct OAuthScopes {
    /// Bot token scopes.
    pub bot: Vec<String>,
}

/// Event subscriptions.
#[derive(Debug, Deserialize)]
pub struct EventSubscriptions {
    /// Whether event subscriptions are enabled.
    pub enabled: bool,
    /// Bot events subscribed to.
    pub bot_events: Vec<String>,
}

/// Required bot scopes for the control plane.
const REQUIRED_BOT_SCOPES: &[&str] = &["channels:history", "app_mentions:read", "chat:write"];

/// Required bot events for the control plane.
const REQUIRED_BOT_EVENTS: &[&str] = &["message.channels", "app_mention"];

/// Validate a manifest file at the given path.
///
/// # Errors
///
/// Returns an error if the manifest is missing, unreadable, or fails validation.
pub fn validate_manifest(path: &Path) -> Result<SlackAppManifest, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read manifest: {e}"))?;

    let manifest: SlackAppManifest = serde_yaml::from_str(&content)
        .map_err(|e| format!("manifest parse error: {e}"))?;

    validate_manifest_struct(&manifest)?;
    Ok(manifest)
}

/// Validate a parsed manifest struct against the required configuration.
pub fn validate_manifest_struct(manifest: &SlackAppManifest) -> Result<(), String> {
    if !manifest.socket_mode.enabled {
        return Err("Socket Mode must be enabled".to_string());
    }

    if manifest.socket_mode.app_token_env.is_empty() {
        return Err("app_token_env must reference the app-level token env var".to_string());
    }

    if manifest.socket_mode.app_token_env.contains("xapp-") {
        return Err("app_token_env must be an env var reference, not a literal token".to_string());
    }

    for scope in REQUIRED_BOT_SCOPES {
        if !manifest.oauth_scopes.bot.contains(&scope.to_string()) {
            return Err(format!("missing required bot scope: {scope}"));
        }
    }

    if !manifest.event_subscriptions.enabled {
        return Err("event_subscriptions must be enabled".to_string());
    }

    for event in REQUIRED_BOT_EVENTS {
        if !manifest.event_subscriptions.bot_events.contains(&event.to_string()) {
            return Err(format!("missing required bot event: {event}"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> SlackAppManifest {
        SlackAppManifest {
            display_name: "mcp-gateway-control".to_string(),
            socket_mode: SocketModeConfig {
                enabled: true,
                app_token_env: "SLACK_APP_TOKEN".to_string(),
            },
            oauth_scopes: OAuthScopes {
                bot: vec![
                    "channels:history".to_string(),
                    "app_mentions:read".to_string(),
                    "chat:write".to_string(),
                ],
            },
            event_subscriptions: EventSubscriptions {
                enabled: true,
                bot_events: vec![
                    "message.channels".to_string(),
                    "app_mention".to_string(),
                ],
            },
        }
    }

    #[test]
    fn valid_manifest_passes() {
        assert!(validate_manifest_struct(&valid_manifest()).is_ok());
    }

    #[test]
    fn socket_mode_disabled_rejected() {
        let mut m = valid_manifest();
        m.socket_mode.enabled = false;
        assert!(validate_manifest_struct(&m).is_err());
    }

    #[test]
    fn missing_scope_rejected() {
        let mut m = valid_manifest();
        m.oauth_scopes.bot = vec!["chat:write".to_string()];
        assert!(validate_manifest_struct(&m).is_err());
    }

    #[test]
    fn literal_token_in_manifest_rejected() {
        let mut m = valid_manifest();
        m.socket_mode.app_token_env = "xapp-1-secret".to_string();
        assert!(validate_manifest_struct(&m).is_err());
    }
}
