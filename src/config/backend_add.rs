// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pieces `mcp-gateway add` needs to write a whole backend (MIK-7787): the
//! default OAuth stanza, whether one backend's `${VAR}` references would
//! resolve at the next load, and the pre-write check that its secret
//! references resolve (ADR-028).

use super::OAuthConfig;
use super::{BackendConfig, EnvOverlay, secret_ref};

/// The stanza `oauth: {}` deserialises to: enabled, no fixed client, so the
/// backend OAuth client follows the server's metadata and registers itself.
impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: super::default_true(),
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: None,
            shared_account: false,
        }
    }
}

// Only the dashboard's add and enable paths ask this (`gateway::ui`, which the
// `webui` feature gates); without it nothing would call the method.
#[cfg(feature = "webui")]
impl BackendConfig {
    /// Every `${VAR}` in this backend's `headers` and `env` that the loader
    /// would refuse (C4), by the loader's own rule (`expand_field`: unset or
    /// empty counts as unresolved), one message each.
    ///
    /// Scoped to one backend on purpose: a reference in some other backend
    /// that only the running gateway's environment resolves must not block
    /// adding or enabling this one.
    pub(crate) fn unresolved_references(&self, name: &str, overlay: &EnvOverlay) -> Vec<String> {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| (format!("backends.{name}.headers.{key}"), value));
        let env = self
            .env
            .iter()
            .map(|(key, value)| (format!("backends.{name}.env.{key}"), value));
        // A whole-value secret reference is not a template: its own check is
        // `check_secret_references` (a `file:` path may hold `${` literally).
        let mut unresolved: Vec<String> = headers
            .chain(env)
            .filter(|(_, value)| !secret_ref::is_reference(value))
            .filter_map(|(field, value)| secret_ref::expand_field(&field, value, overlay).err())
            .collect();
        unresolved.sort();
        unresolved
    }
}

impl BackendConfig {
    /// The pre-write check every writer of a backend runs: each whole-value
    /// `env:`, `file:` or `keychain:` in its `headers` and `env` is resolved,
    /// read and dropped, through the load's own evaluator, enabled or not, so
    /// a reference that does not resolve never reaches gateway.yaml or the
    /// next start. `${VAR}` templates are not checked here: an unset one keeps
    /// add-disabled.
    ///
    /// `pub` only for the binary's discover and setup writers; it returns to
    /// `pub(crate)` once no binary-side writer of `backends` remains.
    ///
    /// # Errors
    ///
    /// Every unresolved reference, one message each naming the field and the
    /// entry, never a value.
    pub fn check_secret_references(
        &self,
        name: &str,
        overlay: &EnvOverlay,
    ) -> Result<(), Vec<String>> {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| (format!("backends.{name}.headers.{key}"), value));
        let env = self
            .env
            .iter()
            .map(|(key, value)| (format!("backends.{name}.env.{key}"), value));
        let mut refused: Vec<String> = headers
            .chain(env)
            .filter(|(_, value)| secret_ref::is_reference(value))
            .filter_map(|(field, value)| {
                secret_ref::evaluate_backend_value(&field, value, overlay).err()
            })
            .collect();
        refused.sort();
        if refused.is_empty() {
            Ok(())
        } else {
            Err(refused)
        }
    }
}

/// Validate that a backend name contains only safe characters.
///
/// Allowed: ASCII alphanumerics, hyphens, underscores, dots.
/// Max length: 128 characters.
pub(crate) fn validate_backend_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Backend name must not be empty".to_string());
    }
    if name.len() > 128 {
        return Err("Backend name exceeds 128 characters".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(
            "Backend name may only contain ASCII letters, digits, hyphens, underscores, and dots"
                .to_string(),
        );
    }
    Ok(())
}
