// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pieces `mcp-gateway add` needs to write a whole backend (MIK-7787): the
//! default OAuth stanza, and whether one backend's `${VAR}` references would
//! resolve at the next load.

use super::{BackendConfig, EnvOverlay, OAuthConfig, secret_ref};

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
            token_refresh_buffer_secs: super::default_token_refresh_buffer(),
            shared_account: false,
        }
    }
}

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
        let mut unresolved: Vec<String> = headers
            .chain(env)
            .filter_map(|(field, value)| secret_ref::expand_field(&field, value, overlay).err())
            .collect();
        unresolved.sort();
        unresolved
    }
}
