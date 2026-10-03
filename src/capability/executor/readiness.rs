// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a capability's login is in place (MIK-7787, design D4).
//!
//! The bundled catalogue is a library: a capability that declares
//! `auth.required: true` is served only once its credential exists, so a new
//! install lists the keyless capabilities and the user turns a keyed one on by
//! supplying its key. Decided cheaply and without prompting: an environment
//! key is looked up in the same live overlay the executor resolves with; an
//! `oauth:<provider>` key needs a cached or stored token for that provider. A
//! `keychain:` or `file:` key, and a per-caller account credential, cannot be
//! decided without reading a secret or knowing the caller, so they stay served.

use std::collections::HashMap;

use super::super::{AuthConfig, CapabilityDefinition};
use super::CapabilityExecutor;

/// The environment variable an `auth.key` names, in each spelling
/// `fetch_credential` reads: `env:NAME`, `{env.NAME}`, or a bare `NAME`.
fn env_var_of(key: &str) -> Option<&str> {
    if let Some(name) = key.strip_prefix("env:") {
        return Some(name);
    }
    if let Some(name) = key.strip_prefix("{env.").and_then(|k| k.strip_suffix('}')) {
        return Some(name);
    }
    CapabilityExecutor::looks_like_env_var_name(key).then_some(key)
}

impl CapabilityExecutor {
    /// What is missing before a capability with this `auth` can run, or
    /// `None` when nothing is (or when it cannot be decided here).
    ///
    /// `oauth_seen` memoises provider lookups across one listing, so a
    /// catalogue with many capabilities on one provider stats its token file
    /// once.
    pub(crate) fn missing_credential(
        &self,
        auth: &AuthConfig,
        oauth_seen: &mut HashMap<String, bool>,
    ) -> Option<String> {
        // A per-caller account credential depends on who calls; a shared
        // account is gateway-held, so its key is checked like any other.
        let per_caller = auth
            .account
            .as_deref()
            .is_some_and(|account| !self.account_is_shared(account));
        if !auth.required || per_caller {
            return None;
        }
        if let Some(var) = env_var_of(&auth.key) {
            let present = self.env.get().resolve(var).is_some_and(|v| !v.is_empty());
            return (!present).then(|| var.to_string());
        }
        let provider = auth.key.strip_prefix("oauth:")?;
        let logged_in = *oauth_seen.entry(provider.to_string()).or_insert_with(|| {
            self.oauth_tokens.read().contains_key(provider)
                || self
                    .token_storage
                    .as_ref()
                    .is_some_and(|storage| storage.token_path(provider, provider).exists())
        });
        (!logged_in).then(|| format!("a {provider} login"))
    }

    /// The line `mcp-gateway cap list` prints for `cap`: name, description and
    /// auth type, then `off: needs <KEY>` when [`Self::missing_credential`]
    /// says the gateway would not list it. One rule, shared with `tools/list`.
    #[must_use]
    pub fn list_line(&self, cap: &CapabilityDefinition) -> String {
        let auth_info = if cap.auth.required {
            format!(" [{}]", cap.auth.auth_type)
        } else {
            String::new()
        };
        format!("  {} - {}{}", cap.name, cap.description, auth_info)
    }
}

#[cfg(test)]
#[path = "readiness_list_tests.rs"]
mod list_tests;
