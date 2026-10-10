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
        let refreshable = auth.token_endpoint.is_some();
        // The answer depends on whether this capability can refresh, so the
        // memo is per provider and per endpoint presence.
        let memo = format!("{provider}\0{refreshable}");
        let logged_in = *oauth_seen.entry(memo).or_insert_with(|| {
            // The rule `fetch_oauth_token` runs: an unexpired cached or stored
            // token, or an expired stored one with a refresh token and an
            // endpoint to use it at (the cache is never refreshed). A file that
            // cannot be read or parsed is no login.
            let cached = self
                .oauth_tokens
                .read()
                .get(provider)
                .is_some_and(|t| !t.is_expired());
            cached
                || self
                    .token_storage
                    .as_ref()
                    .and_then(|storage| storage.load(provider, provider))
                    .is_some_and(|token| {
                        !token.is_expired() || (refreshable && token.refresh_token.is_some())
                    })
        });
        (!logged_in).then(|| format!("a {provider} login"))
    }

    /// An executor that can answer readiness the way the running gateway does:
    /// `env` is the environment its config starts with, and the config's
    /// declared account descriptors are known, so a shared account's key is
    /// checked and a per-caller one is not.
    #[must_use]
    pub fn for_listing(
        config: &crate::config::Config,
        env: std::sync::Arc<crate::config::LiveEnv>,
    ) -> Self {
        let accounts =
            std::sync::Arc::new(crate::identity_propagation::AccountStrategyRegistry::default());
        crate::gateway::declare_account_descriptors(config, &accounts);
        Self::new().with_env(env).with_account_strategies(accounts)
    }

    /// When this listed capability stops being listed with no reload: the
    /// moment its last unexpired `oauth:` token reaches the 60 s buffer
    /// `is_expired` applies, in Unix seconds (MIK-7940). `None` when time
    /// alone cannot change it: not listed, not an `oauth:` key, a token with
    /// no expiry, or a stored token that can be refreshed.
    pub(crate) fn listing_expires_at(&self, auth: &AuthConfig) -> Option<u64> {
        if self.missing_credential(auth, &mut HashMap::new()).is_some() {
            return None;
        }
        let provider = auth.key.strip_prefix("oauth:")?;
        let cached = self
            .oauth_tokens
            .read()
            .get(provider)
            .filter(|t| !t.is_expired())
            .map(|t| t.expires_at);
        let stored = self
            .token_storage
            .as_ref()
            .and_then(|storage| storage.load(provider, provider));
        if auth.token_endpoint.is_some()
            && stored.as_ref().is_some_and(|t| t.refresh_token.is_some())
        {
            return None;
        }
        let stored = stored.filter(|t| !t.is_expired()).map(|t| t.expires_at);
        let valid = [cached, stored].into_iter().flatten();
        // Listed while any accepted token is unexpired; one without an expiry
        // never stops counting.
        valid
            .collect::<Option<Vec<u64>>>()?
            .into_iter()
            .max()
            .map(|expires_at| expires_at.saturating_sub(60))
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
        let off = self
            .missing_credential(&cap.auth, &mut HashMap::new())
            .map(|what| format!(" off: needs {what}"))
            .unwrap_or_default();
        format!("  {} - {}{}{}", cap.name, cap.description, auth_info, off)
    }
}

#[cfg(test)]
#[path = "readiness_list_tests.rs"]
mod list_tests;
