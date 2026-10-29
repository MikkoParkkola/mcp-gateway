// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's own `secrets:` rules, applied on its send.
//!
//! Every `tools/call` to a backend, on every route, passes through
//! [`Backend::request_attempted`](super::Backend), so the rules are applied
//! there and nowhere else. The rules come from the backend's own config: the
//! instance a config reload builds carries the reloaded rules. Values are
//! resolved by the one resolver the registry stamps on every backend it
//! registers, so a value an env file assigns is seen.
//!
//! Order matters. Every key a rule owns is dropped from the arguments before
//! the `Mcp-Param` mirror reads them, so a caller's value for such a key is
//! never mirrored into a header; the resolved values are added after the
//! mirror, so the secret is never mirrored either. Resolution happens before
//! the call is admitted, so a value that does not resolve holds no permit.

use std::sync::Arc;

use serde_json::Value;

use super::Backend;
use crate::secret_injection::{
    CredentialRule, InjectTarget, drop_owned, inject_rules, tool_matches_rule,
};
use crate::secrets::SecretResolver;
use crate::{Error, Result};

/// What a call is sent with: its params, and its per-call headers.
pub(super) type Outbound = (Option<Value>, Vec<(String, String)>);

/// A call's params with the keys its rules own dropped, and the resolved
/// values held back until the mirror has read the params.
pub(super) struct Prepared {
    /// What the mirror reads.
    pub(super) params: Option<Value>,
    /// The arguments with the values added, and the headers to set; `None`
    /// when no rule applies to the call.
    injected: Option<(Value, Vec<(String, String)>)>,
    /// Every header a matching rule owns, set or not: a rule whose value
    /// resolves empty still keeps any header of its name off the call.
    owned_headers: Vec<String>,
}

impl Prepared {
    /// The params and headers to send: the resolved values added, each
    /// header replacing any of the same name, compared case-insensitively.
    pub(super) fn apply(self, mut headers: Vec<(String, String)>) -> Outbound {
        headers.retain(|(held, _)| {
            !self
                .owned_headers
                .iter()
                .any(|owned| held.eq_ignore_ascii_case(owned))
        });
        let Some((arguments, injected)) = self.injected else {
            return (self.params, headers);
        };
        let mut params = self.params;
        if let Some(Value::Object(map)) = params.as_mut() {
            map.insert("arguments".to_owned(), arguments);
        }
        headers.extend(injected);
        (params, headers)
    }
}

impl Backend {
    /// Stamped by the registry that registers this backend; the first stamp
    /// wins.
    pub(crate) fn stamp_secret_resolver(&self, resolver: Arc<SecretResolver>) {
        let _ = self.secret_resolver.set(resolver);
    }

    /// The rules of this backend that apply to `tool`.
    fn secret_rules_for<'a>(&'a self, tool: &str) -> Vec<&'a CredentialRule> {
        self.config
            .secrets
            .iter()
            .filter(|rule| tool_matches_rule(tool, &rule.tools))
            .collect()
    }

    /// Drops what the relay check must not judge as the caller's: the keys
    /// this backend's rules overwrite for `tool`. The captured instance's
    /// rules, so the check and the send read the same ones across a reload.
    #[cfg(feature = "firewall")]
    pub(crate) fn strip_secret_keys(&self, tool: &str, arguments: &mut Value) {
        if let Some(resolver) = self.secret_resolver.get() {
            crate::secret_injection::strip_overwritten(
                &self.config.secrets,
                resolver,
                tool,
                arguments,
            );
        }
    }

    /// Resolves the rules that apply to this call and drops the keys they own
    /// from the params the mirror reads.
    ///
    /// # Errors
    ///
    /// A configuration error naming the backend and the rule, never the
    /// value: no resolver was stamped, the transport cannot carry a rule, a
    /// value does not resolve, an argument rule meets arguments that are not
    /// an object, or a header value is not a valid header value.
    pub(super) fn prepare_secrets(&self, method: &str, params: Option<Value>) -> Result<Prepared> {
        let unchanged = |params| {
            Ok(Prepared {
                params,
                injected: None,
                owned_headers: Vec::new(),
            })
        };
        if method != "tools/call" || self.config.secrets.is_empty() {
            return unchanged(params);
        }
        let Some(tool) = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return unchanged(params);
        };
        let rules = self.secret_rules_for(&tool);
        let Some(first) = rules.first() else {
            return unchanged(params);
        };
        for rule in &rules {
            self.refuse_secret_target(rule)?;
        }
        let Some(resolver) = self.secret_resolver.get() else {
            return Err(Error::Config(format!(
                "backend '{}' secret rule '{}' has no secret resolver: this backend was \
                 not registered by the gateway, so its rule is not applied",
                self.name, first.name
            )));
        };
        let mut params = params;
        let owned = if let Some(Value::Object(map)) = params.as_mut() {
            // An absent `arguments` is an empty object: a rule still applies.
            let arguments = map
                .entry("arguments")
                .and_modify(|value| {
                    if value.is_null() {
                        *value = Value::Object(serde_json::Map::new());
                    }
                })
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            drop_owned(&self.config.secrets, &tool, arguments);
            Some(arguments.clone())
        } else {
            None
        };
        let Some(owned) = owned else {
            return unchanged(params);
        };
        let injection = inject_rules(&self.config.secrets, resolver, &self.name, &tool, owned)?;
        let owned_headers = rules
            .iter()
            .filter(|rule| matches!(rule.inject_as, InjectTarget::Header))
            .map(|rule| rule.inject_key.clone())
            .collect();
        Ok(Prepared {
            params,
            injected: Some((injection.arguments, injection.headers.into_iter().collect())),
            owned_headers,
        })
    }

    /// Refuses a rule this backend cannot deliver where it says. Config load
    /// refuses each of these first; this holds for a backend built in code.
    fn refuse_secret_target(&self, rule: &CredentialRule) -> Result<()> {
        let refusal = |why: &str| {
            Err(Error::Config(format!(
                "backend '{}' secret rule '{}' {why}: the rule is not applied",
                self.name, rule.name
            )))
        };
        #[cfg(feature = "a2a")]
        if matches!(
            self.config.transport,
            crate::config::TransportConfig::A2a { .. }
        ) {
            return refusal("is on an A2A backend, which forwards only the message");
        }
        match rule.inject_as {
            InjectTarget::Query => refusal("injects into a URL query parameter"),
            InjectTarget::Header if !self.transport_carries_identity_headers() => {
                refusal("injects a header on a transport that sends no request headers")
            }
            InjectTarget::Header | InjectTarget::Argument => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "secret_send_tests.rs"]
mod tests;
