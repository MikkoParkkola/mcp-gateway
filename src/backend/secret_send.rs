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
    CredentialRule, InjectTarget, drop_owned, inject_resolved, resolve_rules, resolved_pairs,
    tool_matches_rule,
};
use crate::secrets::SecretResolver;
use crate::{Error, Result};

/// What a call is sent with: its params, its per-call headers, and whether a
/// rule injected a value (the send then needs a transport that redacts).
pub(super) type Outbound = (Option<Value>, Vec<(String, String)>, bool);

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
            return (self.params, headers, false);
        };
        let mut params = self.params;
        if let Some(Value::Object(map)) = params.as_mut() {
            map.insert("arguments".to_owned(), arguments);
        }
        headers.extend(injected);
        (params, headers, true)
    }
}

impl Backend {
    /// Stamped by the registry that registers this backend; the first stamp
    /// wins.
    pub(crate) fn stamp_secret_resolver(&self, resolver: Arc<SecretResolver>) {
        let _ = self.secret_resolver.set(resolver);
    }

    /// Stamped by the registry with its name's shared set; the first stamp
    /// wins.
    pub(crate) fn stamp_needles(&self, needles: Arc<crate::security::needles::NeedleSet>) {
        let _ = self.needles.set(needles);
    }

    /// Gives `transport` this backend's injected values, so every answer it
    /// reads, the startup exchange included, is scrubbed of them.
    pub(crate) fn attach_needles_to(&self, transport: &crate::transport::HttpTransport) {
        if let Some(needles) = self.needles.get() {
            transport.attach_needles(Arc::clone(needles));
        }
    }

    /// No injected value goes to a transport that cannot scrub its echo
    /// (DELTA-10): a construction site that skipped the attach refuses here
    /// rather than sending.
    pub(super) fn refuse_unredacted(
        &self,
        injects: bool,
        transport: &dyn crate::transport::Transport,
    ) -> Result<()> {
        if injects && !transport.redacts_injected_values() {
            tracing::error!(
                backend = %self.name,
                "a call carrying an injected secret was refused: its transport holds no \
                 redaction set"
            );
            return Err(Error::JsonRpc {
                code: -32603,
                message: "the gateway refused to send an injected credential over a transport \
                          that cannot redact it"
                    .to_owned(),
                data: None,
            });
        }
        Ok(())
    }

    /// Once this instance is registered: configured values its name's set
    /// holds that this instance's record lacks start their grace now.
    pub(crate) fn settle_superseded(&self) {
        if let (Some(needles), Some(configured)) = (self.needles.get(), self.configured.get()) {
            needles.pin_configured(&self.name, configured);
        }
    }

    /// Adds every value this backend's rules resolve to now, so a value is
    /// removed from what the backend sends before any call injects it (a
    /// tool description, an initialize answer). A rule that does not resolve
    /// yet adds nothing; its value joins when a send resolves it. The
    /// backend's configured `headers:` and `env:` credentials, `configured`
    /// (the registry's record for its name), are held first, with or without
    /// a resolver: they reach the backend on every start.
    pub(crate) fn seed_needles(
        &self,
        configured: &crate::config::configured_secrets::ConfiguredSecrets,
    ) {
        let Some(needles) = self.needles.get() else {
            return;
        };
        // This instance owns these pins: its name's set settles on them, so
        // a value the instance it replaces held and it lacks counts its grace
        // from now.
        let _ = self.configured.set(configured.clone());
        // Added only: until this instance is registered, the one it replaces
        // may go on serving, so nothing it holds is demoted yet.
        needles.add_configured(&self.name, configured);
        let Some(resolver) = self.secret_resolver.get() else {
            return;
        };
        for rule in &self.config.secrets {
            if let Ok(value) = resolver.resolve(&rule.value) {
                needles.insert(&self.name, &value);
            }
        }
    }

    /// Whether a deferred task dispatched with the `stored` fingerprint may
    /// be polled or settled, renewing what its dispatch sent when it may.
    /// One resolution of this backend's rules for `tool` is both compared
    /// with `stored` and renewed, so a rotation between two lookups cannot
    /// match one value and renew another. The call's own `arguments` must
    /// still inject; then every resolved value joins the set again, a value
    /// a later rule overwrote included. `false` (the task is withheld) on a
    /// mismatch, an unresolvable rule or a refused injection.
    pub(crate) fn vouch_and_renew(
        &self,
        tool: &str,
        arguments: &Value,
        stored: Option<&str>,
    ) -> bool {
        use crate::security::dispatched::{Dispatched, delivers};
        if self.secret_rules_for(tool).is_empty() {
            return delivers(stored, &Dispatched::None);
        }
        let Some(resolver) = self.secret_resolver.get() else {
            return false;
        };
        let Ok(values) = resolve_rules(&self.config.secrets, resolver, &self.name, tool) else {
            return false;
        };
        if !delivers(stored, &self.fingerprint(&values)) {
            return false;
        }
        let mut arguments = arguments.clone();
        if !arguments.is_object() {
            arguments = Value::Object(serde_json::Map::new());
        }
        drop_owned(&self.config.secrets, tool, &mut arguments);
        if inject_resolved(&self.config.secrets, &values, &self.name, tool, arguments).is_err() {
            return false;
        }
        mutant!("R2", { let _ = &values; }, self.insert_resolved(&values));
        true
    }

    /// The fingerprint of one resolution of this backend's rules.
    fn fingerprint(&self, values: &[Option<String>]) -> crate::security::dispatched::Dispatched {
        crate::security::dispatched::Dispatched::of(
            &self.name,
            &resolved_pairs(&self.config.secrets, values),
        )
    }

    /// Insert every non-empty value of one resolution into this backend's
    /// set (or renew it), and name a short one once. A send of these rules
    /// carries only such values: an injected value is its rule's resolved
    /// value, unchanged.
    fn insert_resolved(&self, values: &[Option<String>]) {
        let Some(needles) = self.needles.get() else {
            return;
        };
        for (rule, value) in self.config.secrets.iter().zip(values) {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                needles.insert(&self.name, value);
                needles.warn_if_short(&self.name, &rule.name, value);
            }
        }
    }

    /// The configured credentials this instance was seeded with; empty
    /// before it registers.
    pub(crate) fn configured_record(&self) -> crate::config::configured_secrets::ConfiguredSecrets {
        self.configured.get().cloned().unwrap_or_default()
    }

    /// The rules of this backend that apply to `tool`.
    fn secret_rules_for<'a>(&'a self, tool: &str) -> Vec<&'a CredentialRule> {
        self.config
            .secrets
            .iter()
            .filter(|rule| tool_matches_rule(tool, &rule.tools))
            .collect()
    }

    /// The argument keys this backend's rules for `tool` own: its send drops
    /// the caller's value for each, whatever the credential resolves to. The
    /// folder check refuses a call whose declared path argument is one.
    /// Key names only, never a value.
    #[cfg(feature = "firewall")]
    pub(crate) fn owned_argument_keys(&self, tool: &str) -> Vec<String> {
        self.secret_rules_for(tool)
            .into_iter()
            .filter(|rule| rule.inject_as == InjectTarget::Argument)
            .map(|rule| rule.inject_key.clone())
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
        if method != "tools/call" {
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
            // A deferring dispatch's slot learns that no rule applies.
            crate::security::dispatched::record(&self.name, &tool, || {
                Some(crate::security::dispatched::Dispatched::None)
            });
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
        // One resolution: what a deferring dispatch's slot fingerprints is
        // what this send injects.
        let values = resolve_rules(&self.config.secrets, resolver, &self.name, &tool)?;
        crate::security::dispatched::record(&self.name, &tool, || Some(self.fingerprint(&values)));
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
        let injection = inject_resolved(&self.config.secrets, &values, &self.name, &tool, owned)?;
        // Every value this send carries joins the backend's set before the
        // send leaves, so its echo is removed from whatever comes back.
        self.insert_resolved(&values);
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

#[cfg(test)]
#[path = "secret_attach_refusal_tests.rs"]
mod attach_refusal_tests;
