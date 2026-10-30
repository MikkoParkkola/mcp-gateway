// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The part of the firewall a reload may change (ADR-029, amended
//! 2026-10-30): the compiled rules and the credential-redaction switch that
//! pairs with them. Every generation compiles its own, and each check takes
//! the policy of the generation it is judged under, so one request never
//! mixes two rule sets. The firewall's state (anomaly, tenant, budget,
//! relay) is not here: it outlives every generation.

use super::CompiledRule;
use super::config::FirewallConfig;
use super::verdict::compile_rule;

/// One generation's firewall policy, compiled from its config.
pub(crate) struct FirewallPolicy {
    pub(super) rules: Vec<CompiledRule>,
    /// `security.firewall.credential_redaction`: a response scan may rewrite
    /// a credential in place.
    pub(super) credential_redaction: bool,
}

impl FirewallPolicy {
    /// Compile `config`'s rules. Never fails: a rule whose glob does not
    /// parse compiles to one that matches no tool, and the config load has
    /// already refused it by key path (POLICY.2).
    pub(crate) fn compile(config: &FirewallConfig) -> Self {
        Self {
            rules: config.rules.iter().map(compile_rule).collect(),
            credential_redaction: config.credential_redaction,
        }
    }

    /// Whether a response scan under this policy may rewrite a credential in
    /// place.
    pub(crate) const fn redacts(&self) -> bool {
        self.credential_redaction
    }
}

impl std::fmt::Debug for FirewallPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirewallPolicy")
            .field("rules", &self.rules.len())
            .field("credential_redaction", &self.credential_redaction)
            .finish()
    }
}
