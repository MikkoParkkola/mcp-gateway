// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The part of the firewall a reload may change (ADR-029, amended
//! 2026-10-30): the compiled rules and the credential-redaction switch that
//! pairs with them. Every generation compiles its own, and each check takes
//! the policy of the generation it is judged under, so one request never
//! mixes two rule sets. The firewall's state (anomaly, tenant, budget,
//! relay) is not here: it outlives every generation.

use super::CompiledRule;
use super::collusion_gate::{CollusionAction, CollusionConfig, compile_flows, compile_globs};
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

/// The collusion fields a reload may change (ADR-029, amended, item 2),
/// compiled: what a witness is judged with. The detector's own parameters
/// are not here; they are fixed when the detector is built
/// ([`DetectorParams`]).
pub(crate) struct CollusionView {
    pub(super) sources: Vec<glob::Pattern>,
    pub(super) non_egress: Vec<glob::Pattern>,
    /// `allowed_flows` as (source, egress).
    pub(super) flows: Vec<(glob::Pattern, glob::Pattern)>,
    pub(super) action: CollusionAction,
}

impl CollusionView {
    pub(crate) fn compile(config: &CollusionConfig) -> Self {
        Self {
            sources: compile_globs(&config.sources),
            non_egress: compile_globs(&config.non_egress),
            flows: compile_flows(&config.allowed_flows),
            action: config.action,
        }
    }

    /// What relay detection does under this view.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by the relay gate once it judges under the witness's generation"
        )
    )]
    pub(crate) const fn action(&self) -> CollusionAction {
        self.action
    }
}

impl std::fmt::Debug for CollusionView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollusionView")
            .field("sources", &self.sources.len())
            .field("non_egress", &self.non_egress.len())
            .field("flows", &self.flows.len())
            .field("action", &self.action)
            .finish()
    }
}

/// The relay detector a gateway runs, fixed at startup: the firewall switch
/// and the three collusion settings applied when evidence is recorded.
/// Every generation carries the running one forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DetectorParams {
    firewall_enabled: bool,
    window_secs: u64,
    min_matches: usize,
    common_principals: usize,
}

impl DetectorParams {
    pub(crate) const fn of(config: &FirewallConfig) -> Self {
        Self {
            firewall_enabled: config.enabled,
            window_secs: config.collusion.window_secs,
            min_matches: config.collusion.min_matches,
            common_principals: config.collusion.common_principals,
        }
    }

    /// Whether `wanted`'s live collusion fields may apply on this detector:
    /// the firewall runs, and `wanted` asks for this detector's window and
    /// thresholds. Otherwise a live `block` would run on settings the
    /// operator did not set.
    pub(crate) fn runs(&self, wanted: &FirewallConfig) -> bool {
        self.firewall_enabled && *self == Self::of(wanted)
    }
}
