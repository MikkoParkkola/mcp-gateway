//! Override hook — pin a sandbox to a specific substrate.
//!
//! When the uniform abstraction is wrong for a particular workload, the
//! operator can force a sandbox onto a specific substrate via
//! [`OverrideHook`].

use serde::{Deserialize, Serialize};

use crate::runtime::descriptor::SandboxDescriptor;
use crate::runtime::substrate::SubstrateKind;

/// Override policy for substrate pinning.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverridePolicy {
    /// Override rules, evaluated in order.
    pub rules: Vec<OverrideRule>,
}

/// A single override rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideRule {
    /// Sandbox name pattern (exact match).
    pub sandbox_name: String,

    /// Substrate to pin to.
    pub substrate: SubstrateKind,
}

/// Applies override policies to sandbox descriptors.
#[derive(Debug, Clone, Default)]
pub struct OverrideHook {
    /// The active override policy.
    pub policy: OverridePolicy,
}

impl OverrideHook {
    /// Create a new hook with an empty policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve the effective substrate for a descriptor.
    ///
    /// If a rule matches the descriptor's name, the pinned substrate is
    /// returned; otherwise [`SubstrateKind::auto_detect`] is used.
    pub fn resolve(&self, descriptor: &SandboxDescriptor) -> SubstrateKind {
        for rule in &self.policy.rules {
            if rule.sandbox_name == descriptor.name {
                return rule.substrate;
            }
        }
        SubstrateKind::auto_detect()
    }

    /// Set the override policy.
    #[must_use]
    pub fn with_policy(mut self, policy: OverridePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add a single override rule.
    pub fn add_rule(&mut self, rule: OverrideRule) {
        self.policy.rules.push(rule);
    }
}
