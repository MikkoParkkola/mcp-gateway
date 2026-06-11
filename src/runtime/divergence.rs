//! Substrate-divergence detection.
//!
//! Compiles the same descriptor on two substrates, compares the results,
//! and logs any behavioral delta to the audit trail with a `substrate-id`
//! tag.  CI fails on undocumented divergence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::runtime::audit::{AuditTrail, SubstrateId};
use crate::runtime::compiler::{AppleVmSpec, GvisorBundle};
use crate::runtime::descriptor::SandboxDescriptor;
use crate::runtime::substrate::{CompiledSpec, SubstrateKind};

/// A single detected divergence between two substrate outputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateDivergence {
    /// First substrate.
    pub substrate_a: SubstrateId,

    /// Second substrate.
    pub substrate_b: SubstrateId,

    /// Field or category that diverged.
    pub field: String,

    /// Value on substrate A (JSON string).
    pub value_a: String,

    /// Value on substrate B (JSON string).
    pub value_b: String,

    /// Whether this divergence has been documented in the registry.
    pub documented: bool,
}

/// Registry of known, accepted divergences between substrates.
#[derive(Debug, Clone, Default)]
pub struct DivergenceRegistry {
    documented: BTreeSet<String>,
}

impl DivergenceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a divergence key as documented / accepted.
    pub fn document(&mut self, key: impl Into<String>) {
        self.documented.insert(key.into());
    }

    /// Check whether a divergence key is documented.
    pub fn is_documented(&self, key: &str) -> bool {
        self.documented.contains(key)
    }

    /// Return all documented divergence keys.
    pub fn documented_keys(&self) -> &BTreeSet<String> {
        &self.documented
    }
}

/// Detect divergences between gVisor and Apple substrate outputs for the
/// same descriptor.
///
/// Differences are recorded in `audit` and returned.  The caller decides
/// whether undocumented divergences should fail CI.
pub fn detect_divergence(
    descriptor: &SandboxDescriptor,
    registry: &DivergenceRegistry,
    audit: &mut AuditTrail,
) -> Result<Vec<SubstrateDivergence>> {
    let gvisor_spec = SubstrateKind::Gvisor.compile(descriptor)?;
    let apple_spec = SubstrateKind::Apple.compile(descriptor)?;

    let gvisor_bundle = match &gvisor_spec {
        CompiledSpec::Gvisor(b) => b,
        CompiledSpec::Apple(_) => unreachable!(),
    };
    let apple_spec_inner = match &apple_spec {
        CompiledSpec::Apple(s) => s,
        CompiledSpec::Gvisor(_) => unreachable!(),
    };

    let id_a = SubstrateId("gvisor".into());
    let id_b = SubstrateId("apple".into());
    let mut divergences = Vec::new();

    compare_fields(
        gvisor_bundle,
        apple_spec_inner,
        &id_a,
        &id_b,
        registry,
        &mut divergences,
        audit,
    );

    Ok(divergences)
}

fn compare_fields(
    gvisor: &GvisorBundle,
    apple: &AppleVmSpec,
    id_a: &SubstrateId,
    id_b: &SubstrateId,
    registry: &DivergenceRegistry,
    divergences: &mut Vec<SubstrateDivergence>,
    audit: &mut AuditTrail,
) {
    if gvisor.hostname != apple.name {
        push_divergence(
            divergences,
            audit,
            registry,
            id_a,
            id_b,
            "hostname_vs_name",
            &gvisor.hostname,
            &apple.name,
        );
    }

    let gvisor_mem = gvisor.linux["resources"]["memory"]["limit"].as_u64();
    if gvisor_mem != Some(apple.memory_bytes) {
        push_divergence(
            divergences,
            audit,
            registry,
            id_a,
            id_b,
            "memory_limit",
            &format!("{gvisor_mem:?}"),
            &apple.memory_bytes.to_string(),
        );
    }

    if gvisor.oci_version != "1.0.2" {
        push_divergence(
            divergences,
            audit,
            registry,
            id_a,
            id_b,
            "oci_version",
            &gvisor.oci_version,
            "N/A (Apple VM)",
        );
    }

    let gvisor_env: BTreeSet<String> = gvisor
        .process["env"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let apple_env: BTreeSet<String> = apple
        .environment
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    if gvisor_env != apple_env {
        push_divergence(
            divergences,
            audit,
            registry,
            id_a,
            id_b,
            "environment",
            &format!("{gvisor_env:?}"),
            &format!("{apple_env:?}"),
        );
    }

    let gvisor_caps: BTreeSet<String> = gvisor
        .process["capabilities"]["bounding"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let apple_caps: BTreeSet<String> = BTreeSet::new();
    if gvisor_caps != apple_caps {
        push_divergence(
            divergences,
            audit,
            registry,
            id_a,
            id_b,
            "capabilities",
            &format!("{gvisor_caps:?}"),
            &format!("{apple_caps:?}"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_divergence(
    divergences: &mut Vec<SubstrateDivergence>,
    audit: &mut AuditTrail,
    registry: &DivergenceRegistry,
    id_a: &SubstrateId,
    id_b: &SubstrateId,
    field: &str,
    value_a: &str,
    value_b: &str,
) {
    let documented = registry.is_documented(field);
    divergences.push(SubstrateDivergence {
        substrate_a: id_a.clone(),
        substrate_b: id_b.clone(),
        field: field.to_string(),
        value_a: value_a.to_string(),
        value_b: value_b.to_string(),
        documented,
    });
    audit.log_divergence(id_a, id_b, field, value_a, value_b);
}
