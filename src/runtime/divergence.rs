// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Substrate-divergence detection and audit registry.
//!
//! **AC.4 (MIK-NEW.RUNTIME-D.4)**: any behavior delta between substrates logs
//! to audit with a substrate-id tag; CI fails on undocumented divergence.
//!
//! The [`DivergenceRegistry`] records structural differences between gVisor
//! and Apple VM compiled outputs.  Each record carries the descriptor name,
//! both substrate tags, and a human-readable description of the delta.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::substrate::Substrate;

/// Tag identifying which substrate produced an artifact.
///
/// Used in divergence records to tag the two sides being compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum SubstrateTag {
    /// gVisor `runsc` on Linux.
    GVisor,

    /// Apple containerization VM on macOS.
    AppleVm,
}

impl From<Substrate> for SubstrateTag {
    fn from(s: Substrate) -> Self {
        match s {
            Substrate::GVisor => Self::GVisor,
            Substrate::AppleVm => Self::AppleVm,
        }
    }
}

// ── DivergenceRecord ─────────────────────────────────────────────────────

/// A single cross-substrate divergence entry.
///
/// Logged to the [`DivergenceRegistry`] when the compiler detects a
/// structural difference between gVisor and Apple VM outputs for the
/// same descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DivergenceRecord {
    /// Name of the `SandboxDescriptor` that produced this divergence.
    pub descriptor_name: String,

    /// First substrate tag (typically gVisor).
    pub substrate_a: SubstrateTag,

    /// Second substrate tag (typically Apple VM).
    pub substrate_b: SubstrateTag,

    /// Human-readable description of the divergence.
    pub description: String,
}

// ── DivergenceRegistry ───────────────────────────────────────────────────

/// Thread-safe registry of cross-substrate divergences.
///
/// The compiler logs structural differences here so that CI can fail on
/// undocumented divergence (AC.4).
#[derive(Debug, Default, Clone)]
pub struct DivergenceRegistry {
    /// Internal storage protected by a mutex.
    records: std::sync::Arc<Mutex<Vec<DivergenceRecord>>>,
}

impl DivergenceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: std::sync::Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Log a divergence entry.
    ///
    /// Thread-safe: multiple compilers can log concurrently.
    pub fn log(
        &self,
        descriptor_name: &str,
        substrate_a: SubstrateTag,
        substrate_b: SubstrateTag,
        description: &str,
    ) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        records.push(DivergenceRecord {
            descriptor_name: descriptor_name.to_string(),
            substrate_a,
            substrate_b,
            description: description.to_string(),
        });
    }

    /// Return all recorded divergences (snapshot).
    #[must_use]
    pub fn get_all(&self) -> Vec<DivergenceRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Number of recorded divergences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Returns `true` if no divergences recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if at least one divergence is recorded.
    ///
    /// CI can use this to fail on undocumented divergence (AC.4).
    #[must_use]
    pub fn has_divergence(&self) -> bool {
        !self.is_empty()
    }

    /// Clear all records.
    pub fn clear(&self) {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_has_no_divergence() {
        let r = DivergenceRegistry::new();
        assert!(r.is_empty());
        assert!(!r.has_divergence());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn log_and_retrieve_records() {
        let r = DivergenceRegistry::new();
        r.log(
            "test-sandbox",
            SubstrateTag::GVisor,
            SubstrateTag::AppleVm,
            "mount count mismatch",
        );

        assert_eq!(r.len(), 1);
        assert!(r.has_divergence());

        let records = r.get_all();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].descriptor_name, "test-sandbox");
        assert_eq!(records[0].substrate_a, SubstrateTag::GVisor);
        assert_eq!(records[0].substrate_b, SubstrateTag::AppleVm);
        assert_eq!(records[0].description, "mount count mismatch");
    }

    #[test]
    fn multiple_logs_are_preserved() {
        let r = DivergenceRegistry::new();
        r.log("a", SubstrateTag::GVisor, SubstrateTag::AppleVm, "d1");
        r.log("b", SubstrateTag::GVisor, SubstrateTag::AppleVm, "d2");
        r.log("c", SubstrateTag::GVisor, SubstrateTag::AppleVm, "d3");

        assert_eq!(r.len(), 3);
    }

    #[test]
    fn clear_removes_all_records() {
        let r = DivergenceRegistry::new();
        r.log("x", SubstrateTag::GVisor, SubstrateTag::AppleVm, "d");
        assert_eq!(r.len(), 1);
        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn substrate_tag_from_substrate() {
        assert_eq!(SubstrateTag::from(Substrate::GVisor), SubstrateTag::GVisor);
        assert_eq!(
            SubstrateTag::from(Substrate::AppleVm),
            SubstrateTag::AppleVm
        );
    }

    #[test]
    fn divergence_record_serde_round_trip() {
        let record = DivergenceRecord {
            descriptor_name: "test".into(),
            substrate_a: SubstrateTag::GVisor,
            substrate_b: SubstrateTag::AppleVm,
            description: "cpu shares != vcpu".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: DivergenceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
    }
}
