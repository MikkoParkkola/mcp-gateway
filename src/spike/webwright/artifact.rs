use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::Serialize;

/// Kind of artifact in a run bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Source code artifact (spike runner, module implementation).
    Code,
    /// Screenshot captured during browser automation.
    Screenshot,
    /// DOM snapshot captured from the browser page.
    DomSnapshot,
    /// Model reasoning trace (JSON-encoded step sequence).
    ModelTrace,
    /// Hebb decision-pin recording a task checkpoint.
    HebbDecisionPin,
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Screenshot => write!(f, "screenshot"),
            Self::DomSnapshot => write!(f, "dom_snapshot"),
            Self::ModelTrace => write!(f, "model_trace"),
            Self::HebbDecisionPin => write!(f, "hebb_decision_pin"),
        }
    }
}

/// A single artifact entry in the bundle.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactEntry {
    /// Kind of artifact (code, screenshot, DOM, trace, pin).
    pub kind: ArtifactKind,
    /// Human-readable name for the artifact.
    pub name: String,
    /// Relative path where the artifact is stored.
    pub path: String,
    /// Size in bytes.
    pub byte_size: u64,
    /// RFC3339 creation timestamp.
    pub created_at: String,
}

/// Artifact bundle for a Webwright spike run.
///
/// Collects code + screenshots + DOM snapshots + model trace + hebb
/// decision-pins as one deliverable unit following the 'run-artifact-first'
/// pattern from Webwright's design philosophy.
pub struct ArtifactBundle {
    run_id: String,
    entries: Mutex<BTreeMap<ArtifactKind, Vec<ArtifactEntry>>>,
    total_entries: AtomicU64,
}

impl ArtifactBundle {
    /// Create a new empty artifact bundle for the given run.
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            entries: Mutex::new(BTreeMap::new()),
            total_entries: AtomicU64::new(0),
        }
    }

    /// The run identifier this bundle belongs to.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Add an artifact entry to the bundle.
    pub fn add(&self, entry: ArtifactEntry) {
        self.entries
            .lock()
            .entry(entry.kind)
            .or_default()
            .push(entry);
        self.total_entries.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of entries across all kinds.
    pub fn total_entries(&self) -> u64 {
        self.total_entries.load(Ordering::Relaxed)
    }

    /// Whether a given artifact kind has at least one entry.
    pub fn has_kind(&self, kind: ArtifactKind) -> bool {
        self.entries
            .lock()
            .get(&kind)
            .is_some_and(|v| !v.is_empty())
    }

    /// Count entries of a given kind.
    pub fn count_by_kind(&self, kind: ArtifactKind) -> usize {
        self.entries
            .lock()
            .get(&kind)
            .map_or(0, Vec::len)
    }

    /// Snapshot all entries grouped by kind.
    pub fn snapshot(&self) -> BTreeMap<ArtifactKind, Vec<ArtifactEntry>> {
        self.entries.lock().clone()
    }

    /// Verify the bundle contains all five required artifact kinds.
    pub fn verify_complete(&self) -> BundleVerification {
        let required = [
            ArtifactKind::Code,
            ArtifactKind::Screenshot,
            ArtifactKind::DomSnapshot,
            ArtifactKind::ModelTrace,
            ArtifactKind::HebbDecisionPin,
        ];
        let mut missing = Vec::new();
        for kind in &required {
            if !self.has_kind(*kind) {
                missing.push(*kind);
            }
        }
        BundleVerification {
            complete: missing.is_empty(),
            missing,
            total_entries: self.total_entries(),
        }
    }
}

/// Result of verifying artifact bundle completeness.
#[derive(Debug, Clone)]
pub struct BundleVerification {
    /// Whether all five required artifact kinds are present.
    pub complete: bool,
    /// Which kinds are missing (empty when complete is true).
    pub missing: Vec<ArtifactKind>,
    /// Total number of entries across all kinds.
    pub total_entries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(kind: ArtifactKind) -> ArtifactEntry {
        ArtifactEntry {
            kind,
            name: format!("test_{kind}"),
            path: format!("/artifacts/{kind}/test"),
            byte_size: 100,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn bundle_starts_empty() {
        let bundle = ArtifactBundle::new("run-1");
        assert_eq!(bundle.run_id(), "run-1");
        assert_eq!(bundle.total_entries(), 0);
        assert!(!bundle.verify_complete().complete);
    }

    #[test]
    fn bundle_tracks_entries_by_kind() {
        let bundle = ArtifactBundle::new("run-1");
        bundle.add(sample_entry(ArtifactKind::Code));
        bundle.add(sample_entry(ArtifactKind::Screenshot));

        assert!(bundle.has_kind(ArtifactKind::Code));
        assert!(bundle.has_kind(ArtifactKind::Screenshot));
        assert!(!bundle.has_kind(ArtifactKind::DomSnapshot));
        assert_eq!(bundle.total_entries(), 2);
    }

    #[test]
    fn bundle_verify_complete_when_all_five_kinds_present() {
        let bundle = ArtifactBundle::new("run-1");
        bundle.add(sample_entry(ArtifactKind::Code));
        bundle.add(sample_entry(ArtifactKind::Screenshot));
        bundle.add(sample_entry(ArtifactKind::DomSnapshot));
        bundle.add(sample_entry(ArtifactKind::ModelTrace));
        bundle.add(sample_entry(ArtifactKind::HebbDecisionPin));

        let v = bundle.verify_complete();
        assert!(v.complete);
        assert!(v.missing.is_empty());
        assert_eq!(v.total_entries, 5);
    }

    #[test]
    fn bundle_verify_reports_missing_kinds() {
        let bundle = ArtifactBundle::new("run-1");
        bundle.add(sample_entry(ArtifactKind::Code));

        let v = bundle.verify_complete();
        assert!(!v.complete);
        assert_eq!(v.missing.len(), 4);
    }
}
