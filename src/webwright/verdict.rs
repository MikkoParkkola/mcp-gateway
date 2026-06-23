//! The spike gate verdict (MIK-5205 AC.6) and the platform-reuse provenance
//! record (AC.10, B4-PLATFORM).

/// The three conditions the gate evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateInputs {
    /// (i) bnaut-attestation run identity propagates to the gateway trace and
    /// hebb decision-pins.
    pub attestation_propagates: bool,
    /// (ii) hebb-recall measurably short-circuits a repeat task.
    pub hebb_short_circuits: bool,
    /// (iii) the end-to-end task completes with a full artifact bundle.
    pub end_to_end_complete: bool,
}

impl GateInputs {
    /// Whether all three conditions hold.
    #[must_use]
    pub fn all_pass(self) -> bool {
        self.attestation_propagates && self.hebb_short_circuits && self.end_to_end_complete
    }
}

/// The verdict the spike files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateVerdict {
    /// All three gate conditions passed → file the botnaut-client
    /// productionization epic.
    FileProductionizationEpic,
    /// At least one condition failed → INSPIRE-only, no further engineering.
    InspireOnly,
}

impl GateVerdict {
    /// Evaluate the gate: all three pass → file the epic; else INSPIRE-only.
    #[must_use]
    pub fn evaluate(inputs: GateInputs) -> Self {
        if inputs.all_pass() {
            Self::FileProductionizationEpic
        } else {
            Self::InspireOnly
        }
    }
}

/// Provenance of the spike: the primitives it reuses and the upstream license
/// (AC.10 — "zero bespoke plumbing").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Upstream Webwright license (MIT — hard-fork available).
    pub webwright_license: &'static str,
    /// Platform primitives reused without bespoke reimplementation.
    pub reused_primitives: Vec<&'static str>,
}

impl Provenance {
    /// The spike's reuse record.
    #[must_use]
    pub fn spike() -> Self {
        Self {
            webwright_license: "MIT",
            reused_primitives: vec![
                "botnaut-client",
                "hebb",
                "nab",
                "mcp-gateway",
                "claude-elite",
            ],
        }
    }

    /// Whether `primitive` is reused by the spike.
    #[must_use]
    pub fn reuses(&self, primitive: &str) -> bool {
        self.reused_primitives.contains(&primitive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_pass_files_epic() {
        let inputs = GateInputs {
            attestation_propagates: true,
            hebb_short_circuits: true,
            end_to_end_complete: true,
        };
        assert_eq!(
            GateVerdict::evaluate(inputs),
            GateVerdict::FileProductionizationEpic
        );
    }

    #[test]
    fn any_failure_is_inspire_only() {
        let inputs = GateInputs {
            attestation_propagates: true,
            hebb_short_circuits: false,
            end_to_end_complete: true,
        };
        assert_eq!(GateVerdict::evaluate(inputs), GateVerdict::InspireOnly);
    }

    #[test]
    fn provenance_reuses_platform_primitives_under_mit() {
        let p = Provenance::spike();
        assert_eq!(p.webwright_license, "MIT");
        assert!(p.reuses("hebb"));
        assert!(p.reuses("mcp-gateway"));
    }
}
