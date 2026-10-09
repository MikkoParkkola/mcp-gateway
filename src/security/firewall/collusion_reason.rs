// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8201`: why a relay was reported, and the capacity counter.

/// Why a relay was reported (`MIK-8201`, design §14.3). Plain detection wins:
/// a finding names a stated bound only when no match is plainly unheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayReason {
    /// The sender holds the text from no source at all.
    Relay,
    /// The sender holds it from another tool only (design §14.2).
    OtherSource,
    /// The only evidence is a caller's overflow record (`MIK-8123`).
    OverflowWitness,
    /// An excuse of the sender for that source was dropped for room.
    ExcuseLost,
}

impl RelayReason {
    /// The `reason` label of `mcp_gateway_collusion_relay_total`.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::OtherSource => "other_source",
            Self::OverflowWitness | Self::ExcuseLost => "capacity",
        }
    }
}

/// Capacity bounds an operator can read, by `bound` (`MIK-8201`).
pub(super) const CAPACITY_METRIC: &str = "mcp_gateway_collusion_capacity_total";
