// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Verbatim cross-principal relay detection (OWASP ASI10, partial).
//!
//! Content delivered to principal A that principal B then sends out through a
//! backend call, when B never received it from that source itself. Each side
//! looks ordinary to a per-principal control; only the pair is suspicious.
//!
//! This is the pure core: winnowed fingerprints, bounded in-process state and
//! the relay predicate. Wiring into the request and response paths, the
//! config surface and metrics come in later increments.

use std::time::{Duration, Instant};

/// What the detector does. Mirrors the operator-facing `collusion.action`;
/// `block` arrives with the request-path wiring that can refuse a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayAction {
    /// No state is kept.
    Off,
    /// Findings are reported, calls proceed.
    Observe,
}

/// Detector tuning. Defaults are the design's documented values.
#[derive(Debug, Clone)]
#[allow(dead_code)] // red-first stub; the implementation reads every field
pub(crate) struct RelayParams {
    pub(crate) action: RelayAction,
    pub(crate) window: Duration,
    pub(crate) min_matches: usize,
    pub(crate) common_principals: usize,
    pub(crate) max_fingerprints: usize,
}

impl Default for RelayParams {
    fn default() -> Self {
        Self {
            action: RelayAction::Off,
            window: Duration::from_secs(600),
            min_matches: 2,
            common_principals: 5,
            max_fingerprints: 250_000,
        }
    }
}

/// A relay: content principal `receiver` got from `source` left via `sender`.
///
/// Carries digests and a count, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayFinding {
    pub(crate) source: u64,
    pub(crate) receiver: u64,
    pub(crate) sender: u64,
    pub(crate) tool: String,
    pub(crate) matches: usize,
}

/// Hashes per winnowing window.
const W: usize = 16;

/// Winnowing: the rightmost minimum of every `W`-hash window, distinct, in
/// position order.
fn winnow(_hashes: &[u64]) -> Vec<u64> {
    Vec::new()
}

/// Relay detector state for one gateway process.
pub(crate) struct CollusionDetector {
    _params: RelayParams,
}

impl CollusionDetector {
    pub(crate) fn new(params: RelayParams) -> Self {
        Self { _params: params }
    }

    /// Keyed 64-bit digest of an id (source, principal), as findings carry it.
    pub(crate) fn digest(&self, _id: &str) -> u64 {
        0
    }

    pub(crate) fn fingerprints(&self, _text: &str) -> Vec<u64> {
        Vec::new()
    }

    pub(crate) fn record_delivery_at(
        &self,
        _source: &str,
        _principal: &str,
        _sensitive: bool,
        _text: &str,
        _now: Instant,
    ) {
    }

    pub(crate) fn check_egress_at(
        &self,
        _principal: &str,
        _tool: &str,
        _args: &str,
        _now: Instant,
    ) -> Option<RelayFinding> {
        None
    }

    #[cfg(test)]
    fn is_tracked(&self, _fp: u64) -> bool {
        false
    }

    pub(crate) fn tracked_fingerprints(&self) -> usize {
        0
    }

    pub(crate) fn evicted(&self) -> u64 {
        0
    }

    pub(crate) fn saturated(&self) -> u64 {
        0
    }

    pub(crate) fn source_truncated(&self) -> u64 {
        0
    }
}

#[cfg(test)]
#[path = "collusion_tests.rs"]
mod tests;
