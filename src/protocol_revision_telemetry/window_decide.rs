// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2 decision: the sealed prefix of clean HTTP segments, judged against
//! the operator's declaration. Test-only: the operator runs it through the
//! ignored `u1_production_decision` row, so it adds no public surface.

use std::io;

use super::window::WindowV2;
use super::{RetirementBlocked, Snapshot, Transport};

/// Milliseconds allowed between one segment's seal and the next start.
pub(crate) const RESTART_BUDGET_MS: u64 = 300_000;

/// The operator's declaration. Provenance comes from here, never the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) population: Vec<Transport>,
    pub(crate) listen: String,
    pub(crate) exe_prefix: String,
}

/// Why the v2 window cannot certify a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowBlocked {
    Retirement(RetirementBlocked),
    PopulationMismatch,
    UncleanSegment,
    ConcurrentHttpWriters,
    ForeignWriter,
    CoverageGap,
    NoSealedSegment,
}

/// The sealed span a decision was computed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedSpan {
    pub(crate) started_at: u64,
    pub(crate) ended_at_ms: u64,
    pub(crate) segments: usize,
    pub(crate) snapshot: Snapshot,
}

/// Evaluate the sealed prefix of clean HTTP segments against `declaration`.
pub(crate) fn decide(
    window: &WindowV2,
    declaration: &Declaration,
) -> (Option<SealedSpan>, Result<Vec<String>, WindowBlocked>) {
    let _ = (window, declaration); // STUB(red): certifies everything
    (None, Ok(Vec::new()))
}

/// Parse the operator's declaration. Every value is required.
pub(crate) fn parse_declaration(
    population: Option<&str>,
    listen: Option<&str>,
    exe_prefix: Option<&str>,
) -> io::Result<Declaration> {
    let _ = population; // STUB(red): accepts anything
    Ok(Declaration {
        population: vec![Transport::Http],
        listen: listen.unwrap_or_default().to_string(),
        exe_prefix: exe_prefix.unwrap_or_default().to_string(),
    })
}

#[cfg(test)]
#[path = "window_decide_tests.rs"]
mod tests;
