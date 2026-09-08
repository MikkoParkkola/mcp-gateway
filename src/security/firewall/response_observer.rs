// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Instance-local observations at the actual engine/detector call sites.
//! Compiled only into unit tests; never produces or replaces a verdict.

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub(super) struct ResponseObserver {
    pub inspections: AtomicUsize,
    pub prompt_scans: AtomicUsize,
    pub redactions: AtomicUsize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseInspectionCounts {
    pub inspections: usize,
    pub prompt_scans: usize,
    pub redactions: usize,
}

impl ResponseObserver {
    pub fn snapshot(&self) -> ResponseInspectionCounts {
        ResponseInspectionCounts {
            inspections: self.inspections.load(Ordering::Relaxed),
            prompt_scans: self.prompt_scans.load(Ordering::Relaxed),
            redactions: self.redactions.load(Ordering::Relaxed),
        }
    }
}
