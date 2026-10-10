// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only oracle (MIK-8259): how many times each egress classifier ran
//! its regex sets over a text carrying a given marker.
//!
//! Keyed by a marker the test plants in its own text, not by thread or as a
//! global total, so tests running in parallel, on any runtime thread, cannot
//! see each other's scans.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// The marker prefix a test plants; the marker runs to the next whitespace.
pub(crate) const MARKER: &str = "classification-marker-";

static RUNS: Mutex<Option<HashMap<(&'static str, String), usize>>> = Mutex::new(None);

/// One regex classification of `text` by `site`.
pub(crate) fn note(site: &'static str, text: &str) {
    let Some(at) = text.find(MARKER) else { return };
    let marker: String = text[at..]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let mut runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    *runs
        .get_or_insert_with(HashMap::new)
        .entry((site, marker))
        .or_default() += 1;
}

/// Classifications `site` ran over texts carrying `marker`.
pub(crate) fn runs(site: &'static str, marker: &str) -> usize {
    let runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    runs.as_ref()
        .and_then(|r| r.get(&(site, marker.to_owned())))
        .copied()
        .unwrap_or(0)
}
