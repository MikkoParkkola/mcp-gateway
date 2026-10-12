// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only count of plan executions per [`MetaMcp`] (MIK-8406 t0): one
//! entry each time `gateway_run_playbook` or `gateway_execute` (single or
//! chain) starts a plan. A replay served or refused at the route stage must
//! leave it at zero. Keyed by the instance's address, so rows running in
//! parallel on their own gateways never see each other's counts, and no
//! field is added to [`MetaMcp`]. A freed instance's address can be
//! reused by a later gateway, so rows compare counts before and after, never
//! against an absolute number.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::MetaMcp;

fn entries() -> &'static Mutex<HashMap<usize, usize>> {
    static ENTRIES: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    ENTRIES.get_or_init(Mutex::default)
}

fn key(meta: &MetaMcp) -> usize {
    std::ptr::from_ref(meta) as usize
}

/// Count one plan execution on `meta`.
pub(crate) fn note(meta: &MetaMcp) {
    *entries().lock().unwrap().entry(key(meta)).or_default() += 1;
}

/// Plan executions `meta` has started.
pub(crate) fn count(meta: &MetaMcp) -> usize {
    entries()
        .lock()
        .unwrap()
        .get(&key(meta))
        .copied()
        .unwrap_or(0)
}
