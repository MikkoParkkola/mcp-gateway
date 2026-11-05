// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gate's provisional miss of an unregistered backend, kept per target
//! until that invocation's dispatch takes it.

use super::{in_memo, target_key};

/// Clear `(server, tool)`'s provisional gate miss: each gate entry judges
/// afresh, so a mark never outlives the invocation that set it.
pub(crate) fn clear_gate_absent(server: &str, tool: &str) {
    in_memo(|memo| memo.gate_absent.take(&target_key(server, tool)));
}

/// Mark that the gate found `(server, tool)`'s backend unregistered.
pub(crate) fn mark_gate_absent(server: &str, tool: &str) {
    in_memo(|memo| memo.gate_absent.set(target_key(server, tool), ()));
}

/// Take `(server, tool)`'s provisional gate miss: whether the gate found the
/// backend unregistered. `false` outside a memo.
pub(crate) fn take_gate_absent(server: &str, tool: &str) -> bool {
    in_memo(|memo| memo.gate_absent.take(&target_key(server, tool)).is_some()).unwrap_or(false)
}
