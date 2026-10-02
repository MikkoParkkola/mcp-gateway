// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The era probe cap override shared by the suites that drive shell-script peers.
#![allow(unsafe_code)] // `set_var` is unsafe in edition 2024; see `widen_probe_cap`

/// Debug builds read this to widen the era probe's 2 s cap (`src/backend/era.rs`).
/// The peers here are shell scripts that fork per request; on a stalled runner
/// one answer can take longer than 2 s, and the probe would read that as silence.
const PROBE_CAP_ENV: &str = "MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS";

/// Widen the probe cap for every peer in this binary that is meant to answer.
/// A silent peer then waits out the whole cap, so it is set once, high enough to
/// absorb a stalled runner and low enough to keep that one wait short.
pub fn widen_probe_cap() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: tests run in parallel threads, so other backends may already
        // be probing. std serialises `set_var` against its own env reads
        // (`std::env::var`) and against `Command::spawn`, which holds the env
        // read lock. The peers are stdio children with no DNS, so no foreign
        // `getenv` runs in this test binary.
        unsafe { std::env::set_var(PROBE_CAP_ENV, "20000") };
    });
}
