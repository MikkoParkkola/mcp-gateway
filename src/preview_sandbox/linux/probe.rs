// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The launcher's probe for an npm fetch (D7): npm and node beside the `npx`
//! the target names (a system install or an NVM-only node alike), npm's
//! version floor, and `ip` for bringing `lo` up, each inside a bound tree.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the npm fetch step, a later commit, probes")
)]

use std::path::{Path, PathBuf};

use crate::preview_sandbox::Refusal;

/// Where `ip` may live; the first that exists inside a bound tree is used.
pub(super) const IP_CANDIDATES: [&str; 4] = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

/// npm and node's directory beside `npx` (the path it was found at, before
/// symlinks are followed), as npm and node install them together.
pub(super) fn npm_beside(npx: &Path) -> Result<(PathBuf, PathBuf), Refusal> {
    let _ = npx;
    Err(Refusal::Step("the npm probe is not built yet".into()))
}

/// Refuse an npm older than 9: `npm --version` (2 s, environment cleared but
/// PATH = `node_dir`, since npm starts through `/usr/bin/env node`).
pub(super) fn check_npm(npm: &Path, node_dir: &Path) -> Result<(), Refusal> {
    let _ = (npm, node_dir);
    Err(Refusal::Step("the npm probe is not built yet".into()))
}

/// The first of `candidates` that exists, followed to its real file, and lies
/// under one of `bound` (the plan's read-only trees).
pub(super) fn find_ip(candidates: &[&str], bound: &[String]) -> Result<String, Refusal> {
    let _ = (candidates, bound);
    Err(Refusal::Step("the npm probe is not built yet".into()))
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
