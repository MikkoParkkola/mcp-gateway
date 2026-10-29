// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook `notify` notice, delivered once per install.
//!
//! The 4.0.0 release notice is a migration keyed on the version stamp, and a
//! pre-release build already stamped 4.0.0 runs no migration. This notice is
//! keyed on a marker file instead, so every install hears it exactly once:
//! from the release notice when upgrading from 3.x, from here otherwise. A
//! fresh install is marked without being told about a default it never had.

use std::io::Write;
use std::path::Path;

use mcp_gateway::upgrade_notice::webhook::ITEM;

/// Present once this install has had the notice.
const MARKER: &str = ".notice-4.0.0-webhook-notify";

/// Record that this install has had, or needs no, notice.
pub(super) fn mark(data_dir: &Path) -> std::io::Result<()> {
    std::fs::write(data_dir.join(MARKER), "")
}

/// Write the notice to `out` unless this install already had it; returns
/// whether it was written.
pub(super) fn show_once(data_dir: &Path, out: &mut impl Write) -> std::io::Result<bool> {
    if data_dir.join(MARKER).exists() {
        return Ok(false);
    }
    writeln!(out, "v4.0.0: {ITEM}")?;
    mark(data_dir)?;
    Ok(true)
}
