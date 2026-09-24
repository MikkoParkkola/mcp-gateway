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

/// Present once this install has had the notice.
const MARKER: &str = ".notice-4.0.0-webhook-notify";

/// The notice text, also carried as an item of the 4.0.0 release notice.
pub(super) const ITEM: &str = "Webhook `notify` now defaults to false, and an \
enabled webhook reaches only sessions whose API key may access the capability \
backend. A 3.x webhook that relied on the old default is still acknowledged \
but no longer notifies: add `notify: true` to each webhook that should reach \
MCP sessions.";

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
