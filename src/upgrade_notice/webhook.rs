// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The webhook `notify` notice text. Delivery (the marker file, `show_once`)
//! stays in the CLI binary, so the library writes no file.

/// The notice text, also carried as an item of the 4.0.0 release notice.
pub const ITEM: &str = "Webhook `notify` now defaults to false, and an \
enabled webhook reaches only sessions whose API key may access the capability \
backend. A 3.x webhook that relied on the old default is still acknowledged \
but no longer notifies: add `notify: true` to each webhook that should reach \
MCP sessions.";
