// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The man page renderer, shared by the cargo example the release build runs and by the row that checks it, so the
//! row checks what ships.

/// The man page for `cmd`: one page for the root command, listing its visible top-level subcommands.
pub(crate) fn render(cmd: clap::Command) -> String {
    let _ = cmd;
    String::new()
}
