// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The man page renderer, shared by the cargo example the release build runs and by the row that checks it, so the
//! row checks what ships.

/// The man page for `cmd`: one page for the root command, listing its visible top-level subcommands.
/// The page's `.TH` line names the bare package version: the CLI's own version string adds the UI API version, which
/// is not part of the page's title.
pub(crate) fn render(cmd: clap::Command) -> String {
    let mut out = Vec::new();
    clap_mangen::Man::new(cmd.version(env!("CARGO_PKG_VERSION")))
        .render(&mut out)
        .expect("rendering into memory cannot fail");
    String::from_utf8(out).expect("clap_mangen writes UTF-8")
}
