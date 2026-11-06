// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A failed scan's log line shows its error's client text escaped.

use super::scan_failed;

/// A config scan's error can name a client file whose path holds an ANSI
/// sequence or a bidi override; the logged line holds neither raw.
#[test]
fn a_scan_failure_line_escapes_client_text_in_its_error() {
    let error = anyhow::anyhow!("cannot read /home/u/\u{1b}[31mevil\u{202e}.json");
    for what in ["Config", "Process"] {
        let line = scan_failed(what, &error).to_string();
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{202e}'),
            "{line:?}"
        );
        assert!(
            line.starts_with(&format!("{what} scan failed: ")),
            "{line:?}"
        );
    }
}
