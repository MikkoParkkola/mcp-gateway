// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A failed `cap discover` step prints its error's client text escaped.

use super::failure_line;

/// Discovery, the config write and shadow adoption each print their error,
/// which can name a client file whose path holds an ANSI sequence or a bidi
/// override; the printed line holds neither raw.
#[test]
fn a_failure_line_escapes_client_text_in_its_error() {
    let error = anyhow::anyhow!("cannot read /home/u/\u{1b}[31mevil\u{202e}.json");
    for what in [
        "Discovery failed",
        "Failed to write config",
        "Failed to adopt shadow servers",
    ] {
        let line = failure_line(what, &error);
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{202e}'),
            "{line:?}"
        );
        assert!(line.starts_with(&format!("❌ {what}: ")), "{line:?}");
    }
}
