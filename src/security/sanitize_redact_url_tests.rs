// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::redact_url_for_diagnostics as redact;

#[test]
fn strips_every_credential_bearing_part() {
    assert_eq!(
        redact("https://user:tok@api.example.com/services/SECRET?t=X#f=Y"),
        "https://api.example.com"
    );
    assert_eq!(redact("http://localhost:8080/mcp"), "http://localhost:8080");
}

#[test]
fn never_echoes_input_it_cannot_parse() {
    // The failure path must not become the leak.
    assert_eq!(redact("not a url ?token=SECRET"), "<invalid-url>");
    assert!(!redact("not a url ?token=SECRET").contains("SECRET"));
}

#[test]
fn hostless_schemes_get_a_marker_not_a_path() {
    assert_eq!(redact("file:///etc/SECRET"), "file://<no-host>");
}
