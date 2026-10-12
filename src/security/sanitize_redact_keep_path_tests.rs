// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{UNPARSEABLE_URL, redact_url_keep_path as redact};

#[test]
fn a_parsed_url_keeps_its_path_and_drops_the_rest() {
    let out = redact("https://user:PW1@api.invalid/v1/x?token=Q1#frag=F1");
    assert_eq!(out, "https://api.invalid/v1/x");
    assert_eq!(
        redact("https://:PW11@api.invalid/v1"),
        "https://api.invalid/v1"
    );
    assert_eq!(
        redact("postgres://u:PW12@db.invalid/app"),
        "postgres://db.invalid/app"
    );
}

#[test]
fn a_value_without_a_host_is_whole_or_a_placeholder() {
    // Every shape here once leaked through a hand-written cut.
    for raw in [
        "user:PW2@idp.invalid/p?t=Q2",
        "bob@idp.invalid/p?t=Q3#F3",
        "//carol:PW5@idp.invalid/token",
        "//carol:PW6@idp.invalid/x://y",
        "http://u:PW7@[bad/path",
        "bob:PW8@idp.invalid/x://y",
        "u:PW9://p@idp.invalid/x",
        "u:PW10/p@idp.invalid/x",
        "/rpc?token=Q4",
        "/rpc#access_token=F5",
    ] {
        assert_eq!(redact(raw), UNPARSEABLE_URL, "{raw:?}");
    }
    // Nothing credential-bearing: shown whole, so a mistyped value is named.
    for raw in ["/rpc", "search_flights", "localhost:8080/mcp"] {
        assert_eq!(redact(raw), raw);
    }
    // The boundary: the same value with userinfo is no longer echoed.
    assert_eq!(redact("u:p@localhost:8080/mcp"), UNPARSEABLE_URL);
}
