// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The classic web UI never builds an event handler from an interpolated
//! value, and its `esc()` escapes both quote characters, so a name that holds
//! a quote cannot end an attribute and add a handler of its own.

const INDEX: &str = include_str!("../src/gateway/ui/index.html");

/// Every inline `on<event>="..."` attribute whose value interpolates a
/// template expression, as `line: value`.
fn interpolated_handlers() -> Vec<String> {
    let handler = regex::Regex::new(r#"\bon[a-z]+="([^"]*)""#).expect("pattern");
    INDEX
        .lines()
        .enumerate()
        .flat_map(|(n, line)| {
            handler
                .captures_iter(line)
                .filter_map(|c| c.get(1))
                .filter(|value| value.as_str().contains("${"))
                .map(move |value| format!("{}: {}", n + 1, value.as_str()))
        })
        .collect()
}

#[test]
fn no_inline_handler_interpolates_a_value() {
    let found = interpolated_handlers();
    assert!(
        found.is_empty(),
        "inline handlers built from interpolated values:\n{}",
        found.join("\n")
    );
}

#[test]
fn esc_escapes_both_quote_characters() {
    let start = INDEX.find("function esc(").expect("the page defines esc()");
    let end = INDEX[start..].find("\n}\n").expect("esc() closes");
    let body = &INDEX[start..start + end];
    assert!(
        body.contains("&quot;") && body.contains("&#39;"),
        "esc() must escape \" and ': {body}"
    );
}
