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
    // `&` first, so no entity another replacement writes is escaped again.
    let pairs = [
        ".replace(/&/g, '&amp;')",
        ".replace(/</g, '&lt;')",
        ".replace(/>/g, '&gt;')",
        ".replace(/\"/g, '&quot;')",
        ".replace(/'/g, '&#39;')",
    ];
    let at: Vec<Option<usize>> = pairs.iter().map(|p| body.find(p)).collect();
    assert!(
        at.iter().all(Option::is_some),
        "esc() must make all five replacements: {body}"
    );
    assert!(
        at.iter().skip(1).all(|p| p > &at[0]),
        "esc() must replace & before the others: {body}"
    );
}

/// Every `${...}` inside a double-quoted attribute value is `esc(...)`, the
/// row index `i`, or a choice between two string literals: anything else can
/// carry a quote out of the attribute.
#[test]
fn every_attribute_interpolation_is_escaped() {
    let attribute = regex::Regex::new(r#"\s[a-z][a-z-]*="([^"]*)""#).expect("pattern");
    let expression = regex::Regex::new(r"\$\{([^}]*)\}").expect("pattern");
    let choice = regex::Regex::new(r"^\w+ \? '[^']*' : '[^']*'$").expect("pattern");
    let found: Vec<String> = INDEX
        .lines()
        .enumerate()
        .flat_map(|(n, line)| {
            attribute
                .captures_iter(line)
                .filter_map(|c| c.get(1))
                .flat_map(|value| {
                    expression
                        .captures_iter(value.as_str())
                        .filter_map(|c| c.get(1))
                        .map(|e| e.as_str().to_owned())
                        .collect::<Vec<_>>()
                })
                .filter(|e| !(is_one_esc_call(e) || e == "i" || choice.is_match(e)))
                .map(|e| format!("{}: {e}", n + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        found.is_empty(),
        "attribute values interpolated without esc():\n{}",
        found.join("\n")
    );
}

/// Whether `expression` is one whole `esc(...)` call: the parenthesis it
/// opens closes at its end, so `esc(a) + b` is not.
fn is_one_esc_call(expression: &str) -> bool {
    let Some(inner) = expression.strip_prefix("esc(") else {
        return false;
    };
    let mut depth = 1_usize;
    for (at, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return at + 1 == inner.len();
                }
            }
            _ => {}
        }
    }
    false
}
