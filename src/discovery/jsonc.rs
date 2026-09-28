// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read JSON with comments and trailing commas (JSONC), as Zed's
//! `settings.json` allows (#1876).

/// `text` with `//` and `/* */` comments outside strings removed and each
/// trailing comma before `}` or `]` dropped, ready for a strict JSON parser.
/// `None` for an unterminated block comment or string.
#[must_use]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "red-first stub; wired into the Zed reader by the fix"
    )
)]
#[expect(clippy::unnecessary_wraps, reason = "red-first stub")]
pub(crate) fn strip_jsonc(text: &str) -> Option<String> {
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::strip_jsonc;

    fn parse(text: &str) -> Value {
        let stripped = strip_jsonc(text).unwrap_or_else(|| panic!("strip failed: {text}"));
        serde_json::from_str(&stripped).unwrap_or_else(|e| panic!("{e}: {stripped}"))
    }

    #[test]
    fn line_and_block_comments_are_removed() {
        let v = parse("// top\n{ /* a */ \"a\": 1, // b\n \"b\": /* inline */ 2 }\n");
        assert_eq!(v, serde_json::json!({"a": 1, "b": 2}));
    }

    #[test]
    fn trailing_commas_are_dropped() {
        let v = parse("{ \"a\": [1, 2, ], \"b\": { \"c\": 3, }, }");
        assert_eq!(v, serde_json::json!({"a": [1, 2], "b": {"c": 3}}));
    }

    #[test]
    fn comment_markers_inside_strings_are_kept() {
        let v =
            parse(r#"{ "url": "https://example.test/mcp", "s": "a /* b */ c", "q": "x\"//y" }"#);
        assert_eq!(v["url"], "https://example.test/mcp");
        assert_eq!(v["s"], "a /* b */ c");
        assert_eq!(v["q"], "x\"//y");
    }

    #[test]
    fn a_comma_inside_a_string_before_a_brace_is_kept() {
        let v = parse(r#"{ "a": ",}" }"#);
        assert_eq!(v["a"], ",}");
    }

    #[test]
    fn unterminated_input_is_refused() {
        assert_eq!(strip_jsonc("{ \"a\": 1 /* never closed"), None);
        assert_eq!(strip_jsonc("{ \"a\": \"never closed }"), None);
    }
}
