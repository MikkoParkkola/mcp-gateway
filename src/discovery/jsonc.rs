// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read JSON with comments and trailing commas (JSONC), as Zed's
//! `settings.json` allows (#1876).

/// `text` with `//` and `/* */` comments outside strings removed and each
/// trailing comma before `}` or `]` dropped, ready for a strict JSON parser.
/// `None` for an unterminated block comment or string.
#[must_use]
pub(crate) fn strip_jsonc(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                out.push('"');
                loop {
                    let c = chars.next()?;
                    out.push(c);
                    match c {
                        '\\' => out.push(chars.next()?),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|&c| c != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                loop {
                    let c = chars.next()?;
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    Some(drop_trailing_commas(&out))
}

/// Remove a `,` whose next non-space character is `}` or `]`. Runs after
/// comments are gone, and skips string contents.
fn drop_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(&next) = chars.get(i + 1) {
                    out.push(next);
                    i += 1;
                }
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if !matches!(next, Some('}' | ']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
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
