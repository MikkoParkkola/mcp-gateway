// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T5/T6: the asset table's names are honest content hashes, and nothing
//! the shell serves reaches outside this origin. T7: the tooltip copy is one
//! of those assets, served as JSON.

use super::*;

#[test]
fn t5_every_asset_name_carries_its_content_hash() {
    assert!(
        !ASSETS.is_empty(),
        "the shell ships at least its stylesheet"
    );
    for (name, bytes) in ASSETS {
        let digest = crate::hashing::sha256_hex(bytes);
        // The label right before the extension: `name[.more].<hash>.<ext>`.
        let hash = name.rsplit('.').nth(1).unwrap_or_default();
        assert_eq!(hash, &digest[..12], "{name}: rename it after editing");
    }
}

/// CSS with its comments removed. Only real comments go: a `/*` inside a
/// quoted string or inside `url(...)` is text, not a comment, so a URL there
/// is still seen. The stylesheet carries the fonts' licences in a comment,
/// and those name web addresses that nothing fetches.
fn strip_css_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(c) = rest.chars().next() {
        if rest.starts_with("/*") {
            rest = rest[2..].find("*/").map_or("", |end| &rest[2 + end + 2..]);
            continue;
        }
        let quoted = c == '"' || c == '\'';
        let url = rest
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("url("));
        if quoted || url {
            // Copy the whole string or url(...) verbatim, escapes included.
            let close = if quoted { c } else { ')' };
            let start = if quoted { c.len_utf8() } else { 4 };
            let mut end = rest.len();
            let mut escaped = false;
            for (i, ch) in rest[start..].char_indices() {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == close {
                    end = start + i + ch.len_utf8();
                    break;
                }
            }
            out.push_str(&rest[..end]);
            rest = &rest[end..];
            continue;
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

#[test]
fn t6a_the_comment_strip_hides_nothing_that_is_fetched() {
    // A real comment goes, and its address with it.
    assert!(!strip_css_comments("a{} /* see https://fonts.test/ofl */ b{}").contains("https:"));
    // An address in a string or in url() stays, even beside a comment opener.
    for css in [
        r"a{background:url(https://off-origin.test/x.png)} /* note */",
        r"a{background:url(https://off-origin.test/*x*/.png)}",
        r#"a{content:"/* https://off-origin.test */"}"#,
        r"a{content:'https://off-origin.test' /* trailing */}",
        r#"a{background:URL("https://off-origin.test/a.png")}"#,
        // An escaped quote does not end the string, so this is all text.
        r#"a{content:"\" /* https://off-origin.test"}"#,
    ] {
        assert!(strip_css_comments(css).contains("https:"), "{css}");
    }
    // An unterminated comment removes the rest, as a browser would.
    assert_eq!(strip_css_comments("a{} /* open"), "a{} ");
}

#[test]
fn t6_the_shell_references_nothing_off_origin() {
    let texts = std::iter::once(("index.html", DOCUMENT.as_bytes()))
        .chain(ASSETS.iter().map(|(name, b)| (*name, *b)));
    for (name, bytes) in texts {
        let raw = String::from_utf8_lossy(bytes);
        let css = std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("css"));
        let text = if css {
            strip_css_comments(&raw)
        } else {
            raw.into_owned()
        };
        let lower = text.to_ascii_lowercase();
        assert!(
            !lower.contains("http:") && !lower.contains("https:"),
            "{text}"
        );
        for attribute in ["src=\"//", "href=\"//", "url(//"] {
            assert!(!lower.contains(attribute), "protocol-relative: {text}");
        }
    }
    assert!(
        !DOCUMENT.contains("http-equiv=\"refresh\""),
        "the shell renders in place; it no longer hands the visitor to /ui"
    );
    assert!(
        DOCUMENT.contains("<noscript>") && DOCUMENT.contains(r#"href="/ui/classic""#),
        "without JavaScript the document points to the classic page"
    );
    assert!(
        DOCUMENT.contains(r#"<script type="module" src="/ui/assets/shell."#),
        "the shell's module is loaded from the asset table"
    );
    // Every asset is named by the document, by a stylesheet it loads (the
    // fonts), or by a script it loads (an imported module, fetched copy), so
    // none ships unused.
    let referrers: Vec<String> = ASSETS
        .iter()
        .filter(|(n, _)| {
            std::path::Path::new(n).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("css") || ext.eq_ignore_ascii_case("js")
            })
        })
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .collect();
    for (name, _) in ASSETS {
        let reference = format!("/ui/assets/{name}");
        assert!(
            DOCUMENT.contains(&reference) || referrers.iter().any(|text| text.contains(&reference)),
            "{name} is linked"
        );
    }
    // Every asset the document names is in the table, so none answers 404.
    for reference in DOCUMENT.split("/ui/assets/").skip(1) {
        let name = reference
            .split(['"', '\'', ')', ' '])
            .next()
            .unwrap_or_default();
        assert!(
            ASSETS.iter().any(|(n, _)| *n == name),
            "{name} is not in the table"
        );
    }
}

#[test]
fn t6b_the_csp_allows_nothing_inline_or_foreign() {
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ] {
        assert!(csp().contains(directive), "{directive}");
    }
    assert!(!csp().contains("unsafe"), "{}", csp());
}

#[test]
fn t6c_an_asset_type_follows_its_extension() {
    for (file, want) in [
        ("a.1.css", "text/css; charset=utf-8"),
        ("a.1.js", "text/javascript; charset=utf-8"),
        ("a.1.woff2", "font/woff2"),
        ("a.1.svg", "image/svg+xml"),
        ("a.1.png", "image/png"),
        ("a.1.json", "application/json"),
        ("a.1.html", "application/octet-stream"),
        ("noext", "application/octet-stream"),
    ] {
        assert_eq!(content_type(file), want, "{file}");
    }
}

#[tokio::test]
async fn t7_the_tooltip_copy_is_a_hashed_json_asset() {
    let names: Vec<&str> = ASSETS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| {
            n.starts_with("tips.")
                && std::path::Path::new(n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    assert_eq!(names.len(), 1, "one tooltip copy asset: {names:?}");
    let name = names[0];
    let bytes = ASSETS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, b)| *b)
        .unwrap_or_default();
    let digest = crate::hashing::sha256_hex(bytes);
    assert_eq!(name, format!("tips.{}.json", &digest[..12]));
    let response = asset(Path(name.to_owned())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"application/json"[..])
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"nosniff"[..])
    );
}

/// Every "load N tools" the shipped Tools screen or tooltip copy says, as N.
fn load_counts(text: &str) -> Vec<u64> {
    text.match_indices("load ")
        .filter_map(|(i, m)| {
            let rest = &text[i + m.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let after = &rest[digits.len()..];
            if digits.is_empty() || !after.starts_with(" tools") {
                None
            } else {
                digits.parse().ok()
            }
        })
        .collect()
}

#[test]
fn t8_the_meta_tool_count_on_screen_is_the_gateways() {
    // The Tools screen and its tooltip say how many tools agents load up front.
    // That is the gateway's own meta-tool count, so a copied number fails here
    // the day a meta-tool is added or removed.
    let mut seen = 0;
    for (name, bytes) in ASSETS
        .iter()
        .filter(|(n, _)| n.starts_with("tools.") || n.starts_with("tips."))
    {
        for n in load_counts(&String::from_utf8_lossy(bytes)) {
            assert_eq!(
                n,
                crate::honest_task_tokens::README_META_TOOLS,
                "{name} says agents load {n} tools"
            );
            seen += 1;
        }
    }
    assert!(
        seen >= 2,
        "the screen and its copy both state the count ({seen} found)"
    );
}

#[test]
fn t8a_the_count_reader_finds_a_planted_number() {
    assert_eq!(load_counts("Agents load 12 tools and"), vec![12]);
    assert_eq!(load_counts("load the tools"), Vec::<u64>::new());
}

/// The text between the document's `<style id="frame">` and its `</style>`.
fn inlined_frame() -> &'static str {
    let open = r#"<style id="frame">"#;
    let start = DOCUMENT.find(open).map(|i| i + open.len());
    let text = start.and_then(|s| DOCUMENT[s..].find("</style>").map(|e| &DOCUMENT[s..s + e]));
    text.unwrap_or_default()
}

#[test]
fn t9_the_document_inlines_the_frame_css_byte_for_byte() {
    assert_eq!(
        DOCUMENT.matches("<style").count(),
        1,
        "one inline style, the frame"
    );
    assert!(
        inlined_frame() == FRAME_CSS,
        "the inlined frame is shell-src/frame.css: run scripts/dev/rehash_ui_assets.py"
    );
}

#[test]
fn t9a_the_rest_of_the_stylesheet_is_linked_at_the_end_of_the_body() {
    let (head, body) = DOCUMENT.split_once("<body>").unwrap_or_default();
    assert!(
        !head.contains(r#"rel="stylesheet""#),
        "nothing in the head blocks the first paint"
    );
    let link = body
        .find(r#"<link rel="stylesheet" href="/ui/assets/shell."#)
        .expect("the rest of the stylesheet is linked in the body");
    let tail = &body[link..];
    assert!(
        !tail.contains("<section") && !tail.contains("<div"),
        "the link comes after the page"
    );
}

#[test]
fn t9b_the_csp_allows_exactly_the_inlined_frame() {
    let frame = inlined_frame();
    assert!(!frame.is_empty(), "the document inlines a frame");
    let source = format!(
        "'sha256-{}'",
        crate::hashing::sha256_base64(frame.as_bytes())
    );
    let style = csp()
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("style-src "))
        .unwrap_or_default();
    assert_eq!(style, format!("style-src 'self' {source}"), "{}", csp());
    assert!(!csp().contains("unsafe-inline"), "{}", csp());
}

/// The fixture server checks its own policy against this file, so the
/// gateway's must match it; a stale golden fails here first.
#[test]
fn t9c_the_csp_golden_is_the_gateways_policy() {
    let golden = include_str!("csp.golden").trim_end();
    assert!(
        golden == csp(),
        "src/gateway/ui/csp.golden is stale; its one line must be:\n{}",
        csp()
    );
}
