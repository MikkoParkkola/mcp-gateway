// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T5/T6: the asset table's names are honest content hashes, and nothing
//! the shell serves reaches outside this origin.

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

#[test]
fn t6_the_shell_references_nothing_off_origin() {
    let texts = std::iter::once(DOCUMENT.as_bytes()).chain(ASSETS.iter().map(|(_, b)| *b));
    for text in texts {
        let text = String::from_utf8_lossy(text);
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
    for (name, _) in ASSETS {
        assert!(
            DOCUMENT.contains(&format!("/ui/assets/{name}")),
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
        assert!(CSP.contains(directive), "{directive}");
    }
    assert!(!CSP.contains("unsafe"), "{CSP}");
}

#[test]
fn t6c_an_asset_type_follows_its_extension() {
    for (file, want) in [
        ("a.1.css", "text/css; charset=utf-8"),
        ("a.1.js", "text/javascript; charset=utf-8"),
        ("a.1.woff2", "font/woff2"),
        ("a.1.svg", "image/svg+xml"),
        ("a.1.png", "image/png"),
        ("a.1.html", "application/octet-stream"),
        ("noext", "application/octet-stream"),
    ] {
        assert_eq!(content_type(file), want, "{file}");
    }
}
