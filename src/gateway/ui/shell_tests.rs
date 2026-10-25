// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8870 T5/T6: the asset table's names are honest content hashes, and
//! nothing the shell serves reaches outside this origin.

use super::*;

#[test]
fn t5_every_asset_name_carries_its_content_hash() {
    assert!(
        !ASSETS.is_empty(),
        "the shell ships at least its stylesheet"
    );
    for (name, bytes) in ASSETS {
        let digest = crate::hashing::sha256_hex(bytes);
        let hash = name.split('.').nth(1).unwrap_or_default();
        assert_eq!(hash, &digest[..12], "{name}: rename it after editing");
    }
}

#[test]
fn t6_the_shell_references_nothing_off_origin() {
    let texts = std::iter::once(DOCUMENT.as_bytes()).chain(ASSETS.iter().map(|(_, b)| *b));
    for text in texts {
        let text = String::from_utf8_lossy(text);
        assert!(
            !text.contains("http:") && !text.contains("https:"),
            "{text}"
        );
    }
    assert!(
        DOCUMENT.contains(r#"<meta http-equiv="refresh" content="0; url=/ui">"#),
        "until UI1 the document hands the visitor to /ui"
    );
    for (name, _) in ASSETS {
        assert!(
            DOCUMENT.contains(&format!("/ui/assets/{name}")),
            "{name} is linked"
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
