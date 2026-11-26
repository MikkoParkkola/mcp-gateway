// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shell's scripts, gzipped as the gateway serves them, stay under the ceiling.
//!
//! The bytes are the ones compiled into `ASSETS`.

use std::io::Write as _;

/// 200 KiB, compressed, every script included.
const CORE_JS_BUDGET: usize = 200 * 1024;

/// Gzip level `CompressionLayer::new()` uses.
///
/// `new` returns `Self::default()` (tower-http 0.7.1 `src/compression/layer.rs:38`).
/// Gzip passes that quality through (`src/compression/body.rs:299`); it does not
/// pick a level of its own. `compression-codecs` maps `Level::Default` to
/// `flate2::Compression::default()` (`compression-codecs` 0.4.42
/// `src/flate/params.rs:36`), and that default is `Compression(6)` (flate2 1.1.10
/// `src/lib.rs:266`).
const GZIP_LEVEL: u32 = 6;

/// Stems of every script asset today.
///
/// A content hash changes on every edit of that file, so the row names the
/// stem: a script that joins the table, or one left out of the sum, fails this
/// equality. Order in the asset table is not part of the budget; the comparison
/// sorts both sides.
const CORE_JS_STEMS: &[&str] = &[
    "activity",
    "activity-list",
    "chart",
    "gateway",
    "overview",
    "servers",
    "shell",
    "tools",
    "tooltip",
];

#[test]
fn core_js_stays_under_200_kb_compressed() {
    let mut total = 0usize;
    let mut stems = Vec::new();
    for &(name, bytes) in super::ASSETS {
        if !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
        {
            continue;
        }
        // Every script is counted. A lazy chunk would be named here and skipped.
        let packed = gzip(bytes);
        let size = packed.len();
        println!("{name} {size}");
        total += size;
        stems.push(js_stem(name));
    }
    println!("total {total} budget {CORE_JS_BUDGET}");
    assert!(
        total < CORE_JS_BUDGET,
        "compressed core js is {total} bytes, budget is {CORE_JS_BUDGET}"
    );
    stems.sort_unstable();
    let mut expected: Vec<&str> = CORE_JS_STEMS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        stems, expected,
        "core js stems changed; a script joined or left the sum"
    );
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(GZIP_LEVEL));
    encoder
        .write_all(bytes)
        .expect("the encoder accepts the asset");
    encoder.finish().expect("the encoder finishes")
}

/// The name without the content hash that precedes `.js`.
fn js_stem(name: &str) -> &str {
    let without_ext = name.rsplit_once('.').map_or(name, |(rest, _ext)| rest);
    let (stem, hash) = without_ext.rsplit_once('.').unwrap_or((without_ext, ""));
    assert!(
        hash.len() == 12 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit),
        "{name} is not a content-hashed script name"
    );
    stem
}
