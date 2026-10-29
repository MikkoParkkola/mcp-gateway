// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `production_text`: each `#[cfg(test)]` item shape is blanked by its own
//! extent, and nothing after it is lost.

use crate::test_source_text::production_text;

/// `(source, kept, blanked)`: after blanking, every `kept` text remains and
/// no `blanked` text does.
const CASES: &[(&str, &[&str], &[&str])] = &[
    (
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn product() {}\n",
        &["fn product()"],
        &["fn t()"],
    ),
    (
        "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x;\nfn product() {}\n",
        &["fn product()"],
        &["mod x"],
    ),
    (
        "struct S {\n    #[cfg(test)]\n    probe: u8,\n    live: u8,\n}\nimpl S {}\n",
        &["live: u8", "impl S"],
        &["probe"],
    ),
    (
        "struct S {\n    live: u8,\n    #[cfg(test)]\n    probe: u8\n}\nimpl S {}\n",
        &["live: u8", "}\nimpl S"],
        &["probe"],
    ),
    (
        "enum E {\n    #[cfg(test)]\n    Probe,\n    Live,\n}\n",
        &["Live"],
        &["Probe"],
    ),
    (
        "fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 => { probe() }\n        _ => live(),\n    }\n}\n",
        &["_ => live()"],
        &["probe"],
    ),
    (
        "#[cfg(test)]\nconst TABLE: [u8; 4] = [0; 4];\nfn product() {}\n",
        &["fn product()"],
        &["TABLE"],
    ),
    (
        "#[cfg(test)]\nconst S: Shape = Shape { a: 1 };\nfn product() {}\n",
        &["fn product()"],
        &["Shape {"],
    ),
    (
        "#[cfg(test)]\nuse crate::{probe, other};\nfn product() {}\n",
        &["fn product()"],
        &["probe"],
    ),
    (
        "fn now(&self) -> u64 {\n    #[cfg(test)]\n    if let Some(t) = probe() {\n        return t;\n    } else {\n        idle();\n    }\n    self.live()\n}\n",
        &["self.live()"],
        &["probe", "idle"],
    ),
    (
        "fn now(&self) -> u8 {\n    #[cfg(test)]\n    { probe() }.touch()?;\n    self.live()\n}\n",
        &["self.live()"],
        &["probe", "touch"],
    ),
    (
        "// A comment naming #[cfg(test)] marks nothing.\nfn product() {}\n",
        &["fn product()"],
        &[],
    ),
    (
        "const NOTE: &str = \"#[cfg(test)] in a string\";\nfn product() {}\n",
        &["fn product()", "in a string"],
        &[],
    ),
    (
        "#[cfg(test)]\nfn probe() { let s = \"}\"; }\nfn product() {}\n",
        &["fn product()"],
        &["probe"],
    ),
];

#[test]
fn each_test_item_shape_is_blanked_by_its_own_extent() {
    for (source, kept, blanked) in CASES {
        let out = production_text(source);
        assert_eq!(out.len(), source.len(), "positions kept: {source}");
        assert_eq!(
            out.lines().count(),
            source.lines().count(),
            "lines kept: {source}"
        );
        for k in *kept {
            assert!(out.contains(k), "{k:?} lost from {source:?}: {out:?}");
        }
        for b in *blanked {
            assert!(!out.contains(b), "{b:?} kept in {source:?}: {out:?}");
        }
    }
}

/// An item whose block never closes stays (a scan sees more, never less),
/// and an earlier, well-formed test item is still blanked.
#[test]
fn an_unclosed_item_stays_and_earlier_items_are_still_blanked() {
    let source = "#[cfg(test)]\nfn probe() {}\nfn product() {}\n#[cfg(test)]\nfn broken() {\n";
    let out = production_text(source);
    assert!(!out.contains("probe"));
    assert!(out.contains("fn product()"));
    assert!(out.contains("fn broken()"));
}

/// The case a review named: a test-only last field of `LiveConfig` must not
/// take the `impl LiveConfig` after it.
#[test]
fn a_test_only_field_keeps_the_impl_after_it() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config_reload/mod.rs"),
    )
    .unwrap();
    let out = production_text(&source);
    assert!(out.contains("impl LiveConfig {"));
    assert!(!out.contains("publishes: std::sync::atomic::AtomicU64"));
}
