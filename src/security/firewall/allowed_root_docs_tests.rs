// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Docs rows for per-tool allowed folders (D1, D2): the upgrading fragment
//! names the setting, the reason, the grammar, the section 1 example and
//! every limit; the changelog fragment exists. Batch 6.

use super::config::EXAMPLE;

const UPGRADING: &str = "upgrading.d/8939.md";
const CHANGELOG: &str = "changelog.d/8939.added.md";

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Every limit of design sections 9 and 14, by a phrase the fragment says.
const LIMITS: [&str; 10] = [
    "whole value is a path",
    "sees its own filesystem",
    "swapped between the gateway's check and the backend's open",
    "normalised absolute native paths",
    "Remote backends (Http, WebSocket, A2a) are refused",
    "A root rule refuses capability calls; confine CLI capabilities with `capabilities.files`.",
    "Unicode-equivalent spelling",
    "more than 10,000 entries",
    "really named with `~1`",
    "case-folding mount",
];

/// D1: the setting, why it exists, the grammar with `?`, the example and
/// every limit, plus the two compatibility notes.
#[test]
fn d1_upgrading_fragment_states_the_setting_and_its_limits() {
    let text = read(UPGRADING);
    for needed in [
        "allowed_roots",
        "path_args",
        "`name?`",
        "`name[]`",
        "no schema marks a path",
    ] {
        assert!(text.contains(needed), "{UPGRADING} lacks {needed:?}");
    }
    for limit in LIMITS {
        assert!(
            text.contains(limit),
            "{UPGRADING} lacks the limit {limit:?}"
        );
    }
    let rules = &EXAMPLE[EXAMPLE
        .find("      - match")
        .expect("the example has rules")..];
    assert!(
        text.contains(rules.trim_end()),
        "{UPGRADING} lacks the section 1 example"
    );
    assert!(
        text.contains("#[non_exhaustive]"),
        "{UPGRADING}: the ScanType note"
    );
    assert!(
        text.contains("`reason`"),
        "{UPGRADING}: the audit-format note"
    );
}

/// D2: both fragments exist; the upgrading one has the front matter and the
/// startup line the fragment check reads.
#[test]
fn d2_fragments_exist_with_their_front_matter() {
    assert!(!read(CHANGELOG).trim().is_empty(), "{CHANGELOG} is empty");
    let text = read(UPGRADING);
    assert!(
        text.starts_with("---\nchange: "),
        "{UPGRADING}: front matter"
    );
    assert!(text.contains("\naction: "), "{UPGRADING}: action");
    assert!(text.contains("**Startup:**"), "{UPGRADING}: startup line");
}
