// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every content type a UI API answer is sent with, and every body built by
//! hand, classified for the api command, which streams exactly the download
//! types and buffers everything else. A new type, a type set through a
//! constant, a helper or a typed header, or a new hand-built body fails until
//! it is classified here (and, if it is a download, designed for in the api
//! command). Not read, by design: a response built outside src/gateway/ui,
//! and a handler returning raw bytes (axum's implicit octet-stream).

use std::collections::BTreeMap;

/// How the api command reads an answer carrying this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Streamed: the event stream and the activity export.
    Streamed,
    /// Read whole, the default path.
    Buffered,
    /// Set on a request the gateway sends itself, not on an answer.
    NotAnAnswer,
}

/// Every content-type value and hand-built body in the UI API's production
/// code: file, value as written, class, and how many times it occurs.
const SITES: &[(&str, &str, Class, usize)] = &[
    (
        "src/gateway/ui/activity/mod.rs",
        "\"application/x-ndjson\"",
        Class::Streamed,
        1,
    ),
    (
        "src/gateway/ui/activity/mod.rs",
        "\"text/csv; charset=utf-8\"",
        Class::Streamed,
        1,
    ),
    (
        "src/gateway/ui/capabilities.rs",
        "\"text/yaml; charset=utf-8\"",
        Class::Buffered,
        2,
    ),
    (
        "src/gateway/ui/stream/mod.rs",
        "\"text/event-stream\"",
        Class::Streamed,
        1,
    ),
    (
        "src/gateway/ui/stream/mod.rs",
        "Body::from_stream",
        Class::Streamed,
        1,
    ),
    (
        "src/gateway/ui/tool_call.rs",
        "json_type.clone",
        Class::NotAnAnswer,
        1,
    ),
    (
        "src/gateway/ui/tool_call.rs",
        "Body::from",
        Class::NotAnAnswer,
        1,
    ),
];

/// Served outside /ui/api (the shell's assets and the dashboard page), which
/// the api command refuses to reach.
const OUTSIDE_UI_API: [&str; 2] = ["src/gateway/ui/shell.rs", "src/gateway/ui/dashboard.rs"];

fn test_only(name: &str) -> bool {
    name == "tests"
        || name.ends_with("_tests")
        || name.ends_with("_tests.rs")
        || name.ends_with("_fixture.rs")
        || name.ends_with("_test_support.rs")
        || name.starts_with("test_")
}

/// The UI API's production sources, as (crate-relative path, text with
/// test-only items blanked).
fn sources() -> Vec<(String, String)> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read a source directory") {
            let path = entry.expect("a directory entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if test_only(name) {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path.strip_prefix(root).expect("under the crate root");
                let rel: Vec<_> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect();
                let rel = rel.join("/");
                if !OUTSIDE_UI_API.contains(&rel.as_str()) {
                    let text = std::fs::read_to_string(&path).expect("read a source file");
                    out.push((rel, crate::test_source_text::production_text(&text)));
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(root, &root.join("src/gateway/ui"), &mut out);
    out
}

/// Every content type and hand-built body found, keyed `file value`, counted,
/// equals [`SITES`].
#[test]
fn every_ui_answer_type_is_classified() {
    let value = regex::Regex::new(r#"\bCONTENT_TYPE\s*,\s*("[^"]*"|[A-Za-z_][A-Za-z0-9_.:]*)"#)
        .expect("pattern");
    let body = regex::Regex::new(r"\bBody::(from_stream|from|new)\s*\(").expect("pattern");
    let sources = sources();
    assert!(
        sources.len() >= 50,
        "premise: the UI API sources are read, saw {}",
        sources.len()
    );
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for (file, code) in &sources {
        for c in value.captures_iter(code) {
            *found.entry(format!("{file} {}", c[1].trim())).or_default() += 1;
        }
        for c in body.captures_iter(code) {
            *found.entry(format!("{file} Body::{}", &c[1])).or_default() += 1;
        }
    }
    let mut table: BTreeMap<String, usize> = BTreeMap::new();
    for &(file, written, class, count) in SITES {
        assert!(
            class == Class::NotAnAnswer
                || written.starts_with('"')
                || written.starts_with("Body::"),
            "{file}: an answer's type must be a literal: {written}"
        );
        *table.entry(format!("{file} {written}")).or_default() += count;
    }
    assert!(
        found.contains_key("src/gateway/ui/activity/mod.rs \"application/x-ndjson\""),
        "premise: {found:?}"
    );
    assert_eq!(
        found, table,
        "UI API answer types and the classification disagree"
    );
}

/// No content type is set through a spelling the scan above cannot read.
#[test]
fn no_ui_answer_type_hides_from_the_scan() {
    let hidden =
        regex::Regex::new(r"\bmime::|\bTypedHeader\b|\bheaders::ContentType\b").expect("pattern");
    let found: Vec<String> = sources()
        .iter()
        .flat_map(|(file, code)| {
            hidden
                .find_iter(code)
                .map(move |m| format!("{file}: {}", m.as_str()))
        })
        .collect();
    assert!(
        found.is_empty(),
        "content types set out of the scan's sight: {found:?}"
    );
}
