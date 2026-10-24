// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: `serde-yaml` 0.9.34's behaviour on the cases where the
//! replacement parser is known or suspected to differ, recorded before the
//! swap. One golden, `behaviour.txt`, one row per case:
//! `case \t OK <reading>` or `case \t ERR <serde-yaml text>`.
//!
//! The destinations matter as much as the input. A repeated key is refused
//! in a struct and in the tree, but keeps the last value in any map,
//! including figment's `Dict` and a map field inside a struct. The rows name
//! the destination so that a later stage cannot match one and miss another.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use mcp_gateway::identity_grants::IdentityGrantFile;
use serde::{Deserialize, Serialize};

#[path = "mik_8425_yaml_baseline_behaviour/mig2.rs"]
mod mig2;

#[derive(Debug, Deserialize, Serialize)]
struct Field {
    a: u8,
}

#[derive(Debug, Deserialize, Serialize)]
struct Holder {
    m: BTreeMap<String, u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Shape {
    Unit,
    Newtype(String),
    Pair { x: u8, y: u8 },
}

fn ok_json<T: Serialize, E: std::fmt::Display>(result: Result<T, E>) -> String {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => format!("OK {json}"),
            Err(error) => format!("OK JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// A tree reading as its structure (kinds, tags, key types), which JSON
/// cannot carry: a tagged node and a one-key map serialize alike there.
fn ok_tree(result: Result<yaml::Value, yaml::Error>) -> String {
    match result {
        Ok(value) => format!("OK {}", golden::yaml_structure(&value)),
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// A tree scalar by kind, so `.inf` and `.nan` do not both read as JSON null.
fn scalar_kind(value: &yaml::Value) -> String {
    match value {
        yaml::Value::Null => "null".to_owned(),
        yaml::Value::Bool(b) => format!("bool:{b}"),
        yaml::Value::Number(n) => n
            .as_i64()
            .map(|i| format!("int:{i}"))
            .or_else(|| n.as_u64().map(|u| format!("uint:{u}")))
            .unwrap_or_else(|| format!("float:{}", n.as_f64().unwrap_or(f64::NAN))),
        yaml::Value::String(s) => format!("str:{s:?}"),
        other => format!("other:{}", golden::yaml_structure(other)),
    }
}

fn row(out: &mut String, case: &str, outcome: &str) {
    out.push_str(case);
    out.push('\t');
    out.push_str(outcome);
    out.push('\n');
}

fn duplicates(out: &mut String) {
    let top = "a: 1\na: 2\n";
    row(out, "dup/struct", &ok_json(yaml::from_str::<Field>(top)));
    row(
        out,
        "dup/map",
        &ok_json(yaml::from_str::<BTreeMap<String, u8>>(top)),
    );
    row(
        out,
        "dup/tree",
        &ok_tree(yaml::from_str::<yaml::Value>(top)),
    );
    row(out, "dup/dict", &ok_json(yaml::from_str_loose(top)));
    let nested = "m:\n  a: 1\n  a: 2\n";
    row(
        out,
        "dup/map-in-struct",
        &ok_json(yaml::from_str::<Holder>(nested)),
    );
    let deep = "x:\n  a: 1\n  a: 2\n";
    row(out, "dup/nested-dict", &ok_json(yaml::from_str_loose(deep)));
}

fn merge_keys(out: &mut String) {
    let merge = "b: &b {x: 1}\nm:\n  <<: *b\n  y: 2\n";
    row(
        out,
        "merge/tree",
        &ok_tree(yaml::from_str::<yaml::Value>(merge)),
    );
    row(out, "merge/dict", &ok_json(yaml::from_str_loose(merge)));
    let tagged = "m:\n  !!merge <<: {x: 1}\n";
    row(
        out,
        "merge/tagged-tree",
        &ok_tree(yaml::from_str::<yaml::Value>(tagged)),
    );
}

const SCALARS: &[&str] = &[
    "yes", "no", "on", "off", "y", "n", "true", "True", "TRUE", "false", "0755", "0o755", "0x1F",
    "1_000", "1e3", ".inf", "-.inf", ".nan", "~", "null", "Null", "", "12:30", "'yes'", "\"0755\"",
];

fn scalars(out: &mut String) {
    for s in SCALARS {
        let doc = format!("v: {s}\n");
        let tree = yaml::from_str::<BTreeMap<String, yaml::Value>>(&doc)
            .map(|m| m.get("v").map_or_else(|| "absent".to_owned(), scalar_kind));
        let tree = tree.map_or_else(
            |e| format!("ERR {}", golden::one_line(&e.to_string())),
            |k| format!("OK {k}"),
        );
        row(out, &format!("scalar/tree {s:?}"), &tree);
        let text = yaml::from_str::<BTreeMap<String, String>>(&doc);
        row(out, &format!("scalar/string {s:?}"), &ok_json(text));
        let flag = yaml::from_str::<BTreeMap<String, bool>>(&doc);
        row(out, &format!("scalar/bool {s:?}"), &ok_json(flag));
    }
}

fn documents(out: &mut String) {
    for (case, doc) in [
        ("doc/empty", ""),
        ("doc/explicit-start", "---\na: 1\n"),
        ("doc/two", "a: 1\n---\nb: 2\n"),
    ] {
        row(out, case, &ok_tree(yaml::from_str::<yaml::Value>(doc)));
    }
    for (case, doc) in [
        ("stream/two", "a: 1\n---\nb: 2\n"),
        ("stream/empty-middle", "a: 1\n---\n---\nb: 2\n"),
        ("stream/malformed-later", "a: 1\n---\nb: [1, 2\n"),
    ] {
        // Stop at the first refusal, and never read more than 16 documents:
        // after a malformed document the stream may keep yielding errors.
        let mut readings = Vec::new();
        for document in yaml::documents(doc).take(16) {
            let reading = ok_tree(document);
            let refused = reading.starts_with("ERR");
            readings.push(reading);
            if refused {
                break;
            }
        }
        row(
            out,
            case,
            &format!("{} docs: {}", readings.len(), readings.join(" ; ")),
        );
    }
}

/// Refusal text, or the digest of the expanded tree's structure, so a
/// replacement that parses but expands differently cannot match.
fn parsed_or_refused(doc: &str) -> String {
    yaml::from_str::<yaml::Value>(doc).map_or_else(
        |e| format!("ERR {}", golden::one_line(&e.to_string())),
        |value| {
            format!(
                "OK {}",
                golden::digest(golden::yaml_structure(&value).as_bytes())
            )
        },
    )
}

fn limits(out: &mut String) {
    for depth in [64usize, 127, 128, 129] {
        let doc = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        row(
            out,
            &format!("limit/depth {depth}"),
            &parsed_or_refused(&doc),
        );
    }
    // Fan-out 10 per level over a 10-item base, so level n alone expands to
    // 10^(n+1) nodes and the document holds every level. serde-yaml 0.9.34
    // bounds expansion: it refuses with "repetition limit exceeded" from
    // level 4 (about 10^5 nodes) on, and parses levels 2 and 3. That refusal
    // point is the baseline the replacement parser's budget may not loosen
    // (MIK-8425 design, Resource limits).
    for levels in [2usize, 3, 4, 5, 6] {
        let mut doc = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..=levels {
            let prev = format!("*l{}", level - 1);
            let items = [prev.as_str(); 10].join(", ");
            let _ = writeln!(doc, "l{level}: &l{level} [{items}]");
        }
        row(
            out,
            &format!("limit/alias-fanout-10 levels {levels}"),
            &parsed_or_refused(&doc),
        );
    }
}

/// A one-grant file with `agent` set to `agent`, in the shape the 4.0
/// grants reader accepts.
fn grant_file(agent: &str) -> String {
    format!(
        "schema_version: identity_grants.v1\ngrants:\n- grant_id: g1\n  subject:\n    \
         authority: api_key\n    subject: alice\n  agent: {agent}\n  capability: \
         calendar_read\n  scope: read\n  owner:\n    authority: api_key\n    subject: alice\n  \
         provenance: mcp-gateway identity grants grant\n  reason: r\n"
    )
}

fn enums(out: &mut String) {
    for (case, agent) in [
        ("grant/any", "any"),
        (
            "grant/tag-qualified",
            "!exact {source: mtls, id: spiffe://x}",
        ),
        ("grant/tag-bare-3x", "!exact runner"),
        (
            "grant/map-qualified",
            "{exact: {source: mtls, id: spiffe://x}}",
        ),
        ("grant/map-bare", "{exact: runner}"),
    ] {
        let parsed = yaml::from_str::<IdentityGrantFile>(&grant_file(agent));
        row(out, case, &ok_json(parsed));
    }
    for (case, doc) in [
        ("enum/unit", "unit"),
        ("enum/newtype-tag", "!newtype hi"),
        ("enum/newtype-map", "{newtype: hi}"),
        ("enum/struct-tag", "!pair {x: 1, y: 2}"),
        ("enum/struct-map", "{pair: {x: 1, y: 2}}"),
    ] {
        row(out, case, &ok_json(yaml::from_str::<Shape>(doc)));
    }
}

const AMBIGUOUS: &[&str] = &[
    "yes", "no", "on", "off", "y", "true", "0755", "0x1F", "1e3", "null", "~", ".inf", "", "12:30",
    "- x", "a: b", "#c",
];

fn writes(out: &mut String) {
    let shapes = vec![
        Shape::Unit,
        Shape::Newtype("hi".into()),
        Shape::Pair { x: 1, y: 2 },
    ];
    let written = yaml::to_string(&shapes).expect("shapes serialise");
    row(out, "write/enums", &golden::one_line(&written));
    let ambiguous: BTreeMap<String, String> = AMBIGUOUS
        .iter()
        .enumerate()
        .map(|(i, s)| (format!("k{i:02}"), (*s).to_owned()))
        .collect();
    let written = yaml::to_string(&ambiguous).expect("strings serialise");
    row(out, "write/ambiguous-strings", &golden::one_line(&written));
    let back = yaml::from_str::<BTreeMap<String, String>>(&written);
    let equal = back.as_ref().is_ok_and(|b| *b == ambiguous);
    row(
        out,
        "write/ambiguous-strings-read-back-equal",
        &equal.to_string(),
    );
}

fn report() -> String {
    let mut out = String::new();
    duplicates(&mut out);
    merge_keys(&mut out);
    scalars(&mut out);
    documents(&mut out);
    limits(&mut out);
    enums(&mut out);
    writes(&mut out);
    mig2::rows(&mut out);
    out
}

/// `serde-yaml` 0.9.34's outcome on every recorded case is unchanged.
#[test]
fn yaml_behaviour_matches_the_recording() {
    golden::assert_golden("behaviour.txt", &report());
}

/// The structural form keeps what JSON loses: a tagged node is not a one-key
/// map, and a numeric key is not a string key. Without this, the tree
/// digests could not tell those readings apart.
#[test]
fn the_structural_form_separates_tags_from_maps_and_key_types() {
    let structure =
        |doc: &str| golden::yaml_structure(&yaml::from_str::<yaml::Value>(doc).expect("parses"));
    assert_ne!(structure("a: !exact x\n"), structure("a: {'!exact': x}\n"));
    assert_ne!(structure("1: x\n"), structure("'1': x\n"));
    assert_ne!(structure("a: 1\n"), structure("a: '1'\n"));
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/behaviour.txt; run with --ignored --nocapture"]
fn record_behaviour_golden() {
    print!(
        "----- BEGIN behaviour.txt -----\n{}----- END behaviour.txt -----\n",
        report()
    );
}
