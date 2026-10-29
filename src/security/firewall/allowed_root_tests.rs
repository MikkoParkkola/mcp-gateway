// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for per-tool allowed folders (test plan r2-final). Batch 1: the
//! string precheck, config load, the suggester and the constants.

use super::*;
use serde_json::json;

#[path = "allowed_root_config_tests.rs"]
mod config;
#[path = "allowed_root_docs_tests.rs"]
mod docs;
#[path = "allowed_root_entry_tests.rs"]
mod entry;
#[path = "allowed_root_locality_tests.rs"]
mod locality;
#[path = "allowed_root_rules_tests.rs"]
mod rules;
#[path = "allowed_root_runtime_tests.rs"]
mod runtime;
#[path = "allowed_root_seam_tests.rs"]
mod seam;
#[path = "allowed_root_spelling_tests.rs"]
mod spelling;
#[path = "allowed_root_fs_tests.rs"]
mod tree;
#[path = "allowed_root_warn_tests.rs"]
mod warn;
#[cfg(windows)]
#[path = "allowed_root_windows_tests.rs"]
mod windows;

/// One precheck case with its expected outcome on each OS family.
struct Shape {
    row: &'static str,
    value: &'static str,
    unix: Option<RootReason>,
    windows: Option<RootReason>,
}

const NA: Option<RootReason> = Some(RootReason::NotAbsolute);
const NN: Option<RootReason> = Some(RootReason::NotNormalised);

const SHAPES: &[Shape] = &[
    Shape {
        row: "W1",
        value: r"C:\safe\x",
        unix: NA,
        windows: None,
    },
    Shape {
        row: "W2",
        value: "C:/safe/x",
        unix: NA,
        windows: None,
    },
    Shape {
        row: "W3",
        value: "C:foo",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "W4",
        value: r"\outside",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "W5a",
        value: r"\\server\share\x",
        unix: NA,
        windows: None,
    },
    Shape {
        row: "W6",
        value: r"\\?\C:\safe\x",
        unix: NA,
        windows: None,
    },
    Shape {
        row: "W7",
        value: r"\\?\C:\safe\..\outside",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W8",
        value: r"C:\safe\.\x",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W9",
        value: "/safe/x",
        unix: None,
        windows: NA,
    },
    Shape {
        row: "W13",
        value: r"\\.\C:\outside",
        unix: NA,
        windows: Some(RootReason::DevicePath),
    },
    Shape {
        row: "W14",
        value: r"\\?\UNC\server\share\x",
        unix: NA,
        windows: None,
    },
    Shape {
        row: "W15",
        value: "C:/safe/../outside",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W16",
        value: r"C:\safe/../outside",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W17",
        value: r"/safe/a\..\b",
        unix: None,
        windows: NA,
    },
    Shape {
        row: "R9",
        value: "relative/name",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R10",
        value: "~/x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R11",
        value: "$HOME/x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R11a",
        value: "${HOME}/x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R11b",
        value: r"%USERPROFILE%\x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R12",
        value: "file:///root/x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R12b",
        value: "file:/x",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R12c",
        value: "http://x/y",
        unix: NA,
        windows: NA,
    },
    Shape {
        row: "R13",
        value: "/root/a/../b",
        unix: NN,
        windows: NA,
    },
    Shape {
        row: "R13b",
        value: "/root/./a",
        unix: NN,
        windows: NA,
    },
    Shape {
        row: "R15",
        value: "/root/a\0b",
        unix: NN,
        windows: NA,
    },
    // W18 (lead ruling): Windows strips a trailing dot or space and expands
    // an 8.3 short name, so each aliases a name the gateway did not check
    // there. On Unix each is a distinct legal name. A file really named with
    // `~1` is refused on Windows: a stated false refusal.
    Shape {
        row: "W18a",
        value: r"C:\safe\secret.",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W18b",
        value: r"C:\safe\secret ",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W18c",
        value: r"C:\PROGRA~1\x",
        unix: NA,
        windows: NN,
    },
    Shape {
        row: "W18d",
        value: "/safe/secret.",
        unix: None,
        windows: NA,
    },
    Shape {
        row: "W18e",
        value: "/safe/secret ",
        unix: None,
        windows: NA,
    },
    Shape {
        row: "W18f",
        value: "/safe/PROGRA~1/x",
        unix: None,
        windows: NA,
    },
];

/// W1-W17 and R9-R15: the string precheck, one table on every OS with each
/// row's expectation for this OS. A shape refused only on Windows shows in
/// its own row rather than behind a skip.
#[test]
fn w_rows_precheck_each_path_shape_on_this_os() {
    let mut wrong = Vec::new();
    for shape in SHAPES {
        let want = if cfg!(windows) {
            shape.windows
        } else {
            shape.unix
        };
        let got = precheck(shape.value);
        if got != want {
            wrong.push(format!(
                "{}: {:?} gave {got:?}, want {want:?}",
                shape.row, shape.value
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "precheck rows wrong:\n{}",
        wrong.join("\n")
    );
}

fn load_error(yaml: &str) -> Option<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    crate::config::Config::load(Some(&path))
        .err()
        .map(|e| e.to_string())
}

fn with_rule(rule: &str) -> String {
    format!("security:\n  firewall:\n    enabled: true\n    rules:\n      - {rule}\n")
}

fn assert_refused(rule: &str, path: &str, reason: &str) {
    let yaml = with_rule(rule);
    let err = load_error(&yaml).unwrap_or_else(|| panic!("must not load: {yaml}"));
    assert!(err.contains(path), "names {path}: {err}");
    assert!(err.contains(reason), "says {reason}: {err}");
}

const ROOT: &str = "match: \"read_text_file\", action: block";

/// L1: allowed_roots without path_args, and the reverse.
#[test]
fn l1_roots_and_path_args_come_together() {
    assert_refused(
        &format!("{{{ROOT}, allowed_roots: [\"/srv\"]}}"),
        "security.firewall.rules[0].path_args",
        "required with allowed_roots",
    );
    assert_refused(
        &format!("{{{ROOT}, path_args: [\"path\"]}}"),
        "security.firewall.rules[0].allowed_roots",
        "required with path_args",
    );
}

/// L2: empty lists are refused, as the other scoped keys are.
#[test]
fn l2_empty_lists_are_refused() {
    assert_refused(
        &format!("{{{ROOT}, allowed_roots: [], path_args: [\"path\"]}}"),
        "security.firewall.rules[0].allowed_roots",
        "must not be empty",
    );
    assert_refused(
        &format!("{{{ROOT}, allowed_roots: [\"/srv\"], path_args: []}}"),
        "security.firewall.rules[0].path_args",
        "must not be empty",
    );
}

/// L3, L3b: a root must be absolute after `~` expansion; `~user` is refused.
#[test]
fn l3_relative_and_tilde_user_roots_are_refused() {
    assert_refused(
        &format!("{{{ROOT}, allowed_roots: [\"srv/data\"], path_args: [\"path\"]}}"),
        "security.firewall.rules[0].allowed_roots[0]",
        "must be absolute",
    );
    assert_refused(
        &format!("{{{ROOT}, allowed_roots: [\"~bob/data\"], path_args: [\"path\"]}}"),
        "security.firewall.rules[0].allowed_roots[0]",
        "must be absolute",
    );
}

/// L4: entries outside the path_args grammar are refused, naming the entry.
#[test]
fn l4_bad_path_arg_entries_are_refused() {
    for bad in ["a..b", "[]", "name??", "name?[]"] {
        assert_refused(
            &format!("{{{ROOT}, allowed_roots: [\"/srv\"], path_args: [\"{bad}\"]}}"),
            "security.firewall.rules[0].path_args[0]",
            "not a path argument",
        );
    }
}

/// L5: a load error names the key path and never the value.
#[test]
fn l5_load_errors_never_print_the_value() {
    let yaml = with_rule(&format!(
        "{{{ROOT}, allowed_roots: [\"relative-SENTINEL-8939\"], path_args: [\"path\"]}}"
    ));
    let err = load_error(&yaml).expect("must not load");
    assert!(!err.contains("SENTINEL-8939"), "value leaked: {err}");
}

/// L6: path_outside_root and root_refused are output-only, and no rule's
/// scan may list either (root_refused: lead D8, agreed by consol4).
#[test]
fn l6_path_outside_root_is_not_listable_in_scan() {
    for output_only in ["path_outside_root", "root_refused"] {
        assert_refused(
            &format!("{{match: \"*\", action: block, scan: [{output_only}]}}"),
            "security.firewall.rules[0].scan",
            "output-only",
        );
    }
}

/// L7, L8: a root rule's scan must be empty, and its action warn or block.
#[test]
fn l7_l8_root_rule_scan_and_action_constraints() {
    assert_refused(
        &format!(
            "{{{ROOT}, scan: [credentials], allowed_roots: [\"/srv\"], path_args: [\"path\"]}}"
        ),
        "security.firewall.rules[0].scan",
        "a root rule decides only its own findings",
    );
    assert_refused(
        "{match: \"read_text_file\", action: allow, allowed_roots: [\"/srv\"], path_args: [\"path\"]}",
        "security.firewall.rules[0].action",
        "warn or block",
    );
}

/// L4b: `paths[]?` compiles to an optional array argument.
#[test]
fn l4b_optional_array_compiles() {
    assert_eq!(
        compile_path_arg("paths[]?"),
        Ok(PathArg {
            segments: vec!["paths".into()],
            array: true,
            optional: true
        })
    );
    assert_eq!(
        compile_path_arg("a.b"),
        Ok(PathArg {
            segments: vec!["a".into(), "b".into()],
            array: false,
            optional: false
        })
    );
}

fn schema(props: serde_json::Value, required: &[&str]) -> serde_json::Value {
    json!({"type": "object", "properties": props, "required": required})
}

/// The reference filesystem server's tool schemas (src/filesystem/server.ts at
/// modelcontextprotocol/servers f438a620a), reduced to their properties.
fn reference_schemas() -> Vec<(&'static str, serde_json::Value)> {
    let s = json!({"type": "string"});
    let arr = json!({"type": "array", "items": {"type": "string"}});
    let path_only = || schema(json!({"path": s}), &["path"]);
    vec![
        ("read_file", path_only()),
        (
            "read_text_file",
            schema(
                json!({"path": s, "head": {"type": "number"}, "tail": {"type": "number"}}),
                &["path"],
            ),
        ),
        ("read_media_file", path_only()),
        (
            "read_multiple_files",
            schema(json!({"paths": arr}), &["paths"]),
        ),
        (
            "write_file",
            schema(json!({"path": s, "content": s}), &["path", "content"]),
        ),
        (
            "edit_file",
            schema(
                json!({"path": s, "edits": {"type": "array"}, "dryRun": {"type": "boolean"}}),
                &["path", "edits"],
            ),
        ),
        ("create_directory", path_only()),
        ("list_directory", path_only()),
        (
            "list_directory_with_sizes",
            schema(json!({"path": s, "sortBy": s}), &["path"]),
        ),
        (
            "directory_tree",
            schema(json!({"path": s, "excludePatterns": arr}), &["path"]),
        ),
        (
            "move_file",
            schema(
                json!({"source": s, "destination": s}),
                &["source", "destination"],
            ),
        ),
        (
            "search_files",
            schema(
                json!({"path": s, "pattern": s, "excludePatterns": arr}),
                &["path", "pattern"],
            ),
        ),
        ("get_file_info", path_only()),
        ("list_allowed_directories", schema(json!({}), &[])),
    ]
}

/// S1: across the reference server's 14 tools the suggestions are exactly
/// path, paths[], source and destination; patterns and contents are not paths.
#[test]
fn s1_reference_schemas_suggest_exactly_the_path_arguments() {
    let mut all: Vec<String> = reference_schemas()
        .iter()
        .flat_map(|(_, s)| suggest_path_args(s))
        .collect();
    all.sort();
    all.dedup();
    assert_eq!(all, ["destination", "path", "paths[]", "source"]);
    let (_, move_file) = &reference_schemas()[10];
    // Sorted by name: schema property order is not kept by every JSON map.
    assert_eq!(suggest_path_args(move_file), ["destination", "source"]);
}

/// S2: a schema with no path-like property suggests nothing [keep].
#[test]
fn s2_no_path_like_property_suggests_nothing() {
    let s = schema(
        json!({"query": {"type": "string"}, "limit": {"type": "number"}}),
        &["query"],
    );
    assert!(suggest_path_args(&s).is_empty());
}

/// S2b: a path-like array the schema does not require gets the `?` mark.
#[test]
fn s2b_non_required_array_is_suggested_optional() {
    let s = schema(
        json!({"files": {"type": "array", "items": {"type": "string"}}}),
        &[],
    );
    assert_eq!(suggest_path_args(&s), ["files[]?"]);
}

/// K1: the production constants the test seams replace [keep].
#[test]
fn k1_production_constants_are_pinned() {
    assert_eq!(ROOT_CHECK_DEADLINE, std::time::Duration::from_secs(2));
    assert_eq!(RESOLVER_THREADS, 4);
    assert_eq!(DIRECTORY_ENTRY_CAP, 10_000);
}
