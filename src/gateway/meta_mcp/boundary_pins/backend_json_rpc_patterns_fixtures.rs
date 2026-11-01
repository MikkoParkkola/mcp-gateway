// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the `JsonRpc` pattern pin: each shape runs through the same
//! crate walk and sink the production scan uses.

use super::*;

/// Scan `body` as the body of `fn f` in a one-file crate.
fn scan_fixture(body: &str) -> Patterns {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("src")).expect("src dir");
    let source = format!("fn f(e: R) {{ {body} }}");
    std::fs::write(root.path().join("src/lib.rs"), source).expect("write lib.rs");
    scan(root.path(), &["src/lib.rs"])
}

fn uncarried(body: &str) -> usize {
    scan_fixture(body).uncarried.values().sum()
}

/// A missing alternative fails in every pattern shape; an equal one passes.
#[test]
fn a_pattern_without_the_backend_alternative_fails() {
    for shape in [
        "match e { Error::JsonRpc { code, .. } => code, _ => 0 };",
        "match e { Err(crate::Error::JsonRpc { .. }) => 1, _ => 0 };",
        "match e { (Self::JsonRpc { .. }, _) => 1, _ => 0 };",
        "match e { x @ JsonRpc { .. } => 1, _ => 0 };",
        "if let Error::JsonRpc { code, .. } = e { }",
        "let Error::JsonRpc { code, .. } = e else { return };",
        "matches!(e, Error::JsonRpc { code: -32001, .. });",
    ] {
        assert_eq!(uncarried(shape), 1, "{shape}");
    }
    for carry in [
        "match e { Error::JsonRpc { code, .. } | Error::BackendJsonRpc { code, .. } => code, _ => 0 };",
        "match e { Err(Error::JsonRpc { .. } | Error::BackendJsonRpc { .. }) => 1, _ => 0 };",
        "matches!(e, Error::JsonRpc { code: -1, .. } | Error::BackendJsonRpc { code: -1, .. });",
        "match e { Error::JsonRpc { code, .. } => code, Error::BackendJsonRpc { code, .. } => code, _ => 0 };",
    ] {
        assert_eq!(uncarried(carry), 0, "{carry}");
    }
}

/// Unequal fields or unequal split bodies are not a carry.
#[test]
fn unequal_alternatives_fail() {
    for shape in [
        "match e { Error::JsonRpc { code: -32602, .. } | Error::BackendJsonRpc { code: -32601, .. } => 1, _ => 0 };",
        "match e { Error::JsonRpc { code, message, .. } | Error::BackendJsonRpc { code, .. } => 1, _ => 0 };",
        "match e { Error::JsonRpc { code, .. } => code, Error::BackendJsonRpc { code, .. } => 0, _ => 0 };",
    ] {
        assert_eq!(uncarried(shape), 1, "{shape}");
    }
}

/// A listed exclusion passes; an unlisted, a recounted or a stale one fails.
#[test]
fn a_listed_exclusion_passes() {
    let found = scan_fixture("if let Error::JsonRpc { .. } = e { }").uncarried;
    assert!(diff(&found, "src/lib.rs\tf\t1\tgateway-only\tgateway mark\n").is_empty());
    assert!(diff(&found, "").iter().any(|w| w.starts_with("unlisted:")));
    assert!(
        diff(&found, "src/lib.rs\tf\t2\texcluded\tx\n")
            .iter()
            .any(|w| w.starts_with("listed 2"))
    );
    assert!(
        diff(&found, "src/lib.rs\tf\t1\tcarry\tx\n")
            .iter()
            .any(|w| w.starts_with("no class"))
    );
    assert!(
        diff(&Found::new(), "src/lib.rs\tf\t1\texcluded\tx\n")
            .iter()
            .any(|w| w.starts_with("stale"))
    );
}

/// A backend-only arm that builds `JsonRpc` fails even where its split pair
/// would otherwise read as a carry.
#[test]
fn a_backend_arm_rebuilding_the_gateway_variant_fails() {
    let split = "match e {
        Error::JsonRpc { code, .. } => Error::JsonRpc { code, message: m, data: None },
        Error::BackendJsonRpc { code, .. } => Error::JsonRpc { code, message: m, data: None },
        _ => e };";
    let patterns = scan_fixture(split);
    assert_eq!(patterns.uncarried.values().sum::<usize>(), 0);
    assert_eq!(patterns.rebuilt, ["src/lib.rs\tf"]);
    let iflet = "if let Error::BackendJsonRpc { code, .. } = e { Error::json_rpc(code, m); }";
    assert_eq!(scan_fixture(iflet).rebuilt.len(), 1);
    let kept = "match e { Error::BackendJsonRpc { .. } => e, _ => Error::json_rpc(1, m) };";
    assert!(scan_fixture(kept).rebuilt.is_empty());
}
