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
        "match e { Error::JsonRpc { code, message, data } => Error::JsonRpc { code, message: m, data }, \
         Error::BackendJsonRpc { code, message, data } => \
         Error::backend_json_rpc(JsonRpcError { code, message: m, data }), _ => e };",
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

/// The one exclusion row `found` holds, with `count`, `class` and `reason`.
fn row(found: &Found, count: usize, class: &str, reason: &str) -> String {
    let [(file, func, anchor)] = found.keys().collect::<Vec<_>>()[..] else {
        panic!("one uncarried pattern expected: {found:?}");
    };
    format!("{file}\t{func}\t{anchor}\t{count}\t{class}\t{reason}\n")
}

/// A listed exclusion passes; an unlisted, a recounted or a stale one fails.
#[test]
fn a_listed_exclusion_passes() {
    let found = scan_fixture("if let Error::JsonRpc { .. } = e { }").uncarried;
    assert!(diff(&found, &row(&found, 1, "gateway-only", "gateway mark")).is_empty());
    assert!(diff(&found, "").iter().any(|w| w.starts_with("unlisted:")));
    assert!(
        diff(&found, &row(&found, 2, "excluded", "x"))
            .iter()
            .any(|w| w.starts_with("listed 2"))
    );
    assert!(
        diff(&found, &row(&found, 1, "carry", "x"))
            .iter()
            .any(|w| w.starts_with("no class"))
    );
    assert!(
        diff(&Found::new(), &row(&found, 1, "excluded", "x"))
            .iter()
            .any(|w| w.starts_with("stale"))
    );
}

/// Exclusions are per occurrence: in a function with two uncarried patterns,
/// listing one leaves the other unlisted, and a listed row does not cover a
/// changed pattern in the same function.
#[test]
fn an_exclusion_does_not_cover_its_sibling() {
    let one = scan_fixture("if let Error::JsonRpc { code: -32001, .. } = e { }").uncarried;
    let listed = row(&one, 1, "gateway-only", "gateway mark");
    let both = scan_fixture(
        "if let Error::JsonRpc { code: -32001, .. } = e { }
         matches!(e, Error::JsonRpc { code: -32004, .. });",
    )
    .uncarried;
    let wrong = diff(&both, &listed);
    assert_eq!(wrong.len(), 1, "{wrong:?}");
    assert!(wrong[0].starts_with("unlisted:"), "{wrong:?}");
    let changed = scan_fixture("if let Error::JsonRpc { code: -32602, .. } = e { }").uncarried;
    let moved = diff(&changed, &listed);
    assert!(
        moved.iter().any(|w| w.starts_with("unlisted:")),
        "{moved:?}"
    );
    assert!(moved.iter().any(|w| w.starts_with("stale")), "{moved:?}");
}

/// Operators are part of the shape: split arms whose guards differ only in
/// `==` against `!=` (or `!` against `-`) are not a carry.
#[test]
fn arms_differing_in_an_operator_are_not_a_carry() {
    for shape in [
        "match e { Error::JsonRpc { code, .. } if code == 1 => 1, \
         Error::BackendJsonRpc { code, .. } if code != 1 => 1, _ => 0 };",
        "match e { Error::JsonRpc { code, .. } => !code, \
         Error::BackendJsonRpc { code, .. } => -code, _ => 0 };",
        "match e { Error::JsonRpc { mut code, .. } => { code += 1; code }, \
         Error::BackendJsonRpc { mut code, .. } => { code -= 1; code }, _ => 0 };",
    ] {
        assert_eq!(uncarried(shape), 1, "{shape}");
    }
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

/// A combined arm matching both variants that rebuilds the gateway's variant
/// erases the backend's origin: it fails, though its pattern is a carry.
#[test]
fn a_combined_arm_rebuilding_the_gateway_variant_fails() {
    let combined = "match e {
        Error::JsonRpc { code, .. } | Error::BackendJsonRpc { code, .. } => Error::json_rpc(code, m),
        _ => e };";
    let patterns = scan_fixture(combined);
    assert_eq!(patterns.uncarried.values().sum::<usize>(), 0);
    assert_eq!(patterns.rebuilt, ["src/lib.rs\tf"]);
    let passed_on = "match e {
        e @ (Error::JsonRpc { .. } | Error::BackendJsonRpc { .. }) => e,
        _ => Error::json_rpc(1, m) };";
    assert!(scan_fixture(passed_on).rebuilt.is_empty());
}
