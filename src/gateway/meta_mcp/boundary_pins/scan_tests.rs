// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B scanner rows (test plan v2 §2): the scanner's rules on
//! synthetic source, so a scanner fault fails a small named case.

use super::scan::{Cfg, eval, test_only};

fn cfg(predicate: &str) -> Cfg {
    eval(&syn::parse_str::<syn::Meta>(predicate).expect("a predicate"))
}

fn attrs(source: &str) -> Vec<syn::Attribute> {
    let item: syn::ItemFn = syn::parse_str(&format!("{source} fn f() {{}}")).expect("an item");
    item.attrs
}

/// SCAN-TT: the three-valued truth table. `test` is false, any other atom
/// unknown; `all()` is true and `any()` false. The case count is pinned, so
/// a dropped line fails loudly. Mutants: SCAN-m2 (unknown taken as true),
/// SCAN-m6 (first operand only).
#[test]
fn scan_tt_three_valued_cfg_truth_table() {
    // Operands: F = test, U = an unknown atom, T = not(test).
    let (f, u, t) = ("test", "feature = \"x\"", "not(test)");
    let cases = [
        (f.to_string(), Cfg::False),
        (u.to_string(), Cfg::Unknown),
        (t.to_string(), Cfg::True),
        (format!("not({u})"), Cfg::Unknown),
        (format!("not({t})"), Cfg::False),
        ("all()".to_string(), Cfg::True),
        ("any()".to_string(), Cfg::False),
        (format!("all({f}, {f})"), Cfg::False),
        (format!("all({f}, {u})"), Cfg::False),
        (format!("all({f}, {t})"), Cfg::False),
        (format!("all({u}, {f})"), Cfg::False),
        (format!("all({u}, {u})"), Cfg::Unknown),
        (format!("all({u}, {t})"), Cfg::Unknown),
        (format!("all({t}, {f})"), Cfg::False),
        (format!("all({t}, {u})"), Cfg::Unknown),
        (format!("all({t}, {t})"), Cfg::True),
        (format!("any({f}, {f})"), Cfg::False),
        (format!("any({f}, {u})"), Cfg::Unknown),
        (format!("any({f}, {t})"), Cfg::True),
        (format!("any({u}, {f})"), Cfg::Unknown),
        (format!("any({u}, {u})"), Cfg::Unknown),
        (format!("any({u}, {t})"), Cfg::True),
        (format!("any({t}, {f})"), Cfg::True),
        (format!("any({t}, {u})"), Cfg::True),
        (format!("any({t}, {t})"), Cfg::True),
        (format!("not(any({f}, all({u}, {f})))"), Cfg::True),
        (format!("all(not({u}), any({t}, {u}))"), Cfg::Unknown),
    ];
    assert_eq!(cases.len(), 27, "want 27 cases");
    for (predicate, want) in cases {
        assert_eq!(cfg(&predicate), want, "cfg({predicate})");
    }
}

/// SCAN-1..6: which items are test-only. Production is anything not
/// definitely excluded outside tests. Mutants: SCAN-m1 (a predicate that
/// mentions `test` counts as test-only: SCAN-3, SCAN-4), SCAN-m2 (SCAN-5),
/// SCAN-m12 (cfg ignored: SCAN-1, SCAN-2).
#[test]
fn scan_1_to_6_test_only_by_cfg_evaluation() {
    let rows = [
        ("SCAN-1", "#[cfg(test)]", true),
        ("SCAN-2", "#[cfg(all(test, feature = \"x\"))]", true),
        ("SCAN-3", "#[cfg(any(test, feature = \"webui\"))]", false),
        ("SCAN-4", "#[cfg(not(test))]", false),
        ("SCAN-5", "#[cfg(not(feature = \"webui\"))]", false),
        ("SCAN-6", "#[cfg(any(not(test), windows))]", false),
    ];
    for (row, attr, want) in rows {
        assert_eq!(test_only(&attrs(attr)), want, "{row}: {attr}");
    }
}
