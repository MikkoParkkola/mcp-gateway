// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the raise and plain-refusal recogniser: each writes a small
//! crate and runs it through the same walk and derivation the crate tables
//! use, then asserts the exact rows (or guard hits) it produces.

use super::plain_refusals::Collect;
use super::plain_refusals::Derived;
use super::plain_refusals_tests::{associated_constructors, collect, crate_targets};

/// A crate with `src/gateway/a.rs` = `gateway` and `src/other/b.rs` = `other`.
fn fixture(gateway: &str, other: &str) -> (tempfile::TempDir, Collect, Derived) {
    let dir = tempfile::tempdir().expect("a temp crate");
    let files = [
        ("src/lib.rs", "mod gateway;\nmod other;\n"),
        ("src/gateway/mod.rs", "mod a;\nmod delivery_facts;\n"),
        (
            "src/gateway/delivery_facts.rs",
            "pub(crate) fn raise(e: Effect) { with(|facts| facts.effect = e); }\n\
             pub(crate) fn refused<E>(error: E) -> E { raise(Effect::Refused); error }\n",
        ),
        ("src/gateway/a.rs", gateway),
        ("src/other/mod.rs", "mod b;\n"),
        ("src/other/b.rs", other),
    ];
    for (path, text) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    let collect = collect(dir.path(), &["src/lib.rs"]);
    let derived = collect.derive();
    (dir, collect, derived)
}

/// The plain rows of `src/gateway/a.rs`, as `fn needle ordinal`.
fn plain(gateway: &str) -> Vec<String> {
    let (_dir, _, derived) = fixture(gateway, "");
    derived
        .plain
        .iter()
        .filter_map(|r| r.strip_prefix("src/gateway/a.rs\t"))
        .map(|r| r.replace('\t', " "))
        .collect()
}

#[test]
fn f1_a_tuple_construction_is_a_row() {
    assert_eq!(
        plain("fn f() -> Result<()> { Err(Error::BackendNotFound(s)) }"),
        ["f Error::BackendNotFound(..) 1"]
    );
}

#[test]
fn f2_a_struct_construction_is_a_row() {
    assert_eq!(
        plain("fn f() -> Result<()> { Err(crate::Error::AmbiguousBackend { server, rule }) }"),
        ["f Error::AmbiguousBackend{} 1"]
    );
}

/// F3 (synthetic: none of the twelve is a unit variant) and F4: a tuple
/// constructor handed on as a function is a construction too.
#[test]
fn f4_a_constructor_as_value_is_a_row() {
    assert_eq!(
        plain("fn f(x: Option<String>) -> Result<String> { x.ok_or(()).map_err(Error::Config) }"),
        ["f Error::Config (as value) 1"]
    );
}

#[test]
fn f6_a_construction_inside_a_raise_is_wrapped() {
    assert_eq!(
        plain(
            "fn f() -> Result<()> { \
             Err(crate::gateway::delivery_facts::refused(Error::Protocol(m))) }"
        ),
        ["f Error::Protocol(..) wrapped 1"]
    );
}

#[test]
fn f7_a_refuse_closure_call_is_a_row() {
    assert_eq!(
        plain("fn f() -> Result<()> { let refuse = |m| Error::Protocol(m); Err(refuse(x)) }"),
        ["f Error::Protocol(..) 1", "f via refuse (closure) 1"]
    );
}

#[test]
fn f8_a_helper_call_and_a_helper_value_are_rows() {
    let rows = plain(
        "fn helper(s: &str) -> Error { Error::ToolNotFound(s.into()) }\n\
         fn a() -> Result<()> { Err(helper(\"x\")) }\n\
         fn b(r: Result<(), &str>) -> Result<()> { r.map_err(helper) }",
    );
    assert_eq!(
        rows,
        [
            "a via helper 1",
            "b via helper (as value) 1",
            "helper Error::ToolNotFound(..) 1"
        ]
    );
}

/// F9: the live gate.rs shape, three hops of error-valued methods under a
/// `map_err` closure; the outer caller has its own row.
#[test]
fn f9_a_three_hop_method_chain_reaches_its_outer_caller() {
    let rows = plain(
        "impl G {\n\
         fn profile_withheld_capability(&self) -> Option<Error> { Some(Error::ToolNotFound(n)) }\n\
         fn profile_refusal_as_undefined(&self, r: Error) -> Error { self.profile_withheld_capability().unwrap_or(r) }\n\
         fn withheld_as_undefined(&self, r: Error) -> Error { self.profile_refusal_as_undefined(r) }\n\
         fn dispatch_guards(&self) -> Result<()> { check().map_err(|r| self.withheld_as_undefined(r)) }\n\
         }",
    );
    assert_eq!(
        rows,
        [
            "dispatch_guards via withheld_as_undefined 1",
            "profile_refusal_as_undefined via profile_withheld_capability 1",
            "profile_withheld_capability Error::ToolNotFound(..) 1",
            "withheld_as_undefined via profile_refusal_as_undefined 1"
        ]
    );
}

#[test]
fn f10_an_associated_constructor_call_is_a_row() {
    assert_eq!(
        plain("fn f(b: &B) -> Result<()> { Err(Error::circuit_open(\"x\", b)) }"),
        ["f via circuit_open 1"]
    );
}

#[test]
fn f11_monitored_tokens_in_macros_are_rows() {
    assert_eq!(
        plain(
            "fn f() { debug_assert!(matches!(Error::RateLimited(s), _)); }\n\
             owned!(Error::Config(x));"
        ),
        [
            "<module> Error::Config (in macro) 1",
            "f Error::RateLimited (in macro) 1"
        ]
    );
}

#[test]
fn fn1_a_refusal_outside_the_gateway_is_not_seen() {
    let source = "fn f() -> Result<()> { Err(Error::BackendNotFound(s)) }";
    let (_dir, _, derived) = fixture(source, source);
    assert_eq!(
        derived.plain,
        ["src/gateway/a.rs\tf\tError::BackendNotFound(..)\t1"],
        "stated limit: only src/gateway constructions are classified"
    );
}

#[test]
fn fn2_a_helper_outside_the_gateway_is_not_followed() {
    let (_dir, _, derived) = fixture(
        "fn f() -> Result<()> { Err(crate::other::b::outside(\"x\")) }",
        "pub fn outside(s: &str) -> Error { Error::ToolNotFound(s.into()) }",
    );
    assert!(
        derived.plain.is_empty(),
        "stated limit: a helper outside src/gateway is not followed: {:?}",
        derived.plain
    );
}

/// The guard hits `other` (in src/other/b.rs) produces, with `gateway`
/// defining one helper so a helper rename can be judged.
fn guard_hits(gateway: &str, other: &str) -> Vec<String> {
    let (_dir, collect, derived) = fixture(gateway, other);
    let mut hits: Vec<String> = collect.aliases.iter().map(|(_, t)| t.clone()).collect();
    hits.extend(collect.helper_renames(&derived.helpers));
    hits.extend(
        collect
            .error_impls
            .iter()
            .map(|f| format!("{f}: impl Error")),
    );
    hits.extend(
        collect
            .wrappers
            .iter()
            .map(|(f, n)| format!("{f}: wrapper {n}")),
    );
    hits
}

const HELPER: &str = "pub fn helper(s: &str) -> Error { Error::ToolNotFound(s.into()) }";

#[test]
fn b1_each_banned_import_form_is_a_hit() {
    let cases = [
        ("use crate::Error as E;", "use crate::Error as E"),
        (
            "use crate::error::Error as E;",
            "use crate::error::Error as E",
        ),
        (
            "use crate::Error::BackendNotFound;",
            "use crate::Error::BackendNotFound",
        ),
        ("use crate::Error::*;", "use crate::Error::*"),
        ("use crate::{Error::{Config}};", "use crate::Error::Config"),
        (
            "use crate::gateway::delivery_facts::refused;",
            "use crate::gateway::delivery_facts::refused",
        ),
        (
            "use crate::gateway::delivery_facts::*;",
            "use crate::gateway::delivery_facts::*",
        ),
        (
            "use crate::gateway::delivery_facts as facts;",
            "use crate::gateway::delivery_facts as facts",
        ),
        (
            "use crate::gateway::a::helper as other;",
            "src/other/b.rs: use helper as other",
        ),
    ];
    for (source, want) in cases {
        assert_eq!(guard_hits(HELPER, source), [want], "{source}");
    }
}

#[test]
fn b2_an_error_type_alias_in_the_gateway_is_a_hit() {
    let (_dir, collect, _) = fixture("type E = crate::Error;", "");
    assert_eq!(
        collect.aliases,
        [("src/gateway/a.rs".to_string(), "type E = Error".to_string())]
    );
}

#[test]
fn b3_plain_imports_are_not_hits() {
    let source =
        "use crate::Error;\nuse crate::gateway::delivery_facts;\nuse std::io::Error as IoError;";
    assert!(guard_hits(HELPER, source).is_empty());
}

#[test]
fn b4_an_impl_error_in_the_gateway_is_a_hit() {
    let (_dir, collect, _) = fixture("impl Error { fn f() -> Self { Self::Config(s) } }", "");
    assert_eq!(collect.error_impls, ["src/gateway/a.rs"]);
}

#[test]
fn b5_a_pass_through_raise_wrapper_is_a_hit() {
    let source = "fn wrap<E>(error: E) -> E { crate::gateway::delivery_facts::refused(error) }";
    assert_eq!(guard_hits("", source), ["src/other/b.rs: wrapper wrap"]);
}

#[test]
fn b6_a_macro_definition_naming_a_constructor_is_recorded() {
    let (_dir, collect, derived) = fixture(
        "macro_rules! deny { ($s:expr) => { Error::Config($s) } }",
        "",
    );
    let hits: Vec<Vec<String>> = collect
        .macro_defs
        .iter()
        .map(|(_, _, tokens)| super::plain_refusals::monitored_tokens(tokens, &derived.helpers))
        .collect();
    assert_eq!(hits, [vec!["Error::Config".to_string()]]);
}

/// F11b: a definition with no monitored token, invoked at item level with a
/// construction in its own tokens, still gives a row.
#[test]
fn f11b_an_item_macro_invocation_with_a_constructor_is_a_row() {
    assert_eq!(
        plain(
            "macro_rules! pass { ($e:expr) => { fn g() { let _ = $e; } } }\npass!(Error::Config(x));"
        ),
        ["<module> Error::Config (in macro) 1"]
    );
}

#[test]
fn b7_an_extra_associated_constructor_is_listed() {
    let source = "enum Error {}\nimpl Error {\n\
                  fn circuit_open() -> Self { Self::CircuitOpen { backend, last_failure } }\n\
                  fn not_found(s: &str) -> Self { Error::BackendNotFound(s.into()) }\n\
                  fn is(&self) -> bool { matches!(self, Self::Config(_)) }\n}";
    let found: Vec<String> = associated_constructors(source).into_iter().collect();
    assert_eq!(found, ["circuit_open", "not_found"]);
}

#[test]
fn b8_targets_in_both_bin_layouts_are_found() {
    let dir = tempfile::tempdir().expect("a temp crate");
    let root = dir.path();
    for (path, text) in [
        (
            "Cargo.toml",
            "[package]\nname = \"x\"\n\n[[bin]]\nname = \"x\"\npath = \"src/main.rs\"\n",
        ),
        ("src/lib.rs", ""),
        ("src/main.rs", ""),
        ("src/bin/flat.rs", ""),
        ("src/bin/nested/main.rs", ""),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    let found: Vec<String> = crate_targets(root).into_iter().collect();
    assert_eq!(
        found,
        [
            "src/bin/flat.rs",
            "src/bin/nested/main.rs",
            "src/lib.rs",
            "src/main.rs"
        ]
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"x\"\nautobins = false\n\n[[bin]]\nname = \"x\"\npath = \"src/main.rs\"\n",
    )
    .expect("write");
    let found: Vec<String> = crate_targets(root).into_iter().collect();
    assert_eq!(found, ["src/lib.rs", "src/main.rs"]);
}
