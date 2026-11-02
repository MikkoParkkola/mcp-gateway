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
    hits.extend(collect.raise_imports(&derived));
    let names: std::collections::BTreeSet<String> = derived
        .helpers
        .iter()
        .cloned()
        .chain(
            derived
                .raise_helpers
                .iter()
                .filter_map(|h| h.rsplit("::").next().map(str::to_string)),
        )
        .collect();
    hits.extend(collect.helper_renames(&names));
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
            "src/gateway/a.rs: use helper as other",
        ),
    ];
    for (source, want) in cases {
        assert_eq!(
            guard_hits(&format!("{HELPER}\n{source}"), ""),
            [want],
            "{source}"
        );
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
    for source in [
        "fn wrap<E>(error: E) -> E { crate::gateway::delivery_facts::refused(error) }",
        "fn wrap<E>(error: E) -> E { return crate::gateway::delivery_facts::refused(error); }",
        "fn wrap<E>(error: E) { crate::gateway::delivery_facts::refused(error); }",
    ] {
        assert_eq!(
            guard_hits("", source),
            ["src/other/b.rs: wrapper wrap"],
            "{source}"
        );
    }
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
                  fn is(&self) -> bool { matches!(self, Self::Config(_)) }\n\
                  fn tripped(b: &B) -> Self { Self::circuit_open(\"x\", b) }\n}";
    let found: Vec<String> = associated_constructors(source).into_iter().collect();
    assert_eq!(found, ["circuit_open", "not_found", "tripped"]);
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

/// A refusal-named helper or closure is rowed by the refusal scan in
/// `delivery_framing.rs`, not again here; its own construction still is.
#[test]
fn f12_a_refusal_named_helper_is_not_rowed_twice() {
    assert_eq!(
        plain(
            "fn missing_refusal(s: &str) -> Error { Error::ToolNotFound(s.into()) }\n\
             fn a() -> Result<()> { let refusal = |m| Error::Protocol(m); Err(missing_refusal(\"x\")) }\n\
             fn b() -> Result<()> { Err(refusal(m)) }"
        ),
        [
            "a Error::Protocol(..) 1",
            "missing_refusal Error::ToolNotFound(..) 1"
        ]
    );
}

/// D1 reverted (code review): a private crate-error alias outside the
/// gateway is a hit too (a crate-root one reaches every gateway module);
/// under the gateway a relative `super::Error` alias is one as well.
#[test]
fn b9_crate_error_aliases_are_hits_anywhere() {
    let (_dir, collect, _) = fixture("", "use crate::Error as E;\nfn f() {}");
    assert_eq!(collect.aliases.len(), 1, "{:?}", collect.aliases);
    let (_dir, collect, _) = fixture("use super::Error as E;\ntype F = super::Error;", "");
    assert_eq!(
        collect.aliases,
        [
            (
                "src/gateway/a.rs".to_string(),
                "use super::Error as E".to_string()
            ),
            ("src/gateway/a.rs".to_string(), "type F = Error".to_string()),
        ]
    );
    let (_dir, collect, _) = fixture("use std::io::Error as IoError;", "use super::Error as E;");
    assert!(collect.aliases.is_empty(), "{:?}", collect.aliases);
}

/// The raise rows `gateway` (src/gateway/a.rs) and `other` (src/other/b.rs)
/// produce, as `file fn needle count`, minus the fixture's own
/// `delivery_facts.rs` rows.
fn raise_rows(gateway: &str, other: &str) -> Vec<String> {
    let (_dir, _, derived) = fixture(gateway, other);
    derived
        .raises
        .iter()
        .filter(|(key, _)| !key.starts_with("src/gateway/delivery_facts.rs"))
        .map(|(key, n)| format!("{} {n}", key.replace('\t', " ")))
        .collect()
}

const RAISE_HELPER: &str =
    "fn withheld_for(r: u8) { if r > 0 { crate::gateway::delivery_facts::refused(()); } }\n";

/// F13 (code review HIGH): a call of a local raise helper, or the helper
/// handed on as a value, is a raise row, so deleting it fails the table.
#[test]
fn f13_a_raise_helper_call_is_a_raise_row() {
    let gateway = format!(
        "{RAISE_HELPER}fn a() {{ withheld_for(1); }}\n\
         fn b(x: Option<u8>) {{ let _ = x.map(withheld_for); }}"
    );
    assert_eq!(
        raise_rows(&gateway, ""),
        [
            "src/gateway/a.rs a via withheld_for 1",
            "src/gateway/a.rs b via withheld_for (as value) 1",
            "src/gateway/a.rs withheld_for refused 1"
        ]
    );
}

/// F14: a raise helper called from another module, by path or through an
/// import of it, is a row; a namesake defined elsewhere is not.
#[test]
fn f14_a_raise_helper_is_resolved_across_modules() {
    let other = "use crate::gateway::a::withheld_for;\n\
                 fn c() { crate::gateway::a::withheld_for(2); }\n\
                 fn d() { withheld_for(3); }";
    let rows = raise_rows(RAISE_HELPER, other);
    assert!(
        rows.contains(&"src/other/b.rs c via withheld_for 1".to_string()),
        "{rows:?}"
    );
    assert!(
        rows.contains(&"src/other/b.rs d via withheld_for 1".to_string()),
        "{rows:?}"
    );
    let namesake = raise_rows(
        RAISE_HELPER,
        "fn withheld_for(_: u8) {}\nfn e() { withheld_for(4); }",
    );
    assert!(!namesake.iter().any(|r| r.contains(" e ")), "{namesake:?}");
}

/// F15: a helper that only calls a raise helper is one too (fixed point).
#[test]
fn f15_a_helper_of_a_raise_helper_is_followed() {
    let gateway = format!("{RAISE_HELPER}fn outer() {{ withheld_for(5); }}\nfn f() {{ outer(); }}");
    let rows = raise_rows(&gateway, "");
    assert!(
        rows.contains(&"src/gateway/a.rs f via outer 1".to_string()),
        "{rows:?}"
    );
}

/// D3 narrowed (code review): a refusal-named helper bound or handed on as
/// a value outside a combinator is a row; handed to `map_err` it is the
/// refusal scan's row, not this one's.
#[test]
fn f16_a_refusal_helper_value_outside_a_combinator_is_a_row() {
    assert_eq!(
        plain(
            "fn missing_refusal(s: &str) -> Error { Error::ToolNotFound(s.into()) }\n\
             fn a() -> Result<()> { let make = missing_refusal; Err(make(\"x\")) }\n\
             fn b(r: Result<(), &str>) -> Result<()> { r.map_err(missing_refusal) }"
        ),
        [
            "a via missing_refusal (as value) 1",
            "missing_refusal Error::ToolNotFound(..) 1"
        ]
    );
}

/// Macro rows count each monitored name (code review): a second
/// construction inside an existing invocation changes the row.
#[test]
fn f17_a_second_construction_in_a_macro_changes_its_row() {
    assert_eq!(
        plain(
            "fn f() { debug_assert!(matches!(e, Error::RateLimited(_) | Error::RateLimited(_))); }"
        ),
        ["f Error::RateLimited*2 (in macro) 1"]
    );
}

/// F18 (delta review HIGH): a raise helper that is a method, called as
/// `self.helper()`, is a raise row; a free function of that name is not.
#[test]
fn f18_a_method_raise_helper_call_is_a_raise_row() {
    let gateway = "struct G;\n\
                   impl G {\n\
                   fn advise(&self) { crate::gateway::delivery_facts::refused(()); }\n\
                   fn deliver(&self) { self.advise(); }\n\
                   }\n\
                   fn other(x: &X) { x.unrelated(); }";
    let rows = raise_rows(gateway, "");
    assert!(
        rows.contains(&"src/gateway/a.rs deliver via advise 1".to_string()),
        "{rows:?}"
    );
    let free = raise_rows(
        &format!("{RAISE_HELPER}fn g(x: &X) {{ x.withheld_for(1); }}"),
        "",
    );
    assert!(!free.iter().any(|r| r.contains(" g ")), "{free:?}");
}

/// F19 (delta review, muse): calls through `super::`, `use super::helper`
/// and `use super::*` resolve to the parent module's raise helper.
#[test]
fn f19_a_parent_module_raise_helper_is_resolved() {
    let dir = tempfile::tempdir().expect("a temp crate");
    for (path, text) in [
        ("src/lib.rs", "mod gateway;\n"),
        (
            "src/gateway/mod.rs",
            "mod a;\nmod b;\nmod c;\nmod delivery_facts;\n\
             fn withheld_for(r: u8) { if r > 0 { crate::gateway::delivery_facts::refused(()); } }\n",
        ),
        (
            "src/gateway/delivery_facts.rs",
            "pub(crate) fn raise(e: Effect) { with(|facts| facts.effect = e); }\n\
             pub(crate) fn refused<E>(error: E) -> E { raise(Effect::Refused); error }\n",
        ),
        ("src/gateway/a.rs", "fn f() { super::withheld_for(1); }"),
        (
            "src/gateway/b.rs",
            "use super::withheld_for;\nfn g() { withheld_for(2); }",
        ),
        (
            "src/gateway/c.rs",
            "use super::*;\nfn h() { withheld_for(3); }",
        ),
    ] {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    let derived = collect(dir.path(), &["src/lib.rs"]).derive();
    for row in [
        "src/gateway/a.rs\tf\tvia withheld_for",
        "src/gateway/b.rs\tg\tvia withheld_for",
        "src/gateway/c.rs\th\tvia withheld_for",
    ] {
        assert!(
            derived.raises.contains_key(row),
            "{row}: {:?}",
            derived.raises
        );
    }
}

/// F20 (delta review): `Self::helper()` inside an impl reaches an
/// associated plain-refusal helper.
#[test]
fn f20_a_self_helper_call_is_a_row() {
    let rows = plain(
        "impl G {\n\
         fn helper() -> Error { Error::Config(String::new()) }\n\
         fn f() -> Error { Self::helper() }\n\
         }",
    );
    assert!(rows.contains(&"f via helper 1".to_string()), "{rows:?}");
}

/// F21 (delta review): a renamed import of a raise helper is a guard hit.
#[test]
fn f21_a_renamed_raise_helper_import_is_a_hit() {
    let hits = guard_hits(
        RAISE_HELPER,
        "use crate::gateway::a::withheld_for as record;",
    );
    assert_eq!(hits, ["src/other/b.rs: use withheld_for as record"]);
}

/// F22 (delta review): a raise helper called inside a macro is a raise
/// row; the word in a log message is not.
#[test]
fn f22_a_raise_helper_called_in_a_macro_is_a_raise_row() {
    let gateway = format!(
        "{RAISE_HELPER}fn f() {{ select! {{ _ = t => withheld_for(1), _ = c => {{}} }} }}\n\
         fn g() {{ warn!(\"withheld_for is skipped\"); }}"
    );
    let rows = raise_rows(&gateway, "");
    assert!(
        rows.contains(&"src/gateway/a.rs f withheld_for (in macro) 1".to_string()),
        "{rows:?}"
    );
    assert!(!rows.iter().any(|r| r.contains(" g ")), "{rows:?}");
}
