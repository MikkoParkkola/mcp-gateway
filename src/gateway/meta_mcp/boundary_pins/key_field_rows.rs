// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K5 completeness: every `ApiKeyConfig` field has a row showing that a reload
//! changing it applies on the next call, or a stated reason it has none. A new
//! field fails to compile in `assert_fields_exhaustive` until it is named;
//! a field named there but left out of the table fails the struct comparison.
//! A row counts only while it runs and is about its field: a top-level test
//! with no `#[ignore]`, `#[cfg]` or `#[cfg_attr]` on it or its file, in a file
//! `router/mod.rs` declares with only a `test` (or test-and-`webui`) gate,
//! whose doc comment names the field in backticks. So a row deleted, renamed,
//! switched off, unregistered or mapped to the wrong field fails. The pin
//! checks the declaration, not the features a run enables.

use std::collections::{BTreeMap, BTreeSet};

use super::invoke_stages_dest::tail_is;
use crate::config::ApiKeyConfig;

const KEYS: &str = "src/gateway/router/live_keys_tests.rs";
const RECORD: &str = "src/gateway/router/live_key_identity_record_tests.rs";
const AUTHZ: &str = "src/gateway/router/live_key_authz_tests.rs";

/// The row files, read at build time.
const ROW_FILES: [(&str, &str); 3] = [
    (
        KEYS,
        include_str!("../../../../src/gateway/router/live_keys_tests.rs"),
    ),
    (
        RECORD,
        include_str!("../../../../src/gateway/router/live_key_identity_record_tests.rs"),
    ),
    (
        AUTHZ,
        include_str!("../../../../src/gateway/router/live_key_authz_tests.rs"),
    ),
];

const STRUCT_FILE: &str = include_str!("../../../../src/config/features/api_key.rs");

/// The module file declaring the row files.
const ROUTER_MOD: &str = include_str!("../../../../src/gateway/router/mod.rs");

/// What pins one field's reload.
enum Pin {
    /// The test (file, function) that changes the field by reload and
    /// observes it on the next call.
    Row(&'static str, &'static str),
    /// Why no row can exist.
    Exempt(&'static str),
}

/// Every field and its pin, backed by an exhaustive compile-time inventory.
fn fields() -> Vec<(&'static str, Pin)> {
    assert_fields_exhaustive();
    vec![
        (
            "key",
            Pin::Exempt("a plaintext secret, refused at load, so no reload can carry it"),
        ),
        (
            "key_sha256",
            Pin::Row(
                KEYS,
                "k5_a_key_digest_changed_by_reload_applies_on_the_next_call",
            ),
        ),
        (
            "expires_at",
            Pin::Row(
                KEYS,
                "k2_a_key_removed_or_expired_by_reload_is_refused_on_the_next_call",
            ),
        ),
        (
            "name",
            Pin::Row(
                RECORD,
                "k5_a_key_renamed_by_reload_is_recorded_under_its_new_name",
            ),
        ),
        (
            "rate_limit",
            Pin::Row(
                AUTHZ,
                "k5_a_rate_limit_changed_by_reload_applies_and_keeps_its_usage",
            ),
        ),
        (
            "backends",
            Pin::Row(
                AUTHZ,
                "k5_a_backend_removed_from_a_key_by_reload_is_refused_on_the_next_call",
            ),
        ),
        (
            "allowed_tools",
            Pin::Row(
                AUTHZ,
                "k5_a_tool_left_out_of_allowed_tools_by_reload_is_refused",
            ),
        ),
        (
            "denied_tools",
            Pin::Row(AUTHZ, "k5_a_tool_denied_by_reload_is_refused"),
        ),
        (
            "admin",
            Pin::Row(
                AUTHZ,
                "k5_admin_taken_away_by_reload_closes_the_admin_route",
            ),
        ),
        (
            "kind",
            Pin::Row(
                KEYS,
                "k5_a_key_kind_changed_by_reload_applies_on_the_next_call",
            ),
        ),
        (
            "principal",
            Pin::Row(
                RECORD,
                "k5_a_principal_written_by_reload_keys_the_next_record",
            ),
        ),
        (
            "previous_key_sha256",
            Pin::Row(KEYS, "k5_a_rotation_written_by_reload_honours_its_grace"),
        ),
        (
            "previous_expires_at",
            Pin::Row(KEYS, "k5_a_rotation_written_by_reload_honours_its_grace"),
        ),
        (
            "approved_by",
            Pin::Row(
                KEYS,
                "k5_a_reload_removing_a_cli_keys_approver_ends_it_on_the_next_call",
            ),
        ),
        (
            "cli_host",
            Pin::Exempt("display only: shown on the Keys screen, never read by a decision"),
        ),
    ]
}

/// Keep the compile-time field inventory exhaustive.
fn assert_fields_exhaustive() {
    let ApiKeyConfig {
        key: _,
        key_sha256: _,
        expires_at: _,
        name: _,
        rate_limit: _,
        backends: _,
        allowed_tools: _,
        denied_tools: _,
        admin: _,
        kind: _,
        principal: _,
        previous_key_sha256: _,
        previous_expires_at: _,
        approved_by: _,
        cli_host: _,
    } = ApiKeyConfig::default();
}

/// The named fields of `ApiKeyConfig` as its source declares them.
fn declared_fields(source: &str) -> BTreeSet<String> {
    let file = syn::parse_file(source).expect("api_key.rs parses");
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(s) if s.ident == "ApiKeyConfig" => Some(s),
            _ => None,
        })
        .expect("api_key.rs declares ApiKeyConfig")
        .fields
        .iter()
        .filter_map(|f| f.ident.as_ref().map(ToString::to_string))
        .collect()
}

fn named(attr: &syn::Attribute, name: &str) -> bool {
    tail_is(attr.path(), name)
}

/// An attribute that can switch a test off: `ignore`, `cfg` or `cfg_attr`.
fn disables(attr: &syn::Attribute) -> bool {
    ["ignore", "cfg", "cfg_attr"].iter().any(|n| named(attr, n))
}

/// The top-level test functions of one file that run (no `#[ignore]`,
/// `#[cfg]` or `#[cfg_attr]` of their own, and no such inner attribute on the
/// file), each with its doc comment.
fn tests_in(source: &str) -> BTreeMap<String, String> {
    let file = syn::parse_file(source).expect("a row file parses");
    if file.attrs.iter().any(disables) {
        return BTreeMap::new();
    }
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f)
                if f.attrs.iter().any(|a| named(a, "test")) && !f.attrs.iter().any(disables) =>
            {
                let doc: Vec<String> = f
                    .attrs
                    .iter()
                    .filter(|a| named(a, "doc"))
                    .filter_map(|a| match &a.meta {
                        syn::Meta::NameValue(syn::MetaNameValue {
                            value:
                                syn::Expr::Lit(syn::ExprLit {
                                    lit: syn::Lit::Str(s),
                                    ..
                                }),
                            ..
                        }) => Some(s.value()),
                        _ => None,
                    })
                    .collect();
                Some((f.sig.ident.to_string(), doc.join(" ")))
            }
            _ => None,
        })
        .collect()
}

/// The gates a row module may carry: built for tests, with or without the
/// UI. Any other attribute (another `cfg`, a `#[path]` redirect) could build
/// a different file or none.
const ROW_MODULE_CFGS: [&str; 2] = ["test", "all(test,feature=\"webui\")"];

fn allowed_on_row_module(attr: &syn::Attribute) -> bool {
    named(attr, "doc")
        || (named(attr, "cfg")
            && attr.meta.require_list().is_ok_and(|list| {
                let gate: String = list.tokens.to_string().split_whitespace().collect();
                ROW_MODULE_CFGS.contains(&gate.as_str())
            }))
}

/// The `mod name;` declarations of a module file that carry only the row
/// gates.
fn declared_modules(source: &str) -> BTreeSet<String> {
    let file = syn::parse_file(source).expect("router/mod.rs parses");
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(m)
                if m.content.is_none() && m.attrs.iter().all(allowed_on_row_module) =>
            {
                Some(m.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

/// The module name of a row file under `src/gateway/router/`.
fn module_of(file: &str) -> &str {
    file.rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".rs"))
        .expect("a row file path")
}

/// Each `Row` pin whose test does not count (missing, not run, in an
/// undeclared file, or not naming its field), and each exemption that states
/// no reason.
fn missing_rows(
    files: &[(&str, &str)],
    modules: &str,
    fields: &[(&'static str, Pin)],
) -> Vec<String> {
    let declared = declared_modules(modules);
    fields
        .iter()
        .filter_map(|(field, pin)| match pin {
            Pin::Row(file, row) => {
                let (_, text) = files
                    .iter()
                    .find(|(name, _)| name == file)
                    .unwrap_or_else(|| panic!("{file} is not a row file"));
                let tests = tests_in(text);
                if !declared.contains(module_of(file)) {
                    Some(format!("{field}: router/mod.rs does not declare {file}"))
                } else if let Some(doc) = tests.get(*row) {
                    (!doc.contains(&format!("`{field}`")))
                        .then(|| format!("{field}: `{row}`'s doc does not name `{field}`"))
                } else {
                    Some(format!("{field}: {file} has no running test `{row}`"))
                }
            }
            Pin::Exempt(why) => why
                .trim()
                .is_empty()
                .then(|| format!("{field}: exempt with no reason")),
        })
        .collect()
}

#[test]
fn every_key_field_maps_to_a_reload_row_or_an_exemption() {
    let fields = fields();
    let listed: BTreeSet<String> = fields.iter().map(|(f, _)| (*f).to_owned()).collect();
    assert_eq!(listed.len(), fields.len(), "a field is listed twice");
    assert_eq!(
        listed,
        declared_fields(STRUCT_FILE),
        "the table and ApiKeyConfig's fields differ"
    );
    let missing = missing_rows(&ROW_FILES, ROUTER_MOD, &fields);
    assert!(
        missing.is_empty(),
        "a key field's reload row is gone:\n{}",
        missing.join("\n")
    );
}

/// The pin's own proof: a row deleted, untested, ignored, cfg-gated,
/// unregistered or about another field is caught, and so is an exemption with
/// no reason; a struct field is read by name.
#[test]
fn a_deleted_row_is_caught() {
    let fields = vec![("admin", Pin::Row(AUTHZ, "k5_row"))];
    let module = "#[cfg(test)]\nmod live_key_authz_tests;\n";
    let row = |attrs: &str, doc: &str| format!("/// {doc}\n{attrs}\nasync fn k5_row() {{}}\n");
    let caught = |text: &str, modules: &str| missing_rows(&[(AUTHZ, text)], modules, &fields).len();
    assert_eq!(caught(&row("#[tokio::test]", "K5 `admin`"), module), 0);
    assert_eq!(caught("", module), 1, "deleted");
    assert_eq!(caught(&row("", "K5 `admin`"), module), 1, "not a test");
    assert_eq!(
        caught(&row("#[tokio::test]\n#[ignore]", "K5 `admin`"), module),
        1,
        "ignored"
    );
    assert_eq!(
        caught(&row("#[tokio::test]\n#[cfg(any())]", "K5 `admin`"), module),
        1,
        "cfg-gated"
    );
    assert_eq!(
        caught(&row("#[tokio::test]", "K5 `admin`"), "mod other;\n"),
        1,
        "unregistered"
    );
    let ignored = row("#[tokio::test]\n#[cfg_attr(test, ignore)]", "K5 `admin`");
    assert_eq!(caught(&ignored, module), 1, "cfg_attr");
    let gated_file = format!("#![cfg(any())]\n{}", row("#[tokio::test]", "K5 `admin`"));
    assert_eq!(caught(&gated_file, module), 1, "file cfg");
    let webui = "#[cfg(all(test, feature = \"webui\"))]\nmod live_key_authz_tests;\n";
    assert_eq!(
        caught(&row("#[tokio::test]", "K5 `admin`"), webui),
        0,
        "webui gate"
    );
    for other in ["#[cfg(any())]", "#[cfg(test)]\n#[path = \"x.rs\"]"] {
        let module = format!("{other}\nmod live_key_authz_tests;\n");
        assert_eq!(
            caught(&row("#[tokio::test]", "K5 `admin`"), &module),
            1,
            "{other}"
        );
    }
    assert_eq!(
        caught(&row("#[tokio::test]", "K5 `backends`"), module),
        1,
        "another field"
    );
    assert_eq!(
        missing_rows(&[], module, &[("key", Pin::Exempt(" "))]).len(),
        1
    );
    assert_eq!(
        declared_fields("pub struct ApiKeyConfig { pub a: u8, b: u8 }"),
        BTreeSet::from(["a".to_owned(), "b".to_owned()])
    );
}
