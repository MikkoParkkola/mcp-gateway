// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K5 completeness: every `ApiKeyConfig` field has a row showing that a reload
//! changing it applies on the next call, or a stated reason it has none. A new
//! field fails to compile in `FIELDS`'s destructure until it is named, a field
//! named there but left out of the table fails the struct comparison, and a
//! row deleted or renamed fails the row lookup.

use std::collections::BTreeSet;

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

/// What pins one field's reload.
enum Pin {
    /// The test (file, function) that changes the field by reload and
    /// observes it on the next call.
    Row(&'static str, &'static str),
    /// Why no row can exist.
    Exempt(&'static str),
}

/// Every field and its pin. Destructured with no `..`: a field added to
/// `ApiKeyConfig` stops this compiling until it is named here.
fn fields() -> Vec<(&'static str, Pin)> {
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
    } = ApiKeyConfig::default();
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
    ]
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

/// The top-level test functions of one file.
fn tests_in(source: &str) -> BTreeSet<String> {
    let file = syn::parse_file(source).expect("a row file parses");
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f)
                if f.attrs
                    .iter()
                    .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test")) =>
            {
                Some(f.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

/// Each `Row` pin whose test is not in its file.
fn missing_rows(files: &[(&str, &str)], fields: &[(&'static str, Pin)]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|(field, pin)| match pin {
            Pin::Row(file, row) => {
                let (_, text) = files
                    .iter()
                    .find(|(name, _)| name == file)
                    .unwrap_or_else(|| panic!("{file} is not a row file"));
                (!tests_in(text).contains(*row))
                    .then(|| format!("{field}: {file} has no test `{row}`"))
            }
            Pin::Exempt(_) => None,
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
    let missing = missing_rows(&ROW_FILES, &fields);
    assert!(
        missing.is_empty(),
        "a key field's reload row is gone:\n{}",
        missing.join("\n")
    );
}

/// The pin's own proof: a deleted row and an untested function are caught,
/// and a struct field is read by name.
#[test]
fn a_deleted_row_is_caught() {
    let fields = vec![("admin", Pin::Row(AUTHZ, "k5_row"))];
    let present = "#[tokio::test]\nasync fn k5_row() {}\n";
    assert!(missing_rows(&[(AUTHZ, present)], &fields).is_empty());
    let untested = "async fn k5_row() {}\n";
    assert_eq!(missing_rows(&[(AUTHZ, untested)], &fields).len(), 1);
    assert_eq!(missing_rows(&[(AUTHZ, "")], &fields).len(), 1);
    assert_eq!(
        declared_fields("pub struct ApiKeyConfig { pub a: u8, b: u8 }"),
        BTreeSet::from(["a".to_owned(), "b".to_owned()])
    );
}
