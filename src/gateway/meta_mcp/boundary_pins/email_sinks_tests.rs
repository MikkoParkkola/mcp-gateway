// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture rows for the email-sink pin: each way production code reads an
//! email or writes one into a macro is a counted row, and each form that
//! would emit a raw identity's email is refused.

use super::super::fragments::pin_table;
use super::super::identity_sources::{Scan, differences};
use super::{crate_scan, scan_file};

const FILE: &str = "src/a.rs";

fn scanned(source: &str) -> Scan {
    let mut scan = Scan::default();
    scan_file(
        FILE,
        &syn::parse_file(source).expect("fixture parses"),
        &mut scan,
    );
    scan
}

fn count(source: &str, owner: &str, kind: &str) -> Option<String> {
    scanned(source)
        .rows
        .get(&(FILE.to_owned(), owner.to_owned(), kind.to_owned()))
        .cloned()
}

#[test]
fn an_email_call_and_a_field_read_each_count_as_a_read() {
    let n = count(
        "fn f(i: &I) { let _ = i.email(); let _ = &i.email; }",
        "f",
        "read",
    );
    assert_eq!(n.as_deref(), Some("2"));
}

#[test]
fn a_method_with_arguments_named_email_is_not_a_read() {
    assert_eq!(count("fn f(b: B) { b.email(x); }", "f", "read"), None);
}

#[test]
fn a_log_field_a_format_and_a_json_naming_email_each_count() {
    let source = r#"fn f(i: &I) {
        tracing::debug!(email = %x, "matched");
        let _ = format!("{}", email);
        let _ = json!({ "nested": [email] });
    }"#;
    assert_eq!(count(source, "f", "macro").as_deref(), Some("3"));
}

#[test]
fn a_read_inside_an_impl_fn_is_owned_by_type_and_fn() {
    let n = count(
        "impl P { fn m(&self, i: &I) { i.email(); } }",
        "P::m",
        "read",
    );
    assert_eq!(n.as_deref(), Some("1"));
}

#[test]
fn test_only_code_is_not_scanned() {
    let scan = scanned("#[cfg(test)] fn f(i: &I) { i.email(); tracing::info!(email = 1); }");
    assert!(scan.rows.is_empty() && scan.refused.is_empty(), "{scan:?}");
}

#[test]
fn a_derived_serialize_on_a_raw_type_is_refused_even_under_cfg_attr() {
    for source in [
        "#[derive(Clone, Serialize)] pub struct VerifiedIdentity { email: String }",
        "#[derive(serde::Serialize)] pub struct TemporaryToken { t: u8 }",
        "#[cfg_attr(feature = \"x\", derive(Serialize))] pub struct VerifiedIdentity {}",
    ] {
        assert_eq!(scanned(source).refused.len(), 1, "{source}");
    }
}

#[test]
fn a_hand_written_serialize_for_a_raw_type_is_refused() {
    let scan = scanned("impl serde::Serialize for VerifiedIdentity { fn serialize() {} }");
    assert_eq!(scan.refused.len(), 1, "{scan:?}");
}

#[test]
fn a_derived_debug_on_the_identity_or_the_claims_is_refused() {
    for source in [
        "#[derive(Debug, Clone)] pub struct VerifiedIdentity {}",
        "#[derive(Debug, Deserialize)] struct IdTokenClaims {}",
    ] {
        assert_eq!(scanned(source).refused.len(), 1, "{source}");
    }
}

#[test]
fn a_serialize_or_debug_on_another_type_is_not_refused() {
    let scan = scanned("#[derive(Debug, Serialize)] struct SafeIdentity { email_hash: String }");
    assert!(scan.refused.is_empty(), "{scan:?}");
}

#[test]
fn instrument_without_skip_on_a_raw_identity_fn_is_refused() {
    let refused = scanned("#[tracing::instrument] fn f(i: &VerifiedIdentity) {}").refused;
    assert_eq!(refused.len(), 1, "{refused:?}");
    for allowed in [
        "#[instrument(skip(i))] fn f(i: &VerifiedIdentity) {}",
        "#[instrument(skip_all)] fn f(i: Option<TemporaryToken>) {}",
        "#[instrument] fn f(n: u8) {}",
    ] {
        assert!(scanned(allowed).refused.is_empty(), "{allowed}");
    }
}

/// The live pin: every production read and macro naming an email matches
/// its reviewed row, and no raw-email form exists.
#[test]
fn every_email_read_and_sink_is_a_reviewed_row() {
    let wrong = differences(&crate_scan(), &pin_table("email_sinks"), "email_sinks");
    assert!(
        wrong.is_empty(),
        "email reads and sinks differ from email_sinks.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
