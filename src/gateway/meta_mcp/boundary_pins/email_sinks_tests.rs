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
        source,
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
    // A skip list that leaves the raw argument out, or a field merely named
    // "skip", still records it.
    for refused in [
        "#[instrument(skip(other))] fn f(i: &VerifiedIdentity, other: u8) {}",
        "#[instrument(fields(skipped = 1))] fn f(i: &VerifiedIdentity) {}",
        "#[instrument(skip(i))] fn f(i: &VerifiedIdentity, t: TemporaryToken) {}",
        "#[instrument(parent = skip_all)] fn f(i: &VerifiedIdentity) {}",
        "#[instrument(level = \"debug\", fields(skip = 1))] fn f(i: &VerifiedIdentity) {}",
    ] {
        assert_eq!(scanned(refused).refused.len(), 1, "{refused}");
    }
    for allowed in [
        "#[instrument(skip(i))] fn f(i: &VerifiedIdentity) {}",
        "#[instrument(skip_all)] fn f(i: Option<TemporaryToken>) {}",
        "#[instrument(level = \"debug\", skip_all)] fn f(i: &VerifiedIdentity) {}",
        "#[instrument(skip(i), fields(n = 1))] fn f(i: &VerifiedIdentity) {}",
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

fn body(source: &str, owner: &str) -> Option<String> {
    scanned(source)
        .rows
        .get(&(FILE.to_owned(), owner.to_owned(), "body".to_owned()))
        .cloned()
}

/// A reviewed reader's body is pinned: forwarding the email to a helper
/// changes the hash while the read count stays one.
#[test]
fn an_edited_reader_body_changes_its_pin_while_the_count_holds() {
    let reviewed = "fn f(i: &I) -> bool {\n    i.email().is_empty()\n}\n";
    let edited = "fn f(i: &I) -> bool {\n    log_it(i.email()).is_empty()\n}\n";
    assert_eq!(count(reviewed, "f", "read"), count(edited, "f", "read"));
    let (before, after) = (body(reviewed, "f"), body(edited, "f"));
    assert!(before.is_some(), "a reader has a body row");
    assert_ne!(before, after, "the edit changes the pinned body");
}

/// Only readers are pinned: a fn with no email read has no body row.
#[test]
fn a_fn_without_an_email_read_has_no_body_row() {
    assert_eq!(body("fn g(n: u8) -> u8 { n + 1 }", "g"), None);
}
