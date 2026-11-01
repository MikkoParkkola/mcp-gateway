// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `tools_call` runs its route stages in one order: every target authorized
//! before any is scanned, both before the caller verdicts. Read off the
//! source; the behaviour row is
//! `direct_audit_tests::empty_grant::an_empty_grant_is_refused_before_its_arguments_are_scanned`.

const FILE: &str = "src/gateway/router/handlers/dispatch_tools_call.rs";

/// `tools_call`'s body: from its signature to the end of the file, which
/// holds nothing after it.
fn tools_call_body() -> String {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE);
    let text = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{FILE}: {e}"));
    let start = text
        .find("pub(super) async fn tools_call(")
        .unwrap_or_else(|| panic!("{FILE}: tools_call not found"));
    text[start..].to_string()
}

/// The byte offset of the single occurrence of `needle` in `body`.
fn only(body: &str, needle: &str) -> usize {
    let found: Vec<usize> = body.match_indices(needle).map(|(at, _)| at).collect();
    assert_eq!(
        found.len(),
        1,
        "{FILE}: `{needle}` occurs {} times in tools_call; re-read the order",
        found.len()
    );
    found[0]
}

#[test]
fn tools_call_authorizes_every_target_before_it_scans_any() {
    let body = tools_call_body();
    let authorized = only(&body, ".authorize_call_targets(");
    let scanned = only(&body, ".scan_targets(");
    let verdicts = only(&body, ".caller_verdicts(");
    assert!(
        authorized < scanned,
        "{FILE}: a target is scanned before every target is authorized"
    );
    assert!(
        scanned < verdicts,
        "{FILE}: the caller verdicts run before the request scan"
    );
}
