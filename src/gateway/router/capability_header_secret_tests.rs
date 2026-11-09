// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential pasted into a capability provider's `headers:` in the editor:
//! a literal value is refused on save and the file is left unchanged; a
//! `{env.X}` template passes. Uses the parent's admin gateway fixture.

use super::*;

/// A literal token in no file before this test; the save must not write it.
const LITERAL: &str = "tok-0123456789abcdef-canary";

/// `kept` with one provider header `Authorization: <value>`.
fn with_header(value: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: kept\ndescription: header row\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.example.com\n      path: /kept\n      headers:\n        Authorization: \"{value}\"\n"
    )
}

/// CAPEDIT.1 + CAPEDIT.3 (fail-fast row): a literal bearer token in a
/// provider header is refused by the save, and the file keeps its bytes.
#[tokio::test]
async fn capedit1_a_literal_header_credential_is_refused_and_the_file_kept() {
    let before = capability(CANARY_BEFORE);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    let base = sha256_hex(before.as_bytes());
    let after = with_header(&format!("Bearer {LITERAL}"));
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &base, &after))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a literal header credential was saved: {body}"
    );
    assert_eq!(std::fs::read_to_string(&fx.file).expect("the file"), before);
    assert!(
        !body.contains(LITERAL),
        "the answer echoed the value: {body}"
    );
}
