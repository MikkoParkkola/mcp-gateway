// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The raw ID-token claims' `Debug` carries no email: a stray `?claims` in a
//! log line must not leak the address the audit records now hash.

use super::IdTokenClaims;

const EMAIL: &str = "Ada.Lovelace+Audit@Example.COM";

#[test]
fn the_claims_debug_carries_no_email() {
    let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
        "iss": "https://idp-a.example",
        "sub": "opaque-subject-7f3a",
        "aud": "mcp-gateway-a9",
        "exp": 2_000_000_000_u64,
        "iat": 1_000_000_000_u64,
        "email": EMAIL,
        "email_verified": true,
        "name": format!("Ada <{EMAIL}>"),
        "groups": [EMAIL, "staff"],
    }))
    .expect("the claims parse");
    let shown = format!("{claims:?}");
    assert!(
        shown.contains("opaque-subject-7f3a"),
        "the Debug still names the subject: {shown}"
    );
    assert!(
        !shown.to_lowercase().contains(&EMAIL.to_lowercase()),
        "the claims Debug prints the email: {shown}"
    );
}
