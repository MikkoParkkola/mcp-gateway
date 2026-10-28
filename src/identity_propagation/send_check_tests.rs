// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A non-managed credential's per-send check: a published expiry refuses
//! definitively once past; an unpublished one may be shortened by a JWT's own
//! `exp`, read unverified, but never extended.

use super::*;

const NOW: i64 = 1_800_000_000;

fn now() -> Option<i64> {
    Some(NOW)
}

fn jwt(header: &str, claims: &str) -> String {
    format!(
        "{}.{}.sig",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    )
}

fn bearer(token: &str) -> Vec<(String, String)> {
    vec![("Authorization".to_owned(), format!("Bearer {token}"))]
}

async fn run(check: SendCheck) -> Result<(), Refusal> {
    check().await
}

#[test]
fn only_a_jwt_with_an_alg_header_yields_an_exp() {
    let exp = NOW - 5;
    assert_eq!(
        unverified_jwt_exp(&jwt(r#"{"alg":"RS256"}"#, &format!(r#"{{"exp":{exp}}}"#))),
        Some(exp)
    );
    assert_eq!(
        unverified_jwt_exp(&jwt(r#"{"typ":"x"}"#, &format!(r#"{{"exp":{exp}}}"#))),
        None,
        "no alg: not read as a JWT"
    );
    assert_eq!(unverified_jwt_exp("opaque.dotted.token"), None);
    assert_eq!(unverified_jwt_exp("opaque-token"), None);
}

#[tokio::test]
async fn a_published_expiry_refuses_definitively_once_past() {
    let headers = bearer("opaque");
    assert_eq!(
        run(expiry_check(Expiry::At(NOW + 60), &headers, now)).await,
        Ok(())
    );
    assert_eq!(
        run(expiry_check(Expiry::At(NOW - 1), &headers, now)).await,
        Err(Refusal::Definitive)
    );
}

#[tokio::test]
async fn an_unpublished_expiry_is_only_ever_shortened_by_a_jwt_exp() {
    let expired = jwt(r#"{"alg":"RS256"}"#, &format!(r#"{{"exp":{}}}"#, NOW - 1));
    assert_eq!(
        run(expiry_check(Expiry::Unpublished, &bearer(&expired), now)).await,
        Err(Refusal::ThisLoan),
        "an expired JWT is refused for this loan, never evicting"
    );
    assert_eq!(
        run(expiry_check(
            Expiry::Unpublished,
            &bearer("opaque-token"),
            now
        ))
        .await,
        Ok(()),
        "an opaque token is allowed for its own dispatch"
    );
    let far = jwt(
        r#"{"alg":"RS256"}"#,
        &format!(r#"{{"exp":{}}}"#, NOW + 3600),
    );
    assert_eq!(
        run(expiry_check(Expiry::At(NOW - 1), &bearer(&far), now)).await,
        Err(Refusal::Definitive),
        "a JWT exp never extends a published expiry"
    );
}
