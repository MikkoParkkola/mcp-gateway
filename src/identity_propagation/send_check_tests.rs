// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A non-managed credential's per-send check: a published expiry refuses
//! definitively once past; an unpublished one may be shortened by a JWT's own
//! `exp`, read unverified, but never extended.

use super::*;

const NOW: i64 = 1_800_000_000;

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
    // A fourth segment makes it no JWT, even after a header and claims that
    // would otherwise yield an `exp`.
    assert_eq!(
        unverified_jwt_exp(&format!(
            "{}.extra",
            jwt(r#"{"alg":"RS256"}"#, &format!(r#"{{"exp":{exp}}}"#))
        )),
        None
    );
    assert_eq!(unverified_jwt_exp("opaque.dotted.token"), None);
    assert_eq!(unverified_jwt_exp("opaque-token"), None);
}

#[tokio::test]
async fn a_published_expiry_refuses_definitively_once_past() {
    let headers = bearer("opaque");
    assert_eq!(
        run(expiry_check(Expiry::At(NOW + 60), &headers, || Some(NOW))).await,
        Ok(())
    );
    assert_eq!(
        run(expiry_check(Expiry::At(NOW - 1), &headers, || Some(NOW))).await,
        Err(Refusal::Definitive)
    );
}

#[tokio::test]
async fn an_unpublished_expiry_is_only_ever_shortened_by_a_jwt_exp() {
    let expired = jwt(r#"{"alg":"RS256"}"#, &format!(r#"{{"exp":{}}}"#, NOW - 1));
    assert_eq!(
        run(expiry_check(Expiry::Unpublished, &bearer(&expired), || {
            Some(NOW)
        }))
        .await,
        Err(Refusal::ThisLoan),
        "an expired JWT is refused for this loan, never evicting"
    );
    assert_eq!(
        run(expiry_check(
            Expiry::Unpublished,
            &bearer("opaque-token"),
            || Some(NOW)
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
        run(expiry_check(Expiry::At(NOW - 1), &bearer(&far), || Some(
            NOW
        )))
        .await,
        Err(Refusal::Definitive),
        "a JWT exp never extends a published expiry"
    );
}

#[tokio::test]
async fn a_synthetic_expiry_refuses_this_loan_and_never_evicts() {
    let headers = bearer("opaque");
    assert_eq!(
        run(expiry_check(
            Expiry::AtSynthetic(NOW + 60),
            &headers,
            || Some(NOW)
        ))
        .await,
        Ok(()),
        "before its synthetic expiry the credential is sent"
    );
    assert_eq!(
        run(expiry_check(Expiry::AtSynthetic(NOW - 1), &headers, || {
            Some(NOW)
        }))
        .await,
        Err(Refusal::ThisLoan),
        "a default expiry passing is not the issuer's word: no eviction"
    );
}

/// The bearer scheme is matched case-insensitively, with any run of spaces
/// after it, so an expired JWT under `BEARER` is still read.
#[tokio::test]
async fn any_spelling_of_the_bearer_scheme_is_read() {
    let expired = jwt(r#"{"alg":"RS256"}"#, &format!(r#"{{"exp":{}}}"#, NOW - 1));
    for header in [
        format!("BEARER {expired}"),
        format!("bEaReR {expired}"),
        format!("Bearer   {expired}"),
    ] {
        let headers = vec![("Authorization".to_owned(), header.clone())];
        assert_eq!(
            run(expiry_check(Expiry::Unpublished, &headers, || Some(NOW))).await,
            Err(Refusal::ThisLoan),
            "an expired JWT went unread under {header:?}"
        );
    }
}
