// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C0 T3: the Cloudflare assertion a stream holds is the one admission
//! verified — trimmed to the token, and never a blank header. Fixtures
//! (`AccessIdp`, `access_claims`, `resolve`, `headers`, `subject_pair`,
//! `peer`, `verified_oidc`, `access_mode`) are the parent module's.

use super::super::{
    HEADER_CF_ACCESS_EMAIL, HEADER_CF_ACCESS_JWT, IdentityHeaderRefusal, caller_grant_subject,
};
use super::*;
use axum::http::{HeaderMap, HeaderValue};

use crate::gateway::streaming::HeldSource;

/// One CF assertion header carrying exactly `value`, padding included: the
/// premise of these rows is that the presented bytes reach the seam.
fn cf_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_CF_ACCESS_JWT,
        HeaderValue::from_bytes(value.as_bytes())
            .expect("premise: the presented CF header value constructs"),
    );
    assert_eq!(
        headers
            .get(HEADER_CF_ACCESS_JWT)
            .expect("premise: the CF header is present")
            .to_str()
            .expect("premise: the CF header is text"),
        value,
        "premise: the presented CF header bytes are preserved"
    );
    headers
}

/// C0 T3: a padded genuine assertion resolves its subject, and the held
/// fact is the token itself, not the padded presentation. The blank-plus-
/// user-header and repeated-header refusals are unchanged controls.
#[tokio::test]
async fn padded_cf_assertion_is_captured_trimmed() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let token = idp.sign(&access_claims("u1", AUD, 10, 3600));

    // Control: the unpadded assertion resolves the team subject.
    let plain = headers(&[(HEADER_CF_ACCESS_JWT, token.as_str())]);
    let subject = resolve(
        &plain,
        Some(peer(OUTSIDER)),
        &access_mode(),
        Some(&verifier),
    )
    .await;
    assert_eq!(
        subject_pair(subject.expect("premise: the unpadded control resolves")),
        Some((format!("https://{TEAM}"), "u1".to_string())),
        "premise: the unpadded control lands on the team subject"
    );

    // Controls: a blank assertion beside a CF user header is refused, and
    // a repeated assertion header is malformed.
    let mut blank_with_user = cf_header("   ");
    blank_with_user.insert(
        HEADER_CF_ACCESS_EMAIL,
        HeaderValue::from_static("u@corp.example"),
    );
    assert_eq!(
        resolve(
            &blank_with_user,
            Some(peer(OUTSIDER)),
            &access_mode(),
            Some(&verifier)
        )
        .await,
        Err(IdentityHeaderRefusal::AccessAssertion),
        "control: a blank assertion with a CF user header is refused"
    );
    let repeated = headers(&[
        (HEADER_CF_ACCESS_JWT, token.as_str()),
        (HEADER_CF_ACCESS_JWT, token.as_str()),
    ]);
    assert_eq!(
        resolve(
            &repeated,
            Some(peer(OUTSIDER)),
            &access_mode(),
            Some(&verifier)
        )
        .await,
        Err(IdentityHeaderRefusal::Malformed),
        "control: a repeated CF assertion header is refused"
    );

    // The padded presentation of the same genuine token.
    let padded = format!("  {token}  ");
    let presented = cf_header(&padded);
    let subject = resolve(
        &presented,
        Some(peer(OUTSIDER)),
        &access_mode(),
        Some(&verifier),
    )
    .await;
    assert!(
        subject
            .expect("premise: the padded assertion is judged, not refused as a header")
            .is_some(),
        "own T3: a padded genuine assertion resolves a subject"
    );
    let admission = caller_grant_subject(
        None,
        &presented,
        Some(peer(OUTSIDER)),
        &access_mode(),
        Some(&verifier),
        None,
        None,
    )
    .await
    .expect("premise: the padded assertion admission resolves");
    assert!(
        matches!(&admission.source, HeldSource::Cloudflare(held) if held.expose() == token.as_str()),
        "own T3: the held assertion is the trimmed token"
    );
}

/// C0 T3: a blank assertion header with no CF user headers resolves no
/// subject and is held as no assertion at all.
#[tokio::test]
async fn blank_cf_assertion_is_not_captured() {
    let presented = cf_header("   ");
    assert_eq!(
        resolve(&presented, Some(peer(OUTSIDER)), &access_mode(), None).await,
        Ok(None),
        "premise: a blank assertion alone resolves no subject"
    );
    let admission = caller_grant_subject(
        None,
        &presented,
        Some(peer(OUTSIDER)),
        &access_mode(),
        None,
        None,
        None,
    )
    .await
    .expect("premise: the blank assertion admission resolves");
    assert!(
        matches!(admission.source, HeldSource::None),
        "own T3: a blank assertion header is never held"
    );
}

/// C0 T3 (subject half of the blank-verified row): a verified identity
/// with a blank issuer or a blank subject names nobody, so it must not
/// suppress the Cloudflare subject the same request admits.
#[tokio::test]
async fn blank_verified_identity_does_not_suppress_admitted_cf_subject() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let token = idp.sign(&access_claims("u1", AUD, 10, 3600));
    let presented = headers(&[(HEADER_CF_ACCESS_JWT, token.as_str())]);
    for (case, mut blank) in [
        ("blank issuer", verified_oidc()),
        ("blank subject", verified_oidc()),
    ] {
        match case {
            "blank issuer" => blank.issuer.clear(),
            _ => blank.subject.clear(),
        }
        let subject = caller_grant_subject(
            Some(&blank),
            &presented,
            Some(peer(OUTSIDER)),
            &access_mode(),
            Some(&verifier),
            None,
            None,
        )
        .await;
        assert_eq!(
            subject_pair(subject.expect("premise: the CF control resolves").subject),
            Some((format!("https://{TEAM}"), "u1".to_string())),
            "control: the admitted CF subject stands with a {case}"
        );
    }
}
