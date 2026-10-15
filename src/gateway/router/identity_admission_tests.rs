// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::net::SocketAddr;

use axum::http::HeaderMap;

use super::test_fixture::*;
use super::*;
use crate::gateway::streaming::HeldSource;

async fn resolve_admission(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &CallerIdentityConfig,
    access: Option<&OidcVerifier>,
) -> Result<CallerAdmission, IdentityHeaderRefusal> {
    caller_grant_subject(None, headers, peer, config, access, None, None).await
}

fn pair(subject: Option<GrantSubject>) -> Option<(String, String)> {
    subject.map(|s| (s.authority, s.subject))
}

fn verified() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "oidc-subject".to_string(),
        email: "owner@corp.example".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example".to_string(),
    }
}

#[tokio::test]
async fn cloudflare_admission_holds_the_verified_assertion() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 10, 3600));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    let admission = resolve_admission(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier))
        .await
        .expect("premise: the genuine assertion is admitted");
    assert_eq!(
        pair(admission.subject),
        Some((format!("https://{TEAM}"), "u1".to_string())),
        "premise: the admitted subject is the team subject"
    );
    assert!(
        matches!(&admission.source, HeldSource::Cloudflare(held) if held.expose() == jwt.as_str()),
        "own T3: the held assertion is the verified token"
    );
}

#[tokio::test]
async fn unverified_assertion_is_never_held() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let stranger =
        crate::gateway::oauth::GatewayKeyPair::generate().expect("premise: a stranger key");
    let team_kid = idp.key.key_info().kid;
    let jwt = sign_with(&stranger, &team_kid, &access_claims("u1", AUD, 10, 3600));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    let result = resolve_admission(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert!(
        matches!(result, Err(IdentityHeaderRefusal::AccessAssertion)),
        "own T3: an unverified assertion is refused, so no admission holds it"
    );
}

#[tokio::test]
async fn off_mode_admission_holds_no_source() {
    let h = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "alice"),
        (HEADER_CF_ACCESS_JWT, "[REDACTED]"),
    ]);
    let admission = resolve_admission(
        &h,
        Some(peer(TRUSTED)),
        &CallerIdentityConfig::default(),
        None,
    )
    .await
    .expect("premise: mode off resolves");
    assert!(
        admission.subject.is_none(),
        "control: mode off resolves no subject"
    );
    assert!(
        matches!(admission.source, HeldSource::None),
        "own T2: mode off holds no identity source"
    );
}

#[tokio::test]
async fn oidc_outranked_admission_holds_no_source() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let (config, oidc) = (proxy_mode(), verified());
    let (result, ignored) = count(
        "mcp_identity_header_ignored_total",
        "oidc_precedence",
        caller_grant_subject(
            Some(&oidc),
            &h,
            Some(peer(TRUSTED)),
            &config,
            None,
            None,
            None,
        ),
    )
    .await;
    let admission = result.expect("premise: the outranked admission resolves");
    assert_eq!(
        pair(admission.subject),
        Some((
            "https://issuer.example".to_string(),
            "oidc-subject".to_string()
        )),
        "control: the verified identity outranks the header identity"
    );
    assert!(
        matches!(admission.source, HeldSource::None),
        "own T2: an outranked header identity is never held"
    );
    assert_eq!(ignored, 1, "the outranked header identity was not counted");
}

#[tokio::test]
async fn blank_verified_identity_does_not_suppress_admitted_cf() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 10, 3600));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    for (case, mut blank) in [("blank issuer", verified()), ("blank subject", verified())] {
        match case {
            "blank issuer" => blank.issuer.clear(),
            _ => blank.subject.clear(),
        }
        let admission = caller_grant_subject(
            Some(&blank),
            &h,
            Some(peer(OUTSIDER)),
            &access_mode(),
            Some(&verifier),
            None,
            None,
        )
        .await
        .expect("premise: the CF control resolves");
        assert_eq!(
            pair(admission.subject),
            Some((format!("https://{TEAM}"), "u1".to_string())),
            "own T3: the admitted CF subject stands with a {case}"
        );
        assert!(
            matches!(&admission.source, HeldSource::Cloudflare(held) if held.expose() == jwt.as_str()),
            "own T3: the admitted CF assertion is held with a {case}"
        );
    }
}

async fn assert_proxy_peer_controls(config: &CallerIdentityConfig, peer: SocketAddr) {
    let outsider = SocketAddr::from(([203, 0, 113, 9], 40_000));
    let admitted = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let admission = resolve_admission(&admitted, Some(peer), config, None)
        .await
        .expect("premise: the admitted control resolves");
    assert_eq!(
        pair(admission.subject),
        Some(("corp-sso".to_string(), "alice".to_string())),
        "premise: the admitted control lands under corp-sso"
    );
    assert!(
        !matches!(admission.source, HeldSource::Cloudflare(_)),
        "premise: the admitted control holds no assertion"
    );
    assert!(
        matches!(admission.source, HeldSource::TrustedProxy { _peer: p } if p == peer),
        "premise: the admitted control captures its peer"
    );
    assert!(
        matches!(
            resolve_admission(&admitted, Some(outsider), config, None).await,
            Err(IdentityHeaderRefusal::UntrustedPeer)
        ),
        "control: an untrusted peer with a subject header is refused"
    );
    let removed = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "alice"),
        (HEADER_GATEWAY_IDENTITY_AUTHORITY, "https://issuer.example"),
    ]);
    assert!(
        matches!(
            resolve_admission(&removed, Some(peer), config, None).await,
            Err(IdentityHeaderRefusal::RemovedHeader)
        ),
        "control: a removed gateway header is refused"
    );
    let repeated = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "alice"),
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "bob"),
    ]);
    assert!(
        matches!(
            resolve_admission(&repeated, Some(peer), config, None).await,
            Err(IdentityHeaderRefusal::Malformed)
        ),
        "control: a repeated subject header is refused"
    );
    let off = resolve_admission(
        &admitted,
        Some(peer),
        &CallerIdentityConfig::default(),
        None,
    )
    .await
    .expect("premise: mode off resolves");
    assert!(
        off.subject.is_none() && matches!(off.source, HeldSource::None),
        "control: mode off captures neither fact"
    );
    let outranked = caller_grant_subject(
        Some(&verified()),
        &admitted,
        Some(peer),
        config,
        None,
        None,
        None,
    )
    .await
    .expect("premise: the verified control resolves");
    assert!(
        matches!(outranked.source, HeldSource::None),
        "control: a verified identity captures neither fact"
    );
}

/// C0 T2 successor: in `trusted_proxy` trusting exactly `10.0.0.7` under
/// `corp-sso`, with the same actually trusted peer throughout, a request
/// that resolves no subject captures no peer fact either.
#[tokio::test]
async fn proxy_peer_without_admitted_subject_holds_no_source() {
    let config = CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec![
            "10.0.0.7"
                .parse()
                .expect("premise: the trusted peer parses"),
        ],
        authority: "corp-sso".to_string(),
        ..CallerIdentityConfig::default()
    };
    let peer = SocketAddr::from(([10, 0, 0, 7], 4_433));
    assert_proxy_peer_controls(&config, peer).await;
    let bare = HeaderMap::new();
    let admission = resolve_admission(&bare, Some(peer), &config, None)
        .await
        .expect("premise: no identity headers resolve");
    assert!(
        admission.subject.is_none(),
        "premise: no identity headers resolve no subject"
    );
    assert!(
        !matches!(admission.source, HeldSource::Cloudflare(_)),
        "own T2: no identity headers hold no assertion"
    );
    assert!(
        matches!(admission.source, HeldSource::None),
        "own T2: a peer that admitted nobody is no identity source"
    );
    let label_only = headers(&[(HEADER_GATEWAY_IDENTITY_LABEL, "Alice A.")]);
    let admission = resolve_admission(&label_only, Some(peer), &config, None)
        .await
        .expect("premise: a label alone resolves");
    assert!(
        admission.subject.is_none(),
        "premise: a label alone resolves no subject"
    );
    assert!(
        !matches!(admission.source, HeldSource::Cloudflare(_)),
        "own T2: a label alone holds no assertion"
    );
    assert!(
        matches!(admission.source, HeldSource::None),
        "own T2: a label alone captures no peer fact"
    );
}

/// Peer-retention main, separate from the no-source mains above: a genuine
/// `trusted_proxy` admission retains the very peer that admitted it.
#[tokio::test]
async fn admitted_proxy_peer_is_retained_as_held_source() {
    let admitted_peer = peer(TRUSTED);
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let admission = resolve_admission(&h, Some(admitted_peer), &proxy_mode(), None)
        .await
        .expect("setup-validity: the genuine trusted-proxy admission resolves");
    assert_eq!(
        pair(admission.subject),
        Some(("corp-sso".to_string(), "alice".to_string())),
        "setup-validity: the admitted subject is corp-sso/alice"
    );
    assert!(
        matches!(admission.source, HeldSource::TrustedProxy { _peer: p } if p == admitted_peer),
        "own peer-retention main: the admitted peer is retained as the held source"
    );
}
