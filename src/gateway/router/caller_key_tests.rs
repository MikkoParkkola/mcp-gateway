// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for [`caller_key`]: the exact encoding, that no subject key can
//! equal a credential key, and which variant each identity mix resolves to.
//! The route-level rows live in `tests/meta_firewall_verdict/caller_key.rs`.

use super::*;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client, principal_of};

fn credential(secret: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "key".to_string(),
        principal: principal_of(secret),
        authenticated: true,
        ..anonymous_client()
    }
}

fn cert(san_uri: Option<&str>, cn: Option<&str>, display: &str) -> CertIdentity {
    CertIdentity {
        san_uris: san_uri.map(str::to_string).into_iter().collect(),
        common_name: cn.map(str::to_string),
        display_name: display.to_string(),
        ..Default::default()
    }
}

fn subject(authority: &str, id: &str) -> GrantSubject {
    GrantSubject::new(authority, id, None)
}

// U1: the byte-exact encoding (design F2).
#[test]
fn u1_the_encoding_is_length_prefixed_and_tagged() {
    assert_eq!(
        caller_key(Some(&subject("a:b", "x")), None, None),
        "subject:3:a:b:1:x"
    );
    let client = AuthenticatedClient {
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: "d1".to_string(),
        ..credential("unused")
    };
    assert_eq!(caller_key(None, None, Some(&client)), "credential:2:d1");
}

// U2: a subject key never equals a credential key, and no two distinct
// subjects collide, even for inputs built to collide under a naive join.
#[test]
fn u2_no_two_distinct_callers_share_a_key() {
    let adversarial = [
        ("credential", "2:d1"),
        ("a", "b:c"),
        ("a:b", "c"),
        ("a:1:b", "c"),
        ("", "x"),
        ("x", ""),
        ("1", "1:1:1"),
    ];
    let mut seen = std::collections::HashMap::new();
    for (authority, id) in adversarial {
        let key = caller_key(Some(&subject(authority, id)), None, None);
        if let Some(prior) = seen.insert(key.clone(), (authority, id)) {
            panic!("{prior:?} and {:?} share the key {key}", (authority, id));
        }
    }
    for digest in ["d1", "2:d1", "subject:1:a:1:b", ""] {
        let client = AuthenticatedClient {
            // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
            principal: digest.to_string(),
            ..credential("unused")
        };
        let key = caller_key(None, None, Some(&client));
        assert!(
            !seen.contains_key(&key),
            "credential {digest:?} took a subject key: {key}"
        );
    }
}

// U3: which variant each identity mix resolves to.
#[test]
fn u3_a_subject_outranks_the_credential() {
    let client = credential("k1");
    let key = caller_key(Some(&subject("agent_oauth", "a")), None, Some(&client));
    assert_eq!(key, "subject:11:agent_oauth:1:a");
}

#[test]
fn u3_a_certificate_subject_is_its_san_uri_then_its_cn() {
    for (c, id) in [
        (
            cert(Some("spiffe://t/a"), Some("cn"), "shown"),
            "spiffe://t/a",
        ),
        (cert(None, Some("cn-a"), "shown"), "cn-a"),
    ] {
        let resolved = grant_subject_from_cert_identity(&c).unwrap();
        assert_eq!(
            caller_key(Some(&resolved), Some(&c), None),
            format!("subject:4:mtls:{}:{id}", id.len())
        );
    }
}

#[test]
fn u3_a_certificate_naming_no_subject_is_no_subject_key() {
    // MIK-8286: such a certificate has no grant subject at all.
    let c = cert(None, None, "<unknown>");
    assert_eq!(grant_subject_from_cert_identity(&c), None);
    assert_eq!(caller_key(None, Some(&c), None), "", "no identity at all");
    let client = credential("k1");
    assert!(
        caller_key(None, Some(&c), Some(&client)).starts_with("credential:"),
        "it falls through to the credential"
    );
    // Defence in depth: a placeholder subject handed over with that
    // certificate is re-derived from the certificate, and still names no one.
    let placeholder = GrantSubject::new("mtls", "<unknown>", None);
    assert_eq!(caller_key(Some(&placeholder), Some(&c), None), "");
}

#[test]
fn u3_an_oidc_subject_is_not_re_derived_from_a_certificate() {
    // An issuer that happens to read "mtls" keeps its own subject; only the
    // certificate's own grant subject is re-derived from the certificate.
    let c = cert(Some("spiffe://t/a"), None, "shown");
    let oidc = subject("mtls", "alice");
    assert_eq!(
        caller_key(Some(&oidc), Some(&c), None),
        "subject:4:mtls:5:alice"
    );
}

#[test]
fn u3_no_identity_is_no_key() {
    assert_eq!(caller_key(None, None, None), "");
    assert_eq!(caller_key(None, None, Some(&anonymous_client())), "");
}

// U4 (MIK-8286): authorization no longer keeps a display-name fallback:
// whatever the display name says, a certificate naming no subject has none.
#[test]
fn u4_a_display_name_is_never_a_grant_subject() {
    let c = cert(None, None, "shown");
    assert_eq!(grant_subject_from_cert_identity(&c), None);
}

// GH1942.HARDEN.1 row 9: the bucket half of `CallerKey`.
#[test]
fn caller_key_separates_subjects() {
    let shared = credential("one-key-for-everyone");
    let a = caller_key(Some(&subject("agent_oauth", "a")), None, Some(&shared));
    let b = caller_key(Some(&subject("agent_oauth", "b")), None, Some(&shared));
    assert_ne!(a, b, "two subjects behind one key shared a bucket");
}

#[test]
fn token_exchange_keeps_bucket() {
    let who = subject("oidc:https://idp.example", "alice");
    let before = caller_key(Some(&who), None, Some(&credential("token-1")));
    let after = caller_key(Some(&who), None, Some(&credential("token-2")));
    assert_eq!(before, after, "a new token split one subject's bucket");
}

/// A real leaf, parsed by `CertIdentity::from_der`, with the given CN and
/// SAN URI (either may be absent).
fn leaf(cn: Option<&str>, san_uri: Option<&str>) -> CertIdentity {
    use rcgen::string::Ia5String;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    if let Some(cn) = cn {
        dn.push(DnType::CommonName, cn);
    }
    params.distinguished_name = dn;
    params.subject_alt_names = san_uri
        .map(|uri| SanType::URI(Ia5String::try_from(uri).unwrap()))
        .into_iter()
        .collect();
    let key_pair = KeyPair::generate().expect("key generation failed");
    let der = params.self_signed(&key_pair).expect("cert").der().to_vec();
    CertIdentity::from_der(&der).expect("parses")
}

/// MIK-8286 R1a: a certificate with neither a SAN URI nor a CN has no grant
/// subject, rather than the display-name placeholder every such certificate
/// shares; one with either keeps its subject byte for byte. Mutant: the
/// display-name fallback restored.
#[test]
fn a_certificate_naming_no_subject_has_no_grant_subject() {
    assert_eq!(grant_subject_from_cert_identity(&leaf(None, None)), None);
    let by_cn = grant_subject_from_cert_identity(&leaf(Some("agent-a"), None)).unwrap();
    assert_eq!(
        (by_cn.authority.as_str(), by_cn.subject.as_str()),
        ("mtls", "agent-a")
    );
    let uri = "spiffe://example.test/agent/b";
    let by_uri = grant_subject_from_cert_identity(&leaf(None, Some(uri))).unwrap();
    assert_eq!(
        (by_uri.authority.as_str(), by_uri.subject.as_str()),
        ("mtls", uri)
    );
}

/// MIK-8286 R8 (pins): a certificate that names its subject keeps today's
/// grant subject, subject key and caller key byte for byte, so no stored key
/// moves. Literals copied from the code before the change.
#[test]
fn a_named_certificate_keeps_its_keys_byte_for_byte() {
    let cert = leaf(Some("agent-a"), None);
    let subject = grant_subject_from_cert_identity(&cert).unwrap();
    assert_eq!(
        subject_key(Some(&subject), Some(&cert)).as_deref(),
        Some("subject:4:mtls:7:agent-a")
    );
    assert_eq!(
        caller_key(Some(&subject), Some(&cert), None),
        "subject:4:mtls:7:agent-a"
    );
}
