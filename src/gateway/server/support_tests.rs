// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use std::convert::Infallible;
use std::future::{Ready, ready};

use axum::http::Request;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

fn spiffe_leaf_der(uri: &str) -> Vec<u8> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-agent");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];

    let key_pair = KeyPair::generate().expect("key generation failed");
    params
        .self_signed(&key_pair)
        .expect("cert generation failed")
        .der()
        .to_vec()
}

#[test]
fn peer_chain_identity_extracts_spiffe_svid_leaf() {
    let leaf = CertificateDer::from(spiffe_leaf_der("spiffe://example.test/agent/alpha"));
    let identity = client_identity_from_peer_chain(Some(&[leaf]))
        .expect("peer chain should parse")
        .expect("identity should be present");

    assert_eq!(identity.san_uris, vec!["spiffe://example.test/agent/alpha"]);
    assert_eq!(identity.display_name, "spiffe://example.test/agent/alpha");
}

#[test]
fn peer_chain_identity_is_absent_without_client_certificate() {
    let identity = client_identity_from_peer_chain(None).expect("missing chain is allowed");
    assert!(identity.is_none());

    let empty_identity =
        client_identity_from_peer_chain(Some(&[])).expect("empty chain is allowed");
    assert!(empty_identity.is_none());
}

#[test]
fn peer_chain_identity_rejects_malformed_certificate() {
    let malformed = CertificateDer::from(vec![0, 1, 2, 3]);

    let error = client_identity_from_peer_chain(Some(&[malformed]))
        .expect_err("malformed peer certificate must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn peer_cert_identity_service_inserts_identity_extension() {
    let identity = CertIdentity {
        san_uris: vec!["spiffe://example.test/agent/alpha".to_owned()],
        display_name: "spiffe://example.test/agent/alpha".to_owned(),
        ..CertIdentity::default()
    };
    let mut service = PeerCertIdentityLayer::new(Some(identity.clone())).layer(EchoIdentity);

    let inserted_identity = futures::executor::block_on(service.call(Request::new(())))
        .expect("echo service should not fail");

    assert_eq!(inserted_identity, Some(identity));
}

#[derive(Clone)]
struct EchoIdentity;

impl Service<Request<()>> for EchoIdentity {
    type Response = Option<CertIdentity>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<()>) -> Self::Future {
        ready(Ok(request.extensions().get::<CertIdentity>().cloned()))
    }
}

/// The banner refuses the plain-HTTP link for an HTTPS `public_url` in any
/// letter case, matching the cookie's `Secure` decision.
#[test]
fn an_uppercase_https_public_url_refuses_the_banner_link() {
    let mut config = Config::default();
    config.server.public_url = Some("HTTPS://Gateway.Example".to_string());
    assert!(dashboard_link_refusal(&config).is_some());
    config.server.public_url = Some("http://gateway.example".to_string());
    assert!(dashboard_link_refusal(&config).is_none());
}
