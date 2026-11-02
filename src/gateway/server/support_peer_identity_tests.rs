// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A client certificate the TLS layer accepted but that names no one (no SAN
//! URI, no CN) is no identity: the peer chain yields `Nameless`, and the
//! identity layer refuses the connection's requests exactly as before (401,
//! -32000), so it is never served as "no certificate" or as a nameless
//! identity.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::CertificateDer;
use tower::{Layer, ServiceExt};

use super::{PeerCert, PeerCertIdentityLayer, client_identity_from_peer_chain};

fn self_signed(edit: impl FnOnce(&mut CertificateParams)) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    edit(&mut params);
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().clone()
}

fn dns_only() -> CertificateDer<'static> {
    self_signed(|p| {
        p.subject_alt_names = vec![SanType::DnsName("client.example".try_into().unwrap())];
    })
}

#[test]
fn a_dns_only_certificate_is_nameless() {
    let peer = client_identity_from_peer_chain(Some(&[dns_only()]))
        .expect("a parseable certificate keeps the connection");
    assert!(matches!(peer, PeerCert::Nameless), "{peer:?}");
}

#[test]
fn a_certificate_with_a_common_name_is_named() {
    let leaf = self_signed(|p| {
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "client");
    });
    let peer = client_identity_from_peer_chain(Some(&[leaf])).expect("parses");
    assert!(matches!(peer, PeerCert::Named(_)), "{peer:?}");
}

#[tokio::test]
async fn a_nameless_peer_never_reaches_the_inner_service() {
    let reached = Arc::new(AtomicUsize::new(0));
    let spy = Arc::clone(&reached);
    let inner = axum::Router::new().route(
        "/health",
        axum::routing::get(move || {
            spy.fetch_add(1, Ordering::SeqCst);
            async { "ok" }
        }),
    );
    let peer = client_identity_from_peer_chain(Some(&[dns_only()])).unwrap();
    let app = PeerCertIdentityLayer::new(peer).layer(inner);
    let request = axum::http::Request::get("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(reached.load(Ordering::SeqCst), 0, "nothing inside ran");
}
