// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A client certificate the TLS layer accepted but that names no one (no
//! SAN URI, no CN) yields no identity, so the request takes the
//! unauthenticated path; it neither drops the connection nor becomes a
//! nameless identity.

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::CertificateDer;

use super::client_identity_from_peer_chain;

fn self_signed(edit: impl FnOnce(&mut CertificateParams)) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    edit(&mut params);
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().clone()
}

#[test]
fn a_dns_only_certificate_yields_no_identity() {
    let leaf = self_signed(|p| {
        p.subject_alt_names = vec![SanType::DnsName("client.example".try_into().unwrap())];
    });
    let identity = client_identity_from_peer_chain(Some(&[leaf]))
        .expect("a parseable certificate keeps the connection");
    assert!(
        identity.is_none(),
        "a certificate naming no one is no identity: {identity:?}"
    );
}

#[test]
fn a_certificate_with_a_common_name_still_yields_its_identity() {
    let leaf = self_signed(|p| {
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "client");
    });
    let identity = client_identity_from_peer_chain(Some(&[leaf])).expect("parses");
    assert!(identity.is_some(), "a named certificate keeps its identity");
}
