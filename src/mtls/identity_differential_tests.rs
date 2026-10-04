// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C6 startup SAMPLE rank 1 (`PeerCertIdentityAcceptor::accept`): no client
//! leaf that Rustls/webpki accepts is one `CertIdentity::from_der` rejects.
//! The acceptor refuses the connection on a parse failure, so such a leaf
//! would lock out a client the TLS layer trusted; this pins that none of the
//! bounded unusual-but-signable leaves below does.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, BmpString, CertificateParams, CustomExtension, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType, SerialNumber, UniversalString,
};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;

use super::CertIdentity;

/// A leaf with the usual client-auth shape; `edit` makes it unusual.
fn leaf(edit: impl FnOnce(&mut CertificateParams)) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String("client".into()));
    params.subject_alt_names = vec![SanType::DnsName("client.example".try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    edit(&mut params);
    params
}

fn custom(oid: &[u64], content: &[u8], critical: bool) -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(oid, content.to_vec());
    extension.set_criticality(critical);
    extension
}

const SAN: &[u64] = &[2, 5, 29, 17];

#[test]
fn no_leaf_webpki_accepts_is_one_the_identity_parser_rejects() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "differential CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .unwrap();

    let candidates: Vec<(&str, CertificateParams)> = vec![
        ("baseline", leaf(|_| {})),
        (
            "CN as BMPString (not UTF-8)",
            leaf(|p| {
                p.distinguished_name = rcgen::DistinguishedName::new();
                p.distinguished_name.push(
                    DnType::CommonName,
                    DnValue::BmpString(BmpString::try_from("cliënt").unwrap()),
                );
            }),
        ),
        (
            "CN as UniversalString (not UTF-8)",
            leaf(|p| {
                p.distinguished_name = rcgen::DistinguishedName::new();
                p.distinguished_name.push(
                    DnType::CommonName,
                    DnValue::UniversalString(UniversalString::try_from("cliënt").unwrap()),
                );
            }),
        ),
        (
            "CN of 60000 bytes",
            leaf(|p| {
                p.distinguished_name = rcgen::DistinguishedName::new();
                p.distinguished_name
                    .push(DnType::CommonName, "c".repeat(60_000));
            }),
        ),
        (
            "empty SAN extension",
            leaf(|p| {
                p.subject_alt_names = vec![];
                p.custom_extensions = vec![custom(SAN, &[0x30, 0x00], false)];
            }),
        ),
        (
            "malformed SAN extension",
            leaf(|p| {
                p.subject_alt_names = vec![];
                p.custom_extensions = vec![custom(SAN, &[0x30, 0x05, 0x82, 0x09, 0x41], false)];
            }),
        ),
        (
            "unknown critical extension",
            leaf(|p| p.custom_extensions = vec![custom(&[1, 3, 6, 1, 4, 1, 99999, 1], &[0x05, 0x00], true)]),
        ),
        (
            "unknown non-critical extension",
            leaf(|p| p.custom_extensions = vec![custom(&[1, 3, 6, 1, 4, 1, 99999, 2], &[0x05, 0x00], false)]),
        ),
        (
            "negative serial",
            leaf(|p| p.serial_number = Some(SerialNumber::from_slice(&[0x80, 0x01]))),
        ),
        (
            "21-byte serial (over the 20-octet limit)",
            leaf(|p| p.serial_number = Some(SerialNumber::from_slice(&[0x01; 21]))),
        ),
        (
            "64-byte serial",
            leaf(|p| p.serial_number = Some(SerialNumber::from_slice(&[0x01; 64]))),
        ),
    ];

    let mut split = Vec::new();
    for (name, params) in candidates {
        let key = KeyPair::generate().unwrap();
        let der: CertificateDer<'static> = match params.signed_by(&key, &issuer) {
            Ok(cert) => cert.der().clone(),
            Err(error) => {
                eprintln!("{name:42} | not signable by rcgen: {error}");
                continue;
            }
        };
        let webpki = verifier.verify_client_cert(&der, &[], UnixTime::now());
        let parsed = CertIdentity::from_der(der.as_ref());
        eprintln!(
            "{name:42} | webpki {:8} | from_der {:8} | cn {:?}",
            if webpki.is_ok() { "accepts" } else { "refuses" },
            if parsed.is_ok() { "parses" } else { "rejects" },
            parsed.as_ref().ok().and_then(|identity| identity.common_name.clone()),
        );
        if webpki.is_ok() && parsed.is_err() {
            split.push(name);
        }
    }
    assert!(
        split.is_empty(),
        "accepted by webpki, rejected by from_der: {split:?}"
    );
}
