// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7212.TLSCERT.1–2: inspect actual generated X.509 extensions.

use mcp_gateway::mtls::{CaParams, CertGenerator, GeneratedCert, LeafCertParams};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

fn inspect<T>(pem: &str, check: impl FnOnce(&X509Certificate<'_>) -> T) -> T {
    let (remaining, pem) = parse_x509_pem(pem.as_bytes()).expect("certificate PEM");
    assert!(remaining.iter().all(u8::is_ascii_whitespace));
    let (remaining, cert) = X509Certificate::from_der(&pem.contents).expect("certificate DER");
    assert!(remaining.is_empty(), "unparsed certificate bytes");
    check(&cert)
}

fn generated_ca() -> GeneratedCert {
    CertGenerator::init_ca(&CaParams {
        cn: "TLSCERT regression CA",
        validity_days: 30,
    })
    .unwrap()
}

fn issuer_key_id(ca: &GeneratedCert) -> Vec<u8> {
    inspect(&ca.cert_pem, |cert| {
        let extension = cert
            .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .unwrap()
            .expect("issuer must carry SKI");
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => id.0.to_vec(),
            other => panic!("malformed issuer SKI: {other:?}"),
        }
    })
}

fn external_ca() -> GeneratedCert {
    let key = KeyPair::generate().unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "External TLSCERT CA");
    let expected_id = vec![0xa7; 20];
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Deliberately differs from rcgen's default public-key digest.
    params.key_identifier_method = KeyIdMethod::PreSpecified(expected_id.clone());
    let ca = GeneratedCert {
        cert_pem: params.self_signed(&key).unwrap().pem(),
        key_pem: key.serialize_pem(),
    };
    assert_eq!(
        issuer_key_id(&ca),
        expected_id,
        "external fixture precondition"
    );
    ca
}

fn check_leaf(ca: &GeneratedCert, server: bool) {
    let expected_id = issuer_key_id(ca);
    assert!(!expected_id.is_empty());
    let params = LeafCertParams {
        cn: if server {
            "localhost"
        } else {
            "tls-test-agent"
        },
        ou: Some("engineering"),
        san_dns: if server {
            vec!["localhost".into()]
        } else {
            vec![]
        },
        san_uris: if server {
            vec![]
        } else {
            vec!["spiffe://tlscert.test/agent".into()]
        },
        validity_days: 7,
    };
    let leaf = CertGenerator::issue_leaf(&params, &ca.cert_pem, &ca.key_pem).unwrap();
    inspect(&leaf.cert_pem, |cert| {
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            params.cn
        );
        assert_eq!(
            cert.subject()
                .iter_organizational_unit()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "engineering"
        );
        let sans = &cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names;
        let expected_sans = if server {
            vec![GeneralName::DNSName("localhost")]
        } else {
            vec![GeneralName::URI("spiffe://tlscert.test/agent")]
        };
        assert_eq!(*sans, expected_sans, "leaf identity must be preserved");
        let extension = cert
            .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .unwrap()
            .expect("MIK-7212.TLSCERT.2: CA-issued leaf is missing AKI");
        assert!(!extension.critical, "AKI must be noncritical");
        match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(id) => {
                assert_eq!(
                    id.key_identifier.as_ref().expect("AKI keyIdentifier").0,
                    expected_id,
                    "AKI must reuse this issuer's actual SKI"
                );
            }
            other => panic!("malformed leaf AKI: {other:?}"),
        }
    });
}

#[test]
fn generated_ca_has_critical_certificate_and_crl_signing_usage() {
    // MIK-7212.TLSCERT.1
    inspect(&generated_ca().cert_pem, |cert| {
        let usage = cert
            .key_usage()
            .unwrap()
            .expect("MIK-7212.TLSCERT.1: generated CA is missing key usage");
        assert!(usage.critical, "CA key usage must be critical");
        assert!(usage.value.key_cert_sign());
        assert!(usage.value.crl_sign());
        assert_eq!(usage.value.flags, 0x60, "do not grant unrelated key usages");
        assert!(cert.basic_constraints().unwrap().unwrap().value.ca);
    });
}

#[test]
fn generated_ca_server_leaf_has_issuer_bound_noncritical_aki() {
    check_leaf(&generated_ca(), true);
}

#[test]
fn generated_ca_client_leaf_has_issuer_bound_noncritical_aki() {
    check_leaf(&generated_ca(), false);
}

#[test]
fn external_ca_server_leaf_reuses_prespecified_issuer_ski() {
    check_leaf(&external_ca(), true);
}

#[test]
fn external_ca_client_leaf_reuses_prespecified_issuer_ski() {
    check_leaf(&external_ca(), false);
}

/// The SANs of a server leaf issued with `san_dns`, in order, as text.
fn issued_sans(san_dns: &[&str]) -> Vec<String> {
    let ca = generated_ca();
    let params = LeafCertParams {
        cn: "gateway",
        ou: None,
        san_dns: san_dns.iter().map(ToString::to_string).collect(),
        san_uris: vec![],
        validity_days: 1,
    };
    let leaf = CertGenerator::issue_leaf(&params, &ca.cert_pem, &ca.key_pem).unwrap();
    inspect(&leaf.cert_pem, |cert| {
        let san = cert
            .subject_alternative_name()
            .unwrap()
            .expect("a SAN extension");
        san.value
            .general_names
            .iter()
            .map(|name| match name {
                GeneralName::DNSName(dns) => format!("dns:{dns}"),
                GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => format!(
                        "ip:{}",
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).unwrap())
                    ),
                    16 => format!(
                        "ip:{}",
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap())
                    ),
                    n => format!("ip:<{n} bytes>"),
                },
                other => format!("other:{other:?}"),
            })
            .collect()
    })
}

/// #1955: a TLS client dialling an address matches IP SANs only, so an IP
/// literal given as a "DNS" entry must be written as an IP SAN.
#[test]
fn an_ip_literal_in_san_dns_becomes_an_ip_san() {
    assert_eq!(
        issued_sans(&[
            "localhost",
            "127.0.0.1",
            "::1",
            "[::1]",
            "10.1.2.3",
            "fd00::1"
        ]),
        [
            "dns:localhost",
            "ip:127.0.0.1",
            "ip:::1",
            "ip:::1",
            "ip:10.1.2.3",
            "ip:fd00::1"
        ]
    );
}

/// Names stay DNS SANs, and so does anything that is not a plain IP literal:
/// brackets are an IPv6 spelling, `127.1` is not a dotted quad, and a zone id
/// has no IP SAN form.
#[test]
fn a_name_or_bracketed_v4_stays_a_dns_san() {
    assert_eq!(
        issued_sans(&["gateway.test", "[127.0.0.1]", "127.1", "fe80::1%eth0"]),
        [
            "dns:gateway.test",
            "dns:[127.0.0.1]",
            "dns:127.1",
            "dns:fe80::1%eth0"
        ]
    );
}

/// `--san-dns "localhost, 127.0.0.1"` is a natural way to type a list; the
/// space is not part of either entry.
#[test]
fn spaces_around_san_entries_are_ignored() {
    assert_eq!(
        issued_sans(&[" localhost", " 127.0.0.1 "]),
        ["dns:localhost", "ip:127.0.0.1"]
    );
}
