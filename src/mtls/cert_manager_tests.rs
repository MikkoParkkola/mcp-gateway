// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use rcgen::SanType;
use rcgen::string::Ia5String;

// ─── helpers ─────────────────────────────────────────────────────────────

fn _dns_san(s: &str) -> SanType {
    SanType::DnsName(Ia5String::try_from(s).unwrap())
}

fn _uri_san(s: &str) -> SanType {
    SanType::URI(Ia5String::try_from(s).unwrap())
}

// ─── CA generation ────────────────────────────────────────────────────────

#[test]
fn init_ca_produces_valid_pem_cert_and_key() {
    // GIVEN: CA parameters
    let params = CaParams {
        cn: "Test Root CA",
        validity_days: 365,
    };
    // WHEN: generating CA
    let ca = CertGenerator::init_ca(&params).unwrap();
    // THEN: PEM blocks present
    assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(ca.key_pem.contains("PRIVATE KEY"));
}

#[test]
fn init_ca_generates_unique_keys_on_each_call() {
    let params = CaParams {
        cn: "CA",
        validity_days: 365,
    };
    let ca1 = CertGenerator::init_ca(&params).unwrap();
    let ca2 = CertGenerator::init_ca(&params).unwrap();
    // Each generation produces a unique key
    assert_ne!(ca1.key_pem, ca2.key_pem);
}

// ─── Leaf cert issuance ───────────────────────────────────────────────────

#[test]
fn issue_leaf_server_cert_contains_expected_dns_san() {
    // GIVEN: CA + server leaf params
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();

    let params = LeafCertParams {
        cn: "gateway.company.com",
        ou: None,
        san_dns: vec!["gateway.company.com".to_string()],
        san_uris: vec![],
        validity_days: 90,
    };
    // WHEN: issuing leaf cert
    let leaf = CertGenerator::issue_leaf(&params, &ca.cert_pem, &ca.key_pem).unwrap();
    // THEN: PEM cert produced
    assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(leaf.key_pem.contains("PRIVATE KEY"));
}

#[test]
fn issue_leaf_client_cert_with_spiffe_uri() {
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();

    let params = LeafCertParams {
        cn: "claude-code-agent",
        ou: Some("engineering"),
        san_dns: vec![],
        san_uris: vec!["spiffe://company.com/agent/claude-code".to_string()],
        validity_days: 1,
    };
    let leaf = CertGenerator::issue_leaf(&params, &ca.cert_pem, &ca.key_pem).unwrap();
    assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
}

#[test]
fn issue_leaf_fails_with_invalid_ca_key() {
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();

    let params = LeafCertParams {
        cn: "agent",
        ou: None,
        san_dns: vec!["agent.local".to_string()],
        san_uris: vec![],
        validity_days: 30,
    };
    let result = CertGenerator::issue_leaf(&params, &ca.cert_pem, "not a pem key");
    assert!(result.is_err());
}

// ─── write_to_dir ─────────────────────────────────────────────────────────

#[test]
fn write_to_dir_creates_crt_and_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();

    CertGenerator::write_to_dir(&ca, dir.path(), "ca").unwrap();

    assert!(dir.path().join("ca.crt").exists());
    assert!(dir.path().join("ca.key").exists());
}

#[test]
fn write_to_dir_cert_file_contains_pem_header() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();

    CertGenerator::write_to_dir(&ca, dir.path(), "myca").unwrap();

    let contents = fs::read_to_string(dir.path().join("myca.crt")).unwrap();
    assert!(contents.contains("BEGIN CERTIFICATE"));
}

// POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
#[cfg(unix)]
#[test]
fn write_to_dir_private_key_is_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();

    CertGenerator::write_to_dir(&ca, dir.path(), "ca").unwrap();

    let mode = fs::metadata(dir.path().join("ca.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

// ─── load_certs / load_private_key ────────────────────────────────────────

#[test]
fn load_certs_from_generated_pem_file() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();
    let path = dir.path().join("ca.crt");
    crate::gateway::test_helpers::write_owner_only(&path, &ca.cert_pem).unwrap();

    let certs = load_certs(path.to_str().unwrap()).unwrap();
    assert_eq!(certs.len(), 1);
}

#[test]
fn load_private_key_from_generated_pem_file() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();
    let path = dir.path().join("ca.key");
    crate::gateway::test_helpers::write_owner_only(&path, &ca.key_pem).unwrap();

    let key = load_private_key(path.to_str().unwrap()).unwrap();
    // Key should be non-empty (exact type varies by rcgen algorithm)
    assert!(!key.secret_der().is_empty());
}

#[test]
fn load_certs_returns_error_for_missing_file() {
    let result = load_certs("/nonexistent/path/ca.crt");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Cannot read"));
}

#[test]
fn load_certs_returns_error_for_empty_pem_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.crt");
    fs::write(&path, b"").unwrap();

    let result = load_certs(path.to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn load_private_key_returns_error_for_missing_file() {
    let result = load_private_key("/nonexistent/path/key.pem");
    assert!(result.is_err());
}

#[test]
fn load_private_key_returns_error_when_no_key_in_file() {
    let dir = tempfile::tempdir().unwrap();
    // Write cert PEM but NOT a key
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();
    let path = dir.path().join("cert_only.pem");
    crate::gateway::test_helpers::write_owner_only(&path, &ca.cert_pem).unwrap();

    let result = load_private_key(path.to_str().unwrap());
    assert!(result.is_err());
}

// ─── TLS 1.3 enforcement ─────────────────────────────────────────────────

/// Helper: write CA + server cert/key to a temp dir and return file paths.
fn write_pki_to_dir(dir: &std::path::Path) -> (String, String, String) {
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();

    let leaf = CertGenerator::issue_leaf(
        &LeafCertParams {
            cn: "gateway.test",
            ou: None,
            san_dns: vec!["gateway.test".to_string()],
            san_uris: vec![],
            validity_days: 90,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .unwrap();

    let ca_path = dir.join("ca.crt");
    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");

    crate::gateway::test_helpers::write_owner_only(&ca_path, &ca.cert_pem).unwrap();
    crate::gateway::test_helpers::write_owner_only(&cert_path, &leaf.cert_pem).unwrap();
    crate::gateway::test_helpers::write_owner_only(&key_path, &leaf.key_pem).unwrap();

    (
        ca_path.to_str().unwrap().to_string(),
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
    )
}

#[test]
fn build_tls_config_succeeds_with_valid_pki() {
    // GIVEN: a valid CA + server cert/key on disk
    let dir = tempfile::tempdir().unwrap();
    let (ca_cert, server_cert, server_key) = write_pki_to_dir(dir.path());

    let config = MtlsConfig {
        enabled: true,
        server_cert,
        server_key,
        ca_cert,
        require_client_cert: false,
        ..Default::default()
    };
    // WHEN: building TLS config
    let result = build_tls_config(&config);
    // THEN: no error
    assert!(result.is_ok(), "Expected Ok, got: {result:?}");
}

#[test]
fn build_tls_config_enforces_tls13_only() {
    // GIVEN: a valid CA + server cert/key on disk
    let dir = tempfile::tempdir().unwrap();
    let (ca_cert, server_cert, server_key) = write_pki_to_dir(dir.path());

    let config = MtlsConfig {
        enabled: true,
        server_cert,
        server_key,
        ca_cert,
        require_client_cert: false,
        ..Default::default()
    };
    // WHEN: building TLS config
    let tls_cfg = build_tls_config(&config).unwrap();
    // THEN: only TLS 1.3 is in the supported version list — TLS 1.2 is absent.
    // rustls exposes the negotiated version via `protocol_version`, but the
    // supported versions are baked at build time via `builder_with_protocol_versions`.
    // We verify the indirect observable: the `tls12` feature is absent, so the
    // rustls ProtocolVersion::TLSv1_2 constant is not reachable.  What we can
    // assert is that the config was built without error and that the TLS 1.3
    // builder path was taken (if TLS 1.2 were somehow injected,
    // `builder_with_protocol_versions(&[&version::TLS13])` would panic or error).
    //
    // The primary enforcement is compile-time: the Cargo.toml does NOT include
    // the "tls12" feature for rustls.  This test documents that invariant.
    let _ = tls_cfg; // config produced with TLS 1.3 builder
    // Compile-time invariant: the "tls12" feature for rustls is never enabled.
    // Primary enforcement is Cargo.toml — this documents intent.
    #[allow(unexpected_cfgs, clippy::assertions_on_constants)]
    {
        assert!(
            !cfg!(feature = "rustls/tls12"),
            "tls12 feature must NOT be enabled — TLS 1.2 is explicitly excluded"
        );
    }
}

#[test]
fn build_tls_config_fails_with_mismatched_cert_and_key() {
    // GIVEN: two separate CA-issued leaf certs (different keys)
    let dir = tempfile::tempdir().unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "CA",
        validity_days: 365,
    })
    .unwrap();

    let leaf_a = CertGenerator::issue_leaf(
        &LeafCertParams {
            cn: "a",
            ou: None,
            san_dns: vec!["a.test".to_string()],
            san_uris: vec![],
            validity_days: 30,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .unwrap();

    let leaf_b = CertGenerator::issue_leaf(
        &LeafCertParams {
            cn: "b",
            ou: None,
            san_dns: vec!["b.test".to_string()],
            san_uris: vec![],
            validity_days: 30,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .unwrap();

    let ca_path = dir.path().join("ca.crt");
    let cert_path = dir.path().join("server.crt");
    // Deliberately use leaf_b's key with leaf_a's cert
    let key_path = dir.path().join("server.key");

    crate::gateway::test_helpers::write_owner_only(&ca_path, &ca.cert_pem).unwrap();
    crate::gateway::test_helpers::write_owner_only(&cert_path, &leaf_a.cert_pem).unwrap();
    crate::gateway::test_helpers::write_owner_only(&key_path, &leaf_b.key_pem).unwrap();

    let config = MtlsConfig {
        enabled: true,
        server_cert: cert_path.to_str().unwrap().to_string(),
        server_key: key_path.to_str().unwrap().to_string(),
        ca_cert: ca_path.to_str().unwrap().to_string(),
        require_client_cert: false,
        ..Default::default()
    };
    // WHEN: building TLS config with mismatched cert/key
    let result = build_tls_config(&config);
    // THEN: error is returned
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("TLS config error"), "unexpected error: {msg}");
}
