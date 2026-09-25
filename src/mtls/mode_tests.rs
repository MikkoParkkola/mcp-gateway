// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 R1, I1, I2: the TLS key may not be readable by others; the server cert,
//! client CA and CRL may be read by others but not changed by them.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::cert_manager::{
    CaParams, CertGenerator, LeafCertParams, build_tls_config, load_private_key,
};
use super::config::MtlsConfig;

fn write_mode(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// CA, server cert and key under `dir` at the given modes; the config naming them.
fn pki(dir: &Path, ca: u32, cert: u32, key: u32) -> MtlsConfig {
    let ca_pem = CertGenerator::init_ca(&CaParams {
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
        &ca_pem.cert_pem,
        &ca_pem.key_pem,
    )
    .unwrap();
    let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
    write_mode(&dir.join("ca.crt"), &ca_pem.cert_pem, ca);
    write_mode(&dir.join("server.crt"), &leaf.cert_pem, cert);
    write_mode(&dir.join("server.key"), &leaf.key_pem, key);
    MtlsConfig {
        enabled: true,
        server_cert: path("server.crt"),
        server_key: path("server.key"),
        ca_cert: path("ca.crt"),
        require_client_cert: false,
        ..Default::default()
    }
}

fn refusal(config: &MtlsConfig) -> String {
    build_tls_config(config).expect_err("refused").to_string()
}

#[test]
fn tls_key_world_readable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o644, 0o644, 0o644);
    let err = load_private_key(&config.server_key)
        .expect_err("0644 key refused")
        .to_string();
    assert!(
        err.contains("TLS private key")
            && err.contains("mode 0644")
            && err.contains(&config.server_key),
        "{err}"
    );
}

#[test]
fn tls_key_group_readable_owned_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o644, 0o644, 0o640);
    let err = load_private_key(&config.server_key)
        .expect_err("0640 own key refused")
        .to_string();
    assert!(err.contains("lets group"), "{err}");
}

#[test]
fn tls_key_owner_only_loads() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o644, 0o644, 0o600);
    assert!(load_private_key(&config.server_key).is_ok());
}

#[test]
fn build_tls_config_refuses_loose_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o644, 0o644, 0o644);
    let err = refusal(&config);
    assert!(
        err.contains(&config.server_key) && err.contains("TLS private key"),
        "{err}"
    );
}

#[test]
fn tls_cert_and_ca_readable_load() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = pki(dir.path(), 0o644, 0o644, 0o600);
    // Public material: 0644 loads. An empty CRL may or may not parse; either
    // way, a 0644 CRL is not refused for its mode.
    write_mode(&dir.path().join("crl.pem"), "", 0o644);
    config.crl_path = Some(dir.path().join("crl.pem").to_str().unwrap().to_string());
    let without_crl = MtlsConfig {
        crl_path: None,
        ..config.clone()
    };
    build_tls_config(&without_crl).expect("0644 cert and CA load");
    if let Err(e) = build_tls_config(&config) {
        assert!(
            !e.to_string().contains("Refusing"),
            "a 0644 CRL is not mode-refused: {e}"
        );
    }
}

#[test]
fn tls_ca_group_writable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o664, 0o644, 0o600);
    let err = refusal(&config);
    assert!(
        err.contains("TLS certificate") && err.contains("change it") && err.contains("chmod go-w"),
        "{err}"
    );
    assert!(!err.contains("chmod 600"), "{err}");
}

#[test]
fn tls_server_cert_world_writable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = pki(dir.path(), 0o644, 0o646, 0o600);
    let err = refusal(&config);
    assert!(err.contains("lets other users change it"), "{err}");
}

#[test]
fn tls_crl_group_writable_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = pki(dir.path(), 0o644, 0o644, 0o600);
    write_mode(&dir.path().join("crl.pem"), "", 0o664);
    config.crl_path = Some(dir.path().join("crl.pem").to_str().unwrap().to_string());
    let err = refusal(&config);
    assert!(err.contains("certificate revocation list"), "{err}");
}

/// F18 A1: rewriting over a cert that umask 002 left `0664` must leave `0644`,
/// or the gateway's own `serve` refuses the output of its own `tls` commands.
#[test]
fn write_to_dir_overwrites_loose_cert_to_0644() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tls");
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();
    std::fs::create_dir_all(&out).unwrap();
    write_mode(&out.join("x.crt"), "stale", 0o664);
    CertGenerator::write_to_dir(&ca, &out, "x").unwrap();
    let mode = std::fs::metadata(out.join("x.crt")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}
