// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 R6: `tls issue-server` reads the CA key through the library's
//! mode-checked loader, refuses one other users can read, and the re-encoded
//! key still signs a leaf that chains to the CA.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use super::{tls_init_ca, tls_issue_server};

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn issue(dir: &Path) -> ExitCode {
    tls_issue_server(
        &dir.join("ca.crt"),
        &dir.join("ca.key"),
        "gateway.test",
        "gateway.test",
        30,
        &dir.join("out"),
    )
}

#[test]
fn tls_issue_server_refuses_loose_ca_key() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(tls_init_ca("CA", 365, dir.path()), ExitCode::SUCCESS);
    chmod(&dir.path().join("ca.key"), 0o644);
    assert_eq!(issue(dir.path()), ExitCode::FAILURE);
    assert!(
        !dir.path().join("out").join("server.key").exists(),
        "nothing issued"
    );
}

#[test]
fn tls_issue_server_accepts_init_ca_output() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(tls_init_ca("CA", 365, dir.path()), ExitCode::SUCCESS);
    // The CA cert is not mode-checked at all, not even for integrity: a
    // tampered cert yields a leaf that does not chain to the CA the server trusts.
    chmod(&dir.path().join("ca.crt"), 0o666);
    assert_eq!(issue(dir.path()), ExitCode::SUCCESS);
    assert_eq!(mode(&dir.path().join("out").join("server.key")), 0o600);
}

#[test]
fn tls_issue_server_reencoded_key_signs() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(tls_init_ca("CA", 365, dir.path()), ExitCode::SUCCESS);
    assert_eq!(issue(dir.path()), ExitCode::SUCCESS);
    let ca = CertificateDer::from_pem_file(dir.path().join("ca.crt")).unwrap();
    let leaf = CertificateDer::from_pem_file(dir.path().join("out").join("server.crt")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .unwrap();
    verifier
        .verify_server_cert(
            &leaf,
            &[],
            &ServerName::try_from("gateway.test").unwrap(),
            &[],
            UnixTime::now(),
        )
        .expect("the leaf chains to the CA the key belongs to");
}
