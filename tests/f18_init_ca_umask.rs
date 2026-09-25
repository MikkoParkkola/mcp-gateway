// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 A1: under umask 002 the certificates `tls init-ca` and `tls issue-server`
//! write must still pass the gateway's own integrity rule on the serve path.
//!
//! The umask is set in a child shell, never here: `umask(2)` is process-wide and
//! would race every other test that creates a file.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use mcp_gateway::mtls::MtlsConfig;
use mcp_gateway::mtls::cert_manager::build_tls_config;

/// Run the gateway binary under umask 002 with `args`.
fn gateway_umask_002(args: &[&str]) {
    let status = Command::new("sh")
        .arg("-c")
        .arg("umask 002; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(args)
        .status()
        .expect("run mcp-gateway");
    assert!(status.success(), "mcp-gateway {args:?} failed: {status}");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_ca_output_serves_under_umask_002() {
    let dir = tempfile::tempdir().unwrap();
    let tls = dir.path().join("tls");
    let tls_s = tls.to_str().unwrap();
    let (ca_crt, ca_key) = (format!("{tls_s}/ca.crt"), format!("{tls_s}/ca.key"));
    gateway_umask_002(&["tls", "init-ca", "--cn", "umask CA", "--out", tls_s]);
    gateway_umask_002(&[
        "tls", "issue-server", "--ca-cert", &ca_crt, "--ca-key", &ca_key, "--cn", "localhost",
        "--san-dns", "localhost", "--out", tls_s,
    ]);

    for (file, want) in [("ca.crt", 0o644), ("server.crt", 0o644), ("ca.key", 0o600), ("server.key", 0o600)] {
        assert_eq!(mode(&tls.join(file)), want, "{file}");
    }
    let config = MtlsConfig {
        enabled: true,
        server_cert: format!("{tls_s}/server.crt"),
        server_key: format!("{tls_s}/server.key"),
        ca_cert: ca_crt,
        require_client_cert: true,
        ..Default::default()
    };
    if let Err(e) = build_tls_config(&config) {
        panic!("serve refused the gateway's own tls output: {e}");
    }
}
