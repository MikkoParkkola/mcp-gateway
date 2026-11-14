// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one CA bundle a preview's package fetch trusts (the CA amendment to
//! ADR-027's fetch step): chosen on the gateway's side, read once from one
//! descriptor, and snapshotted by its bytes into the preview's private
//! directory, which the helper binds read-only into the sandbox root.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the helper's fetch step binds it (the sandbox fetch part)"
    )
)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use super::super::Refusal;

/// The largest bundle accepted, in bytes.
pub(super) const MAX_BUNDLE: usize = 4 << 20;

/// The distros' bundle files, in the order tried when `SSL_CERT_FILE` is unset.
pub(super) const DISTRO_BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// The `SSL_CERT_FILE` value `lookup` gives, passed on as given (a value that
/// is not UTF-8 included): production calls it with `std::env::var_os`.
pub(super) fn ambient_ca_bundle(lookup: impl Fn(&str) -> Option<OsString>) -> Option<OsString> {
    let _ = lookup;
    None
}

/// The chosen bundle: the bytes read and validated, and where they came from.
#[derive(Debug)]
pub(super) struct HostBundle {
    pub(super) bytes: Vec<u8>,
    pub(super) source: PathBuf,
}

impl HostBundle {
    /// Choose the bundle: `ca_bundle` (the `SSL_CERT_FILE` value) when set,
    /// else the first distro path that exists under `root` (`/` in
    /// production). An existing candidate that fails any check refuses: there
    /// is no fall-through.
    pub(super) fn choose(ca_bundle: Option<&OsStr>, root: &Path) -> Result<Self, Refusal> {
        // Red stub: the first readable candidate, unchecked.
        let candidates: Vec<PathBuf> = match ca_bundle {
            Some(value) => vec![PathBuf::from(value)],
            None => DISTRO_BUNDLES
                .iter()
                .map(|p| root.join(p.trim_start_matches('/')))
                .collect(),
        };
        for path in candidates {
            if let Ok(bytes) = std::fs::read(&path) {
                return Ok(Self {
                    bytes,
                    source: path,
                });
            }
        }
        Err(Refusal::Step("no CA bundle on this host".into()))
    }
}

/// Write `bytes` as the preview's CA snapshot `ca.pem` in `dir`.
pub(super) fn write_snapshot(dir: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    // Red stub: a plain write, neither exclusive nor read-only.
    let path = dir.join("ca.pem");
    std::fs::write(&path, bytes)?;
    Ok(path)
}

#[cfg(test)]
#[path = "ca_bundle_tests.rs"]
mod tests;
