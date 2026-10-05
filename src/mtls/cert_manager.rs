// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Certificate management — loading, rustls config building, and CLI helpers.
//!
//! Provides:
//! - [`build_tls_config`] — build a `rustls::ServerConfig` from `MtlsConfig`
//! - [`load_certs`] / [`load_private_key`] — PEM file loading
//! - [`CertGenerator`] — `rcgen`-backed cert generation for `mcp-gateway tls` CLI commands
//!
//! # File format
//!
//! All certificate and key files are expected in **PEM format**.  DER is not
//! supported to keep operator tooling simple (openssl, cfssl, cert-manager all
//! default to PEM).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, version};
use tracing::debug;

use crate::mtls::config::MtlsConfig;
use crate::{Error, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Public: build TLS server config
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `rustls::ServerConfig` for mutual TLS from the gateway config.
///
/// When `config.require_client_cert` is `true`, clients without a valid
/// certificate signed by the configured CA are rejected at the TLS handshake.
///
/// When `config.require_client_cert` is `false`, client certificates are
/// requested but not required (TLS-only, no mutual auth).
///
/// # Security
///
/// TLS 1.3 is enforced as the minimum protocol version (PQC hardening, issue
/// #116).  TLS 1.2 is unconditionally rejected — the `tls12` rustls feature is
/// not compiled in and `with_protocol_versions` provides defense-in-depth.
///
/// # Errors
///
/// Returns an error if any certificate or key file cannot be read or parsed,
/// or if the rustls config cannot be built (e.g. mismatched cert/key pair).
pub fn build_tls_config(config: &MtlsConfig) -> Result<ServerConfig> {
    let server_certs = load_certs(&config.server_cert)?;
    let server_key = load_private_key(&config.server_key)?;
    let ca_certs = load_certs(&config.ca_cert)?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .map_err(|e| Error::Config(format!("Failed to add CA cert to trust store: {e}")))?;
    }

    let client_verifier = build_client_verifier(config, root_store)?;

    // Enforce TLS 1.3 minimum — defense-in-depth on top of the removed tls12 feature.
    let mut tls_cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| Error::Config(format!("TLS config error (cert/key mismatch?): {e}")))?;

    // Prefer HTTP/2, fall back to HTTP/1.1
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    debug!(
        server_cert = %config.server_cert,
        ca_cert = %config.ca_cert,
        require_client_cert = config.require_client_cert,
        "mTLS config built"
    );

    Ok(tls_cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: PEM loading
// ─────────────────────────────────────────────────────────────────────────────

/// Load all certificates from a PEM file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains no valid PEM
/// certificate blocks.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem_data = read_file(path, crate::config::CheckedFile::TlsCert)?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem_data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse certs from '{path}': {e}")))?;

    if certs.is_empty() {
        return Err(Error::Config(format!("No certificates found in '{path}'")));
    }

    Ok(certs)
}

/// Load the first private key from a PEM file.
///
/// Supports RSA (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`), and EC keys.
///
/// # Errors
///
/// Returns an error if the file cannot be read, contains no private key, or
/// the key format is unsupported.
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem_data = read_file(path, crate::config::CheckedFile::TlsKey)?;
    let key = PrivateKeyDer::from_pem_slice(pem_data.as_slice()).map_err(|e| {
        // NoItemsFound maps to the "no key" case; all other errors are parse failures.
        match e {
            rustls::pki_types::pem::Error::NoItemsFound => {
                Error::Config(format!("No private key found in '{path}'"))
            }
            other => Error::Config(format!(
                "Failed to parse private key from '{path}': {other}"
            )),
        }
    })?;

    Ok(key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: certificate generation (CLI helpers)
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for generating a CA certificate.
#[derive(Debug)]
pub struct CaParams<'a> {
    /// Common Name for the root CA (e.g. `"MCP Gateway Root CA"`).
    pub cn: &'a str,
    /// Validity period in days.
    pub validity_days: u32,
}

/// Parameters for generating a leaf certificate (server or client).
#[derive(Debug)]
pub struct LeafCertParams<'a> {
    /// Common Name.
    pub cn: &'a str,
    /// Organisational Unit (optional).
    pub ou: Option<&'a str>,
    /// Subject Alternative Names — DNS entries. An IP literal (`127.0.0.1`,
    /// `::1`, `[::1]`) is written as an IP SAN instead, which an mTLS policy's
    /// `san_dns` pattern does not match. Surrounding whitespace is ignored.
    pub san_dns: Vec<String>,
    /// Subject Alternative Names — URI entries (e.g. SPIFFE IDs).
    pub san_uris: Vec<String>,
    /// Validity period in days.
    pub validity_days: u32,
}

/// Generated certificate and key pair in PEM format.
#[derive(Debug)]
pub struct GeneratedCert {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

/// Certificate generator backed by `rcgen`.
///
/// Provides high-level wrappers for generating CA and leaf certificates
/// without requiring `openssl` or other external tools.
pub struct CertGenerator;

impl CertGenerator {
    /// Generate a self-signed CA certificate.
    ///
    /// The CA certificate can be used to sign server and client certificates
    /// via [`CertGenerator::issue_leaf`].
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or certificate serialisation fails.
    pub fn init_ca(params: &CaParams<'_>) -> Result<GeneratedCert> {
        let key_pair = KeyPair::generate()
            .map_err(|e| Error::Config(format!("Failed to generate CA key: {e}")))?;

        let mut ca_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, params.cn);
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.not_after = validity_to_date(params.validity_days)?;

        let ca_cert = ca_params
            .self_signed(&key_pair)
            .map_err(|e| Error::Config(format!("CA cert generation failed: {e}")))?;

        Ok(GeneratedCert {
            cert_pem: ca_cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// Issue a leaf certificate (server or client) signed by `ca_cert_pem` /
    /// `ca_key_pem`.
    ///
    /// # Errors
    ///
    /// Returns an error if the CA cert/key cannot be parsed, key generation
    /// fails, or certificate serialisation fails.
    pub fn issue_leaf(
        params: &LeafCertParams<'_>,
        ca_cert_pem: &str,
        ca_key_pem: &str,
    ) -> Result<GeneratedCert> {
        // Parse CA key pair
        let ca_key = KeyPair::from_pem(ca_key_pem)
            .map_err(|e| Error::Config(format!("Failed to parse CA key: {e}")))?;

        // Parse CA certificate + key into an Issuer for signing (rcgen 0.14 API)
        let ca_issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
            .map_err(|e| Error::Config(format!("Failed to parse CA cert: {e}")))?;

        // Build leaf params
        let leaf_key = KeyPair::generate()
            .map_err(|e| Error::Config(format!("Failed to generate leaf key: {e}")))?;

        let mut leaf_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, params.cn);
        if let Some(ou) = params.ou {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        leaf_params.distinguished_name = dn;
        leaf_params.not_after = validity_to_date(params.validity_days)?;
        leaf_params.use_authority_key_identifier_extension = true;

        leaf_params.subject_alt_names = super::san::leaf_sans(&params.san_dns, &params.san_uris)?;

        // rcgen 0.14: signed_by takes (&signing_key, &Issuer)
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .map_err(|e| Error::Config(format!("Leaf cert signing failed: {e}")))?;

        Ok(GeneratedCert {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }

    /// Write a [`GeneratedCert`] to disk.
    ///
    /// Writes `<stem>.crt` (`0644`) and `<stem>.key` (`0600`) under `dir` (`0700`).
    /// On Windows both files are owner-only.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the files
    /// cannot be written.
    pub fn write_to_dir(cert: &GeneratedCert, dir: &Path, stem: &str) -> Result<()> {
        fs::create_dir_all(dir)
            .map_err(|e| Error::Config(format!("Cannot create dir '{}': {e}", dir.display())))?;
        #[cfg(unix)]
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Config(format!("Cannot set dir permissions: {e}")))?;

        let cert_path = dir.join(format!("{stem}.crt"));
        // Windows has no 0644 to set: the cert goes through the same private
        // create-and-rename as the key, so it never carries the directory's
        // inherited DACL (a cert others can change is refused on read).
        #[cfg(windows)]
        write_private_file(&cert_path, &cert.cert_pem, "cert")?;
        #[cfg(not(windows))]
        {
            fs::write(&cert_path, &cert.cert_pem)
                .map_err(|e| Error::Config(format!("Cannot write cert: {e}")))?;
            // Exactly 0644 whatever the umask or an older file's mode: `serve`
            // refuses a cert others can change (F18 I1), and this one is public.
            #[cfg(unix)]
            fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))
                .map_err(|e| Error::Config(format!("Cannot set cert permissions: {e}")))?;
        }

        write_private_file(&dir.join(format!("{stem}.key")), &cert.key_pem, "key")?;

        Ok(())
    }
}

fn write_private_file(path: &Path, pem: &str, what: &str) -> Result<()> {
    // `OpenOptions::mode` applies only to a file it creates. Writing over an
    // existing key would reuse that file's inode and its original mode, so the
    // new key would sit in a possibly world-readable file until the chmod that
    // followed the write. Create a fresh owner-only file and rename it over the
    // destination instead, so the key is never readable at a wider mode.
    static TMP_NONCE: AtomicU64 = AtomicU64::new(0);

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("private");

    let mut tmp_path = None;
    for _ in 0..8 {
        let nonce = TMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let candidate = dir.join(format!("{stem}.tmp.{}.{nonce}", std::process::id()));
        match crate::config_persistence::create_new_private(&candidate) {
            Ok(mut file) => {
                if let Err(e) = file
                    .write_all(pem.as_bytes())
                    .and_then(|()| file.sync_all())
                {
                    // Close first: Windows will not remove a file still open here.
                    drop(file);
                    let _ = fs::remove_file(&candidate);
                    return Err(Error::Config(format!("Cannot write {what}: {e}")));
                }
                tmp_path = Some(candidate);
                break;
            }
            // Stale temp collided; try the next nonce.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::Config(format!("Cannot write {what}: {e}"))),
        }
    }

    let tmp_path = tmp_path.ok_or_else(|| {
        Error::Config(format!(
            "Cannot write {what}: no unique temp file after 8 attempts"
        ))
    })?;

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        Error::Config(format!("Cannot write {what}: {e}"))
    })?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_file(path: &str, what: crate::config::CheckedFile) -> Result<Vec<u8>> {
    crate::config::read_checked_file(Path::new(path), what)
        .map(String::into_bytes)
        .map_err(|e| Error::Config(e.to_string()))
}

/// Build a `WebPkiClientVerifier` with optional CRL support.
fn build_client_verifier(
    config: &MtlsConfig,
    root_store: rustls::RootCertStore,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let store = Arc::new(root_store);
    let builder = WebPkiClientVerifier::builder(store);

    // Load CRL if configured
    let builder = if let Some(ref crl_path) = config.crl_path {
        let crls = load_crls(crl_path)?;
        builder.with_crls(crls)
    } else {
        builder
    };

    // Require or allow unauthenticated clients
    let verifier = if config.require_client_cert {
        builder
            .build()
            .map_err(|e| Error::Config(format!("Failed to build client verifier: {e}")))?
    } else {
        builder
            .allow_unauthenticated()
            .build()
            .map_err(|e| Error::Config(format!("Failed to build client verifier: {e}")))?
    };

    Ok(verifier)
}

/// Load CRL entries from a PEM file.
fn load_crls(path: &str) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let pem_data = read_file(path, crate::config::CheckedFile::TlsCrl)?;
    CertificateRevocationListDer::pem_slice_iter(pem_data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse CRL from '{path}': {e}")))
}

/// Convert a validity period (days) into a future `OffsetDateTime` for `rcgen`.
///
/// Returns a date `days` from today. For simplicity we compute year/month/day
/// from the current time and add the requested days.  The `rcgen::date_time_ymd`
/// helper is used so we do not need to depend on the `time` crate directly.
fn validity_to_date(days: u32) -> Result<time::OffsetDateTime> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Config(format!("System time error: {e}")))?
        .as_secs();

    let future_secs = now_secs.saturating_add(u64::from(days) * 86_400);

    // Convert Unix timestamp to (year, month, day) using time crate (pulled in
    // transitively by rcgen).
    let dt =
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(future_secs).unwrap_or(i64::MAX))
            .map_err(|e| Error::Config(format!("Date calculation error: {e}")))?;

    // Use rcgen's ymd helper to keep alignment with its internal representation
    Ok(date_time_ymd(dt.year(), dt.month() as u8, dt.day()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "cert_manager_tests.rs"]
mod tests;

// Unix-only (W-L1): asserts POSIX mode bits on the written key; Windows uses DACLs (win_acl).
#[cfg(all(test, unix))]
mod private_key_permission_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    /// `OpenOptions::mode` only applies to a file it creates, so writing over an
    /// existing key would leave that file's original — possibly world-readable —
    /// mode in place. The new key must land on a fresh, owner-only inode.
    #[test]
    fn rewriting_a_key_replaces_the_file_rather_than_writing_into_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("server.key");

        // GIVEN: a key file left behind by an earlier run at a permissive mode.
        fs::write(&path, "old key").expect("seed key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("seed mode");
        let before = fs::metadata(&path).expect("seed metadata").ino();

        // WHEN: we write a new key to the same path.
        write_private_file(&path, "new key", "key").expect("write key");

        // THEN: it is a different file, owner-only, holding the new key.
        let after = fs::metadata(&path).expect("metadata");
        assert_ne!(before, after.ino(), "key was written into the old inode");
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&path).expect("read key"), "new key");
    }
}
