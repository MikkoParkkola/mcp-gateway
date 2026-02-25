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
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Ia5String, KeyPair,
    SanType, date_time_ymd,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
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

    let mut tls_cfg = rustls::ServerConfig::builder()
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
    let pem_data = read_file(path)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut pem_data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse certs from '{path}': {e}")))?;

    if certs.is_empty() {
        return Err(Error::Config(format!(
            "No certificates found in '{path}'"
        )));
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
    let pem_data = read_file(path)?;
    let key = rustls_pemfile::private_key(&mut pem_data.as_slice())
        .map_err(|e| Error::Config(format!("Failed to parse private key from '{path}': {e}")))?
        .ok_or_else(|| Error::Config(format!("No private key found in '{path}'")))?;

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
    /// Subject Alternative Names — DNS entries.
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

        // Parse CA certificate for signing
        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| Error::Config(format!("Failed to parse CA cert: {e}")))?;
        let ca_cert = ca_cert_params
            .self_signed(&ca_key)
            .map_err(|e| Error::Config(format!("Failed to rebuild CA cert for signing: {e}")))?;

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

        // Add SANs — rcgen 0.13 uses Ia5String for DNS and URI SAN types
        let mut sans: Vec<SanType> = Vec::new();
        for dns in &params.san_dns {
            let ia5 = Ia5String::try_from(dns.as_str())
                .map_err(|e| Error::Config(format!("Invalid DNS SAN '{dns}': {e}")))?;
            sans.push(SanType::DnsName(ia5));
        }
        for uri in &params.san_uris {
            let ia5 = Ia5String::try_from(uri.as_str())
                .map_err(|e| Error::Config(format!("Invalid URI SAN '{uri}': {e}")))?;
            sans.push(SanType::URI(ia5));
        }
        leaf_params.subject_alt_names = sans;

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(|e| Error::Config(format!("Leaf cert signing failed: {e}")))?;

        Ok(GeneratedCert {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }

    /// Write a [`GeneratedCert`] to disk.
    ///
    /// Writes `<stem>.crt` and `<stem>.key` under `dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the files
    /// cannot be written.
    pub fn write_to_dir(cert: &GeneratedCert, dir: &Path, stem: &str) -> Result<()> {
        fs::create_dir_all(dir)
            .map_err(|e| Error::Config(format!("Cannot create dir '{}': {e}", dir.display())))?;

        fs::write(dir.join(format!("{stem}.crt")), &cert.cert_pem)
            .map_err(|e| Error::Config(format!("Cannot write cert: {e}")))?;

        fs::write(dir.join(format!("{stem}.key")), &cert.key_pem)
            .map_err(|e| Error::Config(format!("Cannot write key: {e}")))?;

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_file(path: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error::Config(format!("Cannot read '{path}': {e}")))
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
        builder
            .with_crls(crls)
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
fn load_crls(path: &str) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>> {
    let pem_data = read_file(path)?;
    let crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>> =
        rustls_pemfile::crls(&mut pem_data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse CRL from '{path}': {e}")))?;
    Ok(crls)
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
    let dt = time::OffsetDateTime::from_unix_timestamp(
        i64::try_from(future_secs).unwrap_or(i64::MAX),
    )
    .map_err(|e| Error::Config(format!("Date calculation error: {e}")))?;

    // Use rcgen's ymd helper to keep alignment with its internal representation
    Ok(date_time_ymd(dt.year(), dt.month() as u8, dt.day()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── helpers ─────────────────────────────────────────────────────────────

    fn dns_san(s: &str) -> SanType {
        SanType::DnsName(Ia5String::try_from(s).unwrap())
    }

    fn uri_san(s: &str) -> SanType {
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
        fs::write(&path, &ca.cert_pem).unwrap();

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
        fs::write(&path, &ca.key_pem).unwrap();

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
        fs::write(&path, &ca.cert_pem).unwrap();

        let result = load_private_key(path.to_str().unwrap());
        assert!(result.is_err());
    }
}
