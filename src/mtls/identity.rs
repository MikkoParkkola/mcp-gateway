//! Certificate identity extraction.
//!
//! Parses an X.509 DER-encoded certificate and extracts the fields used for
//! policy matching: Common Name, Organisational Unit, SAN URIs, SAN DNS names.
//!
//! # No unsafe
//!
//! `x509-parser` performs minimal `unsafe` internally for ASN.1 parsing;
//! this module itself contains no `unsafe` code and simply calls the safe
//! public API.

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use crate::{Error, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Certificate identity
// ─────────────────────────────────────────────────────────────────────────────

/// Extracted identity fields from a verified client certificate.
///
/// All fields are optional because not every certificate uses every field.
/// The `display_name` is computed once for use in audit logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertIdentity {
    /// Certificate Common Name (CN).
    pub common_name: Option<String>,

    /// First Organisational Unit (OU) in the subject.
    pub organizational_unit: Option<String>,

    /// Subject Alternative Name — URI entries (e.g. SPIFFE IDs).
    pub san_uris: Vec<String>,

    /// Subject Alternative Name — DNS entries.
    pub san_dns_names: Vec<String>,

    /// Pre-computed human-readable label for logs/audit events.
    pub display_name: String,
}

impl CertIdentity {
    /// Parse a DER-encoded certificate and extract its identity fields.
    ///
    /// # Errors
    ///
    /// Returns `Error::Config` if the certificate cannot be parsed or has
    /// a malformed subject DN.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| Error::Config(format!("Failed to parse client certificate: {e}")))?;

        let common_name = extract_cn(&cert);
        let organizational_unit = extract_ou(&cert);
        let (san_uris, san_dns_names) = extract_sans(&cert);

        let display_name = build_display_name(common_name.as_ref(), &san_uris);

        Ok(Self {
            common_name,
            organizational_unit,
            san_uris,
            san_dns_names,
            display_name,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the CN attribute from the subject DN.
fn extract_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_owned)
}

/// Extract the first OU attribute from the subject DN.
fn extract_ou(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_organizational_unit()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_owned)
}

/// Extract SAN URI and SAN DNS entries from the certificate extensions.
fn extract_sans(cert: &X509Certificate<'_>) -> (Vec<String>, Vec<String>) {
    let mut uris = Vec::new();
    let mut dns_names = Vec::new();

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::URI(uri) => uris.push((*uri).to_owned()),
                GeneralName::DNSName(dns) => dns_names.push((*dns).to_owned()),
                _ => {}
            }
        }
    }

    (uris, dns_names)
}

/// Build a human-readable display name for logs.
///
/// Prefers the SPIFFE URI if present, then CN, then `"<unknown>"`.
fn build_display_name(cn: Option<&String>, san_uris: &[String]) -> String {
    san_uris
        .iter()
        .find(|u| u.starts_with("spiffe://"))
        .map(String::as_str)
        .or_else(|| cn.map(String::as_str))
        .unwrap_or("<unknown>")
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, SanType};

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Generate a self-signed DER cert with the given CN and SANs.
    fn make_cert_der(cn: &str, ou: Option<&str>, sans: &[SanType]) -> Vec<u8> {
        use rcgen::KeyPair;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        if let Some(ou_str) = ou {
            dn.push(DnType::OrganizationalUnitName, ou_str);
        }
        params.distinguished_name = dn;
        params.subject_alt_names = sans.to_vec();

        let key_pair = KeyPair::generate().expect("key generation failed");
        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen cert generation failed");
        cert.der().to_vec()
    }

    /// Build a DNS SAN using the Ia5String type required by rcgen 0.13.
    fn dns_san(s: &str) -> SanType {
        SanType::DnsName(Ia5String::try_from(s).unwrap())
    }

    /// Build a URI SAN using the Ia5String type required by rcgen 0.13.
    fn uri_san(s: &str) -> SanType {
        SanType::URI(Ia5String::try_from(s).unwrap())
    }

    /// A minimal cert with only CN (no SANs).
    fn cert_cn_only(cn: &str) -> Vec<u8> {
        // rcgen requires at least one SAN; provide a DNS fallback
        make_cert_der(cn, None, &[dns_san(cn)])
    }

    // ── from_der: basic fields ────────────────────────────────────────────────

    #[test]
    fn from_der_extracts_common_name() {
        // GIVEN: cert with CN=claude-code-agent
        let der = cert_cn_only("claude-code-agent");
        // WHEN: parsing
        let id = CertIdentity::from_der(&der).unwrap();
        // THEN: CN extracted
        assert_eq!(id.common_name.as_deref(), Some("claude-code-agent"));
    }

    #[test]
    fn from_der_extracts_organizational_unit() {
        // GIVEN: cert with OU=engineering
        let der = make_cert_der(
            "test-agent",
            Some("engineering"),
            &[dns_san("test-agent")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert_eq!(id.organizational_unit.as_deref(), Some("engineering"));
    }

    #[test]
    fn from_der_extracts_san_uri() {
        // GIVEN: cert with SPIFFE URI SAN
        let der = make_cert_der(
            "cursor-agent",
            None,
            &[uri_san("spiffe://company.com/agent/cursor")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert_eq!(id.san_uris, vec!["spiffe://company.com/agent/cursor"]);
    }

    #[test]
    fn from_der_extracts_san_dns_name() {
        // GIVEN: cert with DNS SAN
        let der = make_cert_der(
            "server",
            None,
            &[dns_san("gateway.company.com")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert!(id.san_dns_names.contains(&"gateway.company.com".to_string()));
    }

    #[test]
    fn from_der_extracts_multiple_sans() {
        // GIVEN: cert with both URI and DNS SANs
        let der = make_cert_der(
            "multi-san",
            None,
            &[
                uri_san("spiffe://company.com/svc/foo"),
                dns_san("foo.internal"),
            ],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert_eq!(id.san_uris.len(), 1);
        assert_eq!(id.san_dns_names.len(), 1);
    }

    #[test]
    fn from_der_invalid_bytes_returns_error() {
        // GIVEN: garbage bytes
        let result = CertIdentity::from_der(b"not a cert");
        // THEN: parse error
        assert!(result.is_err());
    }

    // ── display_name priority ─────────────────────────────────────────────────

    #[test]
    fn display_name_prefers_spiffe_uri_over_cn() {
        // GIVEN: cert with both CN and SPIFFE URI
        let der = make_cert_der(
            "my-cn",
            None,
            &[uri_san("spiffe://company.com/agent/foo")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert_eq!(id.display_name, "spiffe://company.com/agent/foo");
    }

    #[test]
    fn display_name_falls_back_to_cn_when_no_spiffe() {
        // GIVEN: cert with CN only (DNS SAN added by rcgen requirement)
        let der = cert_cn_only("claude-code-agent");
        let id = CertIdentity::from_der(&der).unwrap();
        assert_eq!(id.display_name, "claude-code-agent");
    }

    #[test]
    fn display_name_is_unknown_when_no_cn_or_spiffe() {
        // GIVEN: the build_display_name helper with no CN and no SPIFFE URI
        let name = build_display_name(None, &[]);
        assert_eq!(name, "<unknown>");
    }

    #[test]
    fn display_name_ignores_non_spiffe_uri_sans() {
        // GIVEN: cert with a non-SPIFFE URI SAN (uses CN instead)
        let der = make_cert_der(
            "fallback-cn",
            None,
            &[uri_san("https://not-spiffe.example.com")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        // THEN: non-SPIFFE URI means display_name falls back to CN
        assert_eq!(id.display_name, "fallback-cn");
    }

    // ── ou absent → None ──────────────────────────────────────────────────────

    #[test]
    fn organizational_unit_is_none_when_absent() {
        let der = cert_cn_only("no-ou-agent");
        let id = CertIdentity::from_der(&der).unwrap();
        assert!(id.organizational_unit.is_none());
    }

    // ── empty SANs when not present ───────────────────────────────────────────

    #[test]
    fn san_lists_reflect_what_cert_contains() {
        // GIVEN: cert with only DNS SANs
        let der = make_cert_der(
            "server",
            None,
            &[dns_san("gateway.example.com")],
        );
        let id = CertIdentity::from_der(&der).unwrap();
        assert!(id.san_uris.is_empty(), "No URI SANs expected");
        assert!(!id.san_dns_names.is_empty());
    }

    // ── default identity ──────────────────────────────────────────────────────

    #[test]
    fn default_cert_identity_has_empty_fields() {
        let id = CertIdentity::default();
        assert!(id.common_name.is_none());
        assert!(id.organizational_unit.is_none());
        assert!(id.san_uris.is_empty());
        assert!(id.san_dns_names.is_empty());
    }
}
