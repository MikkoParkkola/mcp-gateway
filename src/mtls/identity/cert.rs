// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A client certificate's identity. A leaf module, so its private fields are
//! private to this file alone: an identity comes only from a parsed
//! certificate ([`CertIdentity::from_der`]).

use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::gateway::auth::QuotaPrincipal;
use crate::{Error, Result};

/// Extracted identity fields from a verified client certificate.
///
/// All fields are optional because not every certificate uses every field.
/// The `display_name` is computed once for use in audit logs.
///
/// Built only by parsing a certificate, and read through its accessors:
///
/// ```
/// use mcp_gateway::mtls::CertIdentity;
///
/// let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
/// params.distinguished_name = rcgen::DistinguishedName::new();
/// params.distinguished_name.push(rcgen::DnType::CommonName, "agent-1");
/// let key = rcgen::KeyPair::generate().expect("key");
/// let der = params.self_signed(&key).expect("self-signed").der().to_vec();
/// let identity = CertIdentity::from_der(&der).expect("parses").expect("names someone");
/// assert_eq!(identity.common_name(), Some("agent-1"));
/// ```
///
/// Code outside this module cannot build one by a struct literal:
///
/// ```compile_fail,E0451
/// use mcp_gateway::mtls::CertIdentity;
///
/// fn mint() -> CertIdentity {
///     CertIdentity {
///         common_name: None,
///         organizational_unit: None,
///         san_uris: Vec::new(),
///         san_dns_names: Vec::new(),
///         display_name: String::new(),
///         quota_principal: None,
///     }
/// }
/// ```
///
/// or by copying another with one field changed:
///
/// ```compile_fail,E0451
/// use mcp_gateway::mtls::CertIdentity;
///
/// fn relabel(other: CertIdentity) -> CertIdentity {
///     CertIdentity {
///         common_name: None,
///         ..other
///     }
/// }
/// ```
///
/// and cannot change one after it was built:
///
/// ```compile_fail,E0616
/// use mcp_gateway::mtls::CertIdentity;
///
/// fn rename(identity: &mut CertIdentity) {
///     identity.common_name = None;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertIdentity {
    /// Certificate Common Name (CN).
    common_name: Option<String>,

    /// First Organisational Unit (OU) in the subject.
    organizational_unit: Option<String>,

    /// Subject Alternative Name — URI entries (e.g. SPIFFE IDs).
    san_uris: Vec<String>,

    /// Subject Alternative Name — DNS entries.
    san_dns_names: Vec<String>,

    /// Pre-computed human-readable label for logs/audit events.
    display_name: String,

    /// Nonce-quota bucket, derived from the whole certificate DER.
    ///
    /// `None` on any identity built by hand — a fixture cannot mint quota.
    /// Set only by [`CertIdentity::from_der`], so two certificates sharing a
    /// CN or display name stay separate and one certificate presented on many
    /// connections shares one bucket.
    quota_principal: Option<QuotaPrincipal>,
}

impl CertIdentity {
    /// Certificate Common Name (CN).
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// First Organisational Unit (OU) in the subject.
    #[must_use]
    pub fn organizational_unit(&self) -> Option<&str> {
        self.organizational_unit.as_deref()
    }

    /// Subject Alternative Name URI entries (e.g. SPIFFE IDs).
    #[must_use]
    pub fn san_uris(&self) -> &[String] {
        &self.san_uris
    }

    /// Subject Alternative Name DNS entries.
    #[must_use]
    pub fn san_dns_names(&self) -> &[String] {
        &self.san_dns_names
    }

    /// Human-readable label for logs and audit events.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Nonce-quota bucket, derived from the whole certificate DER.
    #[must_use]
    pub fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        self.quota_principal.as_ref()
    }

    /// The subject this certificate names, verbatim: its first SAN URI that is
    /// not empty or only whitespace, else its CN if that is not. `None` when it
    /// has neither: such a certificate names nobody, and its display name is a
    /// placeholder every such certificate shares, so it is never an identity.
    pub(crate) fn subject_id(&self) -> Option<&str> {
        self.san_uris
            .iter()
            .map(String::as_str)
            .chain(self.common_name.as_deref())
            .find(|value| !value.trim().is_empty())
    }

    /// Parse a DER-encoded certificate and extract its identity fields.
    ///
    /// # Trust boundary
    ///
    /// The returned identity carries a [`QuotaPrincipal`], which is an
    /// *authenticated* credential's bucket. Production reaches this only from
    /// the peer chain of a handshake Rustls has already verified
    /// (`client_identity_from_peer_chain`, behind the TLS acceptor). Parsing
    /// is public and proves nothing on its own: calling this on unverified
    /// bytes would let the sender choose its own bucket.
    ///
    /// `Ok(None)` for a certificate that parses but names no one: no SAN URI
    /// and no CN, or only empty or whitespace-only ones (see
    /// [`Self::subject_id`]). That is no identity, distinct from a parse
    /// error, and its caller refuses it as such.
    ///
    /// # Errors
    ///
    /// Returns `Error::Config` if the certificate cannot be parsed or has
    /// a malformed subject DN.
    pub fn from_der(der: &[u8]) -> Result<Option<Self>> {
        let identity = Self::parse(der)?;
        Ok(identity.subject_id().is_some().then_some(identity))
    }

    /// [`Self::parse`] for a test that needs the identity of a certificate
    /// naming no one, to prove what downstream code does with one.
    #[cfg(test)]
    pub(crate) fn parse_for_test(der: &[u8]) -> Result<Self> {
        Self::parse(der)
    }

    /// The identity fields of `der`, whether or not they name anyone.
    fn parse(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| Error::Config(format!("Failed to parse client certificate: {e}")))?;

        let common_name = super::extract_cn(&cert);
        let organizational_unit = super::extract_ou(&cert);
        let (san_uris, san_dns_names) = super::extract_sans(&cert);

        let display_name = super::build_display_name(common_name.as_ref(), &san_uris);

        Ok(Self {
            common_name,
            organizational_unit,
            san_uris,
            san_dns_names,
            display_name,
            quota_principal: Some(QuotaPrincipal::client_certificate(der)),
        })
    }
}

/// The fields of a hand-built test identity, all defaulting to empty. Test
/// code only: production builds a [`CertIdentity`] through
/// [`CertIdentity::from_der`] alone.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct CertFields {
    pub(crate) common_name: Option<String>,
    pub(crate) organizational_unit: Option<String>,
    pub(crate) san_uris: Vec<String>,
    pub(crate) san_dns_names: Vec<String>,
    pub(crate) display_name: String,
    pub(crate) quota_principal: Option<QuotaPrincipal>,
}

#[cfg(test)]
impl CertIdentity {
    /// A test's fixed identity, unchecked: a test may build one naming no
    /// one, to prove what downstream code does with it.
    pub(crate) fn for_test(fields: CertFields) -> Self {
        let CertFields {
            common_name,
            organizational_unit,
            san_uris,
            san_dns_names,
            display_name,
            quota_principal,
        } = fields;
        Self {
            common_name,
            organizational_unit,
            san_uris,
            san_dns_names,
            display_name,
            quota_principal,
        }
    }
}
