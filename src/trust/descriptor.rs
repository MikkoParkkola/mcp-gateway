//! Live descriptor projection for `tools/list` results.
//!
//! Attaches digest-only TrustCard references to tool descriptors.
//! Never embeds full TrustCard, CapabilityBom, or secret-bearing metadata
//! in the descriptor.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A digest-only TrustCard reference attached to a tool descriptor.
///
/// Contains only the SHA-256 digest of the full TrustCard JSON, never the
/// full TrustCard content or any resolved secret values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDescriptorRef {
    /// SHA-256 digest of the canonical TrustCard JSON.
    pub trust_card_digest: String,
    /// Schema version of the referenced TrustCard.
    pub schema_version: String,
}

/// Compute a digest-only TrustCard reference from a TrustCard.
///
/// The TrustCard is serialized to canonical JSON, and the SHA-256 digest
/// is computed. No secret values are included in the digest.
pub fn project_trust_descriptor(card: &crate::trust::TrustCard) -> TrustDescriptorRef {
    let canonical = serde_json::to_string(card).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    TrustDescriptorRef {
        trust_card_digest: format!("sha256:{}", hex::encode(hash)),
        schema_version: card.schema_version.clone(),
    }
}

/// Validate that a descriptor reference does not contain secret-bearing
/// metadata or full TrustCard/CBOM content.
pub fn validate_descriptor_safety(descriptor_json: &str) -> bool {
    let lower = descriptor_json.to_lowercase();
    // Must not contain common secret patterns
    let secret_patterns = [
        "bearer",
        "api_key",
        "secret",
        "password",
        "token",
        "private_key",
    ];
    for pattern in &secret_patterns {
        if lower.contains(pattern) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::*;

    fn sample_card() -> TrustCard {
        TrustCard {
            schema_version: TRUSTCARD_SCHEMA_VERSION.to_string(),
            name: "test-server".to_string(),
            server: TrustServer {
                source_uri: Some("https://example.com/mcp".to_string()),
                publisher: Some("test-publisher".to_string()),
                license: Some("MIT".to_string()),
                transport: "http".to_string(),
                auth_mode: "bearer".to_string(),
                runtime_profile: "remote_http".to_string(),
                network_reach: TrustNetworkReach::Public,
                signature_evidence: vec![],
                risk_class: TrustRiskClass::Low,
                data_classes: vec!["public".to_string()],
                permissions: vec!["network".to_string()],
                evidence_quality: "verified".to_string(),
            },
            tool: None,
            findings: vec![],
            generated_at: "2026-06-30T00:00:00Z".to_string(),
        }
    }

    // MIK-6556.AC.8: Live descriptor projection attaches digest-only TrustCard
    // references to tools/list results and never embeds full TrustCard,
    // CapabilityBom, or secret-bearing metadata in the descriptor.
    #[test]
    fn descriptor_contains_digest_only_not_full_card() {
        let card = sample_card();
        let desc = project_trust_descriptor(&card);

        assert!(
            desc.trust_card_digest.starts_with("sha256:"),
            "Descriptor must contain a sha256 digest"
        );
        assert_eq!(desc.schema_version, TRUSTCARD_SCHEMA_VERSION);

        let desc_json = serde_json::to_string(&desc).unwrap();
        // Must NOT contain full TrustCard content
        assert!(
            !desc_json.contains("test-publisher"),
            "Descriptor must not embed full TrustCard publisher"
        );
        assert!(
            !desc_json.contains("https://example.com/mcp"),
            "Descriptor must not embed full TrustCard source_uri"
        );
    }

    #[test]
    fn descriptor_is_deterministic() {
        let card = sample_card();
        let d1 = project_trust_descriptor(&card);
        let d2 = project_trust_descriptor(&card);
        assert_eq!(d1.trust_card_digest, d2.trust_card_digest);
    }

    #[test]
    fn descriptor_rejects_secret_bearing_content() {
        assert!(validate_descriptor_safety(
            r#"{"trust_card_digest":"sha256:abc"}"#
        ));
        assert!(!validate_descriptor_safety(
            r#"{"bearer":"token123","trust_card_digest":"sha256:abc"}"#
        ));
        assert!(!validate_descriptor_safety(
            r#"{"api_key":"sk-1234","trust_card_digest":"sha256:abc"}"#
        ));
    }
}
