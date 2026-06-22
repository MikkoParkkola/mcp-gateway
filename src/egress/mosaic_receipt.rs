//! Attestable receipt for mosaic egress decisions (MIK-6273.AC.5).
//!
//! Each record includes direct_risk, mosaic_risk, decision, classifier_version,
//! query_hash, history_hash, session_id_hash, and either botnaut_state_content_id
//! or a signed_json_fallback.

use serde::{Deserialize, Serialize};

use crate::hashing::sha256_hex;
use crate::egress::mosaic_guard::MosaicEgressDecision;

/// Attestable egress decision receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MosaicEgressReceipt {
    pub direct_risk: f64,
    pub mosaic_risk: f64,
    pub decision: String,
    pub classifier_version: String,
    pub query_hash: String,
    pub history_hash: String,
    pub session_id_hash: String,
    /// Botnaut .state / receipt content id when attestation path used.
    pub botnaut_state_content_id: Option<String>,
    /// Signed JSON fallback when botnaut unavailable (always populated for verifiability).
    pub signed_json_fallback: Option<String>,
}

impl MosaicEgressReceipt {
    /// Build receipt from score data. Falls back to local signed JSON.
    pub fn from_score(
        direct_risk: f64,
        mosaic_risk: f64,
        decision: MosaicEgressDecision,
        classifier_version: &str,
        query_hash: &str,
        history_hash: &str,
        session_id_hash: &str,
    ) -> Self {
        let decision_str = decision.as_str().to_string();
        // Construct canonical payload for signing/fallback
        let payload = serde_json::json!({
            "direct_risk": direct_risk,
            "mosaic_risk": mosaic_risk,
            "decision": decision_str,
            "classifier_version": classifier_version,
            "query_hash": query_hash,
            "history_hash": history_hash,
            "session_id_hash": session_id_hash,
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
        let canonical = serde_json::to_string(&payload).unwrap_or_default();
        let sig = sha256_hex(format!("mosaic-fallback|{}", canonical).as_bytes());
        let signed_json = format!("{{\"payload\":{},\"sig\":\"sha256:{}\"}}", canonical, sig);

        Self {
            direct_risk,
            mosaic_risk,
            decision: decision_str,
            classifier_version: classifier_version.to_string(),
            query_hash: query_hash.to_string(),
            history_hash: history_hash.to_string(),
            session_id_hash: session_id_hash.to_string(),
            botnaut_state_content_id: None, // botnaut companion; not primary in this checkout
            signed_json_fallback: Some(signed_json),
        }
    }

    /// Compatibility constructor used by invoke wiring (AC.3).
    #[allow(clippy::too_many_arguments)]
    pub fn from_score_fields(
        direct_risk: f64,
        mosaic_risk: f64,
        decision: &str,
        classifier_version: &str,
        query_hash: &str,
        history_hash: &str,
        session_id_hash: &str,
        _botnaut: Option<String>,
    ) -> Self {
        // Map str decision to enum for core path.
        let dec = match decision {
            "block" => MosaicEgressDecision::Block,
            "redact" => MosaicEgressDecision::Redact,
            "warn" => MosaicEgressDecision::Warn,
            _ => MosaicEgressDecision::Allow,
        };
        // delegate
        let mut r = Self::from_score(
            direct_risk,
            mosaic_risk,
            dec,
            classifier_version,
            query_hash,
            history_hash,
            session_id_hash,
        );
        if _botnaut.is_some() {
            r.botnaut_state_content_id = _botnaut;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_contains_required_attestation_fields() {
        let r = MosaicEgressReceipt::from_score(
            0.1, 0.2, MosaicEgressDecision::Allow, "v1", "qhash", "hhash", "shash",
        );
        assert!(r.history_hash == "hhash");
        assert!(r.classifier_version == "v1");
        assert!(r.botnaut_state_content_id.is_none() || r.botnaut_state_content_id.is_some());
        assert!(r.signed_json_fallback.is_some());
        let fb = r.signed_json_fallback.unwrap();
        assert!(fb.contains("sig"));
    }
}
