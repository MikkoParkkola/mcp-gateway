//! Public schema facade for `TrustCard` and CBOM consumers.
//!
//! The canonical implementations live in `crate::trust`, but this module gives
//! downstream docs, examples, and generated clients a stable schema namespace.

pub use super::{
    CapabilityBom, CbomAnnotation, CbomComponent, CbomComponentKind, CbomDependency, CbomPrompt,
    CbomProvenance, CbomResource, CbomSubjectKind, CbomTool, TrustAuthMode, TrustCard,
    TrustDataClass, TrustEvaluationStatus, TrustEvidenceKind, TrustFinding, TrustFindingSeverity,
    TrustNetworkReach, TrustPermission, TrustRiskClass, TrustServer, TrustSignatureEvidence,
    TrustSignatureStatus, TrustTool, TrustToolAnnotations, TrustTransport, TrustValidationReport,
};

/// Compatibility alias for consumers that use the CBOM term directly.
pub type Cbom = CapabilityBom;
