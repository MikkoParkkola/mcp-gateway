//! Schema facade for TrustCard and CapabilityBom types.
//!
//! Re-exports all public trust types from the parent module for convenient
//! access via `crate::trust::schema::*`.

pub use super::{
    CapabilityBom, CbomAnnotation, CbomDependency, CbomPrompt, CbomProvenance, CbomResource,
    CbomTool, TrustCard, TrustFinding, TrustFindingSeverity, TrustNetworkReach, TrustRiskClass,
    TrustServer, TrustSignatureEvidence, TrustTool,
};
