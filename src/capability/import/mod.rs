//! Protocol import layer — converts external API descriptions into
//! reviewable `CapabilityDraft` values before YAML generation.
//!
//! # Architecture
//!
//! ```text
//! OpenAPI spec  ──┐
//! GraphQL SDL   ──┤
//! Postman coll. ──┼──▶ CapabilityDraft ──▶ Generator ──▶ YAML + TrustCard + Risk report
//! OCI package   ──┘
//! ```

pub mod draft;
pub mod generator;
pub mod graphql;
pub mod oci;
pub mod openapi;
pub mod postman;

pub use draft::{
    CapabilityDraft, DraftAuth, DraftExample, ImportSourceKind, ReviewState, SafetyClassification,
    TrustCardStub,
};
pub use generator::{GenerationOutput, ImportGenerator};
pub use graphql::GraphQlImporter;
pub use oci::OciMcpPackageImporter;
pub use openapi::OpenApiDraftConverter;
pub use postman::PostmanImporter;
