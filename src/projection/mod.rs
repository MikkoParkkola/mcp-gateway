//! Projection layer for the gateway proxy surface (MIK-3530).
//!
//! The gateway exposes the union of many heterogeneous backend tool surfaces.
//! The projection layer absorbs that churn by:
//!
//! 1. Defining a small **canonical schema** ([`Actor`], [`Subject`],
//!    [`EnvTime`], [`Url`], [`Body`]) that backend responses can be projected
//!    onto, always preserving the original payload under `_raw`
//!    ([`Projected`]).
//! 2. Tagging tools with a [`Role`] (selector / extractor / enricher / action)
//!    so discovery can be filtered by intent.
//!
//! This module (MIK-3531) provides the foundation types and their
//! serialization contract. The descriptor wiring (role/projection on the tool
//! descriptor) and the projection logic that consumes a [`ProjectionSpec`] land
//! in subsequent PRs (MIK-3532 / MIK-3533 / MIK-3534).

pub mod engine;
pub mod mode;
pub mod role;
pub mod schema;

pub use engine::project;
pub use mode::{
    AbRecord, ProjectionDecision, ProjectionMode, ab_classification, projection_decision,
    projection_key_suffix,
};
pub use role::Role;
pub use schema::{
    Actor, ActorSpec, Body, BodySpec, EnvTime, EnvTimeSpec, Projected, ProjectionSpec, Subject,
    SubjectSpec, Url, UrlSpec,
};
