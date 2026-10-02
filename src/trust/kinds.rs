// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CBOM subject, component and evidence kinds.

use serde::{Deserialize, Serialize};

/// CBOM subject kind for annotations and provenance records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CbomSubjectKind {
    /// Server subject.
    Server,
    /// Tool subject.
    Tool,
    /// Prompt subject.
    Prompt,
    /// Resource subject.
    Resource,
    /// Runtime subject.
    Runtime,
    /// Dependency subject.
    Dependency,
}

/// CBOM component kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CbomComponentKind {
    /// Server component.
    Server,
    /// Tool component.
    Tool,
    /// Prompt component.
    Prompt,
    /// Resource component.
    Resource,
    /// Runtime component.
    Runtime,
    /// Dependency component.
    Dependency,
}

/// Evidence quality for a `TrustCard` field.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvidenceKind {
    /// Declared by a trusted source.
    Declared,
    /// Inferred from local metadata.
    Inferred,
    /// Observed from a live protocol response.
    Observed,
    /// Missing or unknown.
    Missing,
}
