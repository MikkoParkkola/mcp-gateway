// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Parsed `OpenAPI` document model.
//!
//! Single responsibility: serde deserialization types mirroring the subset
//! of the `OpenAPI` 3.0/3.1 schema the converter consumes.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

/// Simplified `OpenAPI` spec structure (just what we need)
#[derive(Debug, Deserialize)]
pub(crate) struct OpenApiSpec {
    pub(crate) openapi: Option<String>,
    pub(crate) swagger: Option<String>,
    pub(crate) info: OpenApiInfo,
    pub(crate) servers: Option<Vec<OpenApiServer>>,
    pub(crate) paths: HashMap<String, HashMap<String, OpenApiOperation>>,
    pub(crate) components: Option<OpenApiComponents>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields needed for parsing, may be used in future
pub(crate) struct OpenApiInfo {
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) version: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct OpenApiServer {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct OpenApiOperation {
    #[serde(default)]
    pub(crate) operation_id: Option<String>,
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) parameters: Vec<OpenApiParameter>,
    #[serde(default)]
    pub(crate) request_body: Option<OpenApiRequestBody>,
    #[serde(default)]
    pub(crate) responses: HashMap<String, OpenApiResponse>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) security: Option<Vec<HashMap<String, Vec<String>>>>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OpenApiParameter {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(rename = "in", default)]
    pub(crate) location: String,
    #[serde(default)]
    pub(crate) required: bool,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) schema: Option<Value>,
    #[serde(default, rename = "$ref")]
    pub(crate) reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub(crate) struct OpenApiRequestBody {
    #[serde(default)]
    pub(crate) required: bool,
    #[serde(default)]
    pub(crate) content: HashMap<String, OpenApiMediaType>,
    #[serde(default, rename = "$ref")]
    pub(crate) reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OpenApiMediaType {
    #[serde(default)]
    pub(crate) schema: Option<Value>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub(crate) struct OpenApiResponse {
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) content: Option<HashMap<String, OpenApiMediaType>>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct OpenApiComponents {
    #[serde(default)]
    pub(crate) schemas: HashMap<String, Value>,
    #[serde(default, rename = "securitySchemes")]
    pub(crate) security_schemes: HashMap<String, OpenApiSecurityScheme>,
    #[serde(default)]
    pub(crate) parameters: HashMap<String, OpenApiParameter>,
    #[serde(default, rename = "requestBodies")]
    pub(crate) request_bodies: HashMap<String, OpenApiRequestBody>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct OpenApiSecurityScheme {
    #[serde(rename = "type")]
    pub(crate) scheme_type: String,
    #[serde(default)]
    pub(crate) scheme: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(rename = "in", default)]
    pub(crate) location: Option<String>,
}
