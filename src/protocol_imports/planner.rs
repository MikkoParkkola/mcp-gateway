use serde_json::{Value, json};

use crate::{Error, Result, capability::OpenApiConverter, hashing::sha256_hex};

use super::{
    CapabilityDraft, DraftRoute, GraphqlImportSpec, GraphqlOperationImport, GraphqlOperationType,
    ImportPlan, ImportRisk, ImportRiskKind, ImportRiskLevel, ImportSafeDefaults, ImportSource,
    ImportSourceKind, OciMcpPackageImport, OciToolImport, TrustCardDraft, TrustEvidenceLevel,
    helpers::{
        PostmanRequest, aggregate_gates, classify_route_risks, classify_schema_risks,
        collect_postman_requests, digest_for, empty_object_schema, gates_for_risks, human_title,
        is_safe_method, lacks_graphql_bounds, plan_digest, policy_for_gates, postman_input_schema,
        slugify, source_kind_slug,
    },
};

/// Safe import planner for `OpenAPI`, GraphQL, Postman, and OCI MCP packages.
#[derive(Debug, Clone)]
pub struct ProtocolImportPlanner {
    context_integrity_profile: String,
    safe_defaults: ImportSafeDefaults,
}

impl Default for ProtocolImportPlanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolImportPlanner {
    /// Create a planner with conservative import defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context_integrity_profile: "imported_tool_baseline".to_string(),
            safe_defaults: ImportSafeDefaults::default(),
        }
    }

    /// Override the context integrity profile attached to generated drafts.
    #[must_use]
    pub fn with_context_integrity_profile(mut self, profile: impl Into<String>) -> Self {
        self.context_integrity_profile = profile.into();
        self
    }

    /// Plan a safe import from `OpenAPI` or Swagger content.
    ///
    /// # Errors
    ///
    /// Returns an error if the source cannot be converted into capability YAML
    /// or if generated YAML cannot be parsed back into a draft.
    pub fn plan_openapi(&self, source_name: &str, content: &str) -> Result<ImportPlan> {
        let source_digest = digest_for(ImportSourceKind::OpenApi, content.as_bytes());
        let source = ImportSource {
            name: source_name.to_string(),
            kind: ImportSourceKind::OpenApi,
            uri: None,
            license: None,
            provenance: None,
        };
        let capabilities = OpenApiConverter::new().convert_string(content)?;
        let mut drafts = Vec::with_capacity(capabilities.len());

        for generated in capabilities {
            drafts.push(self.draft_from_capability_yaml(
                &source,
                &source_digest,
                &generated.yaml,
            )?);
        }

        Ok(self.finalize_plan(source, source_digest, drafts))
    }

    /// Plan a safe import from selected GraphQL operations.
    ///
    /// # Errors
    ///
    /// Returns an error when no operations are supplied.
    pub fn plan_graphql(&self, source_name: &str, spec: &GraphqlImportSpec) -> Result<ImportPlan> {
        if spec.operations.is_empty() {
            return Err(Error::Config(
                "GraphQL import requires at least one operation".to_string(),
            ));
        }

        let normalized = serde_json::to_vec(&spec).unwrap_or_default();
        let source_digest = digest_for(ImportSourceKind::Graphql, &normalized);
        let source = ImportSource {
            name: source_name.to_string(),
            kind: ImportSourceKind::Graphql,
            uri: Some(spec.endpoint.clone()),
            license: None,
            provenance: None,
        };

        let mut drafts = spec
            .operations
            .iter()
            .map(|operation| self.draft_from_graphql(&source, &source_digest, spec, operation))
            .collect::<Vec<_>>();
        drafts.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(self.finalize_plan(source, source_digest, drafts))
    }

    /// Plan a safe import from a Postman collection JSON document.
    ///
    /// # Errors
    ///
    /// Returns an error if the collection cannot be parsed or contains no
    /// importable requests.
    pub fn plan_postman(&self, content: &str) -> Result<ImportPlan> {
        let value: Value = serde_json::from_str(content)
            .map_err(|e| Error::Config(format!("Failed to parse Postman collection: {e}")))?;
        let source_name = value
            .pointer("/info/name")
            .and_then(Value::as_str)
            .unwrap_or("postman-collection");
        let source_digest = digest_for(ImportSourceKind::Postman, content.as_bytes());
        let source = ImportSource {
            name: source_name.to_string(),
            kind: ImportSourceKind::Postman,
            uri: value
                .pointer("/info/_postman_id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            license: value
                .pointer("/info/license")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            provenance: None,
        };

        let mut requests = Vec::new();
        collect_postman_requests(&value, &mut requests);
        if requests.is_empty() {
            return Err(Error::Config(
                "Postman collection did not contain importable requests".to_string(),
            ));
        }

        let mut drafts = requests
            .iter()
            .map(|request| self.draft_from_postman(&source, &source_digest, request))
            .collect::<Vec<_>>();
        drafts.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(self.finalize_plan(source, source_digest, drafts))
    }

    /// Plan a safe import from OCI MCP package metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the package exposes no tool metadata.
    pub fn plan_oci_package(&self, package: &OciMcpPackageImport) -> Result<ImportPlan> {
        if package.tools.is_empty() {
            return Err(Error::Config(
                "OCI MCP package import requires at least one tool".to_string(),
            ));
        }

        let normalized = serde_json::to_vec(&package).unwrap_or_default();
        let source_digest = package
            .digest_sha256
            .clone()
            .unwrap_or_else(|| digest_for(ImportSourceKind::OciMcpPackage, &normalized));
        let source = ImportSource {
            name: package.name.clone(),
            kind: ImportSourceKind::OciMcpPackage,
            uri: Some(package.image_ref.clone()),
            license: package.license.clone(),
            provenance: package.provenance.clone(),
        };

        let mut drafts = package
            .tools
            .iter()
            .map(|tool| self.draft_from_oci_tool(&source, &source_digest, package, tool))
            .collect::<Vec<_>>();
        drafts.sort_by(|left, right| left.id.cmp(&right.id));

        Ok(self.finalize_plan(source, source_digest, drafts))
    }

    fn draft_from_capability_yaml(
        &self,
        source: &ImportSource,
        source_digest: &str,
        yaml: &str,
    ) -> Result<CapabilityDraft> {
        let value: Value = serde_yaml::from_str(yaml).map_err(|e| {
            Error::Config(format!("Failed to parse generated capability YAML: {e}"))
        })?;
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("imported_tool")
            .to_string();
        let description = value
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("Imported capability draft")
            .to_string();
        let input_schema = value
            .pointer("/schema/input")
            .cloned()
            .unwrap_or_else(empty_object_schema);
        let output_schema = value
            .pointer("/schema/output")
            .cloned()
            .unwrap_or_else(empty_object_schema);
        let method = value
            .pointer("/providers/primary/config/method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let endpoint = value
            .pointer("/providers/primary/config/base_url")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let path = value
            .pointer("/providers/primary/config/path")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let auth_required = value
            .pointer("/auth/required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let read_only = value
            .pointer("/metadata/read_only")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| is_safe_method(&method));

        let route = DraftRoute {
            protocol: "rest".to_string(),
            method: Some(method.clone()),
            endpoint,
            operation: path,
        };
        let risks = classify_route_risks(
            &route,
            &input_schema,
            auth_required,
            read_only,
            &description,
        );
        Ok(self.build_draft(
            source,
            source_digest,
            &name,
            &description,
            route,
            input_schema,
            output_schema,
            risks,
            Some(yaml.to_string()),
        ))
    }

    fn draft_from_graphql(
        &self,
        source: &ImportSource,
        source_digest: &str,
        spec: &GraphqlImportSpec,
        operation: &GraphqlOperationImport,
    ) -> CapabilityDraft {
        let method = match operation.operation_type {
            GraphqlOperationType::Query => "QUERY",
            GraphqlOperationType::Mutation => "MUTATION",
            GraphqlOperationType::Subscription => "SUBSCRIPTION",
        };
        let route = DraftRoute {
            protocol: "graphql".to_string(),
            method: Some(method.to_string()),
            endpoint: Some(spec.endpoint.clone()),
            operation: Some(operation.name.clone()),
        };
        let mut risks = classify_route_risks(
            &route,
            &operation.variables_schema,
            true,
            matches!(operation.operation_type, GraphqlOperationType::Query),
            &operation.query,
        );

        if matches!(operation.operation_type, GraphqlOperationType::Query)
            && lacks_graphql_bounds(&operation.query, &operation.variables_schema)
        {
            risks.push(ImportRisk {
                kind: ImportRiskKind::UnboundedQuery,
                level: ImportRiskLevel::Medium,
                reason: "GraphQL query lacks obvious pagination or complexity bounds".to_string(),
                field: Some(operation.name.clone()),
            });
        }

        self.build_draft(
            source,
            source_digest,
            &slugify(&operation.name),
            &operation.name,
            route,
            operation.variables_schema.clone(),
            operation.response_schema.clone(),
            risks,
            None,
        )
    }

    fn draft_from_postman(
        &self,
        source: &ImportSource,
        source_digest: &str,
        request: &PostmanRequest,
    ) -> CapabilityDraft {
        let route = DraftRoute {
            protocol: "rest".to_string(),
            method: Some(request.method.clone()),
            endpoint: Some(request.url.clone()),
            operation: Some(request.name.clone()),
        };
        let input_schema = postman_input_schema(&request.query_params);
        let risks = classify_route_risks(
            &route,
            &input_schema,
            false,
            is_safe_method(&request.method),
            "",
        );

        self.build_draft(
            source,
            source_digest,
            &slugify(&request.name),
            &request.name,
            route,
            input_schema,
            empty_object_schema(),
            risks,
            None,
        )
    }

    fn draft_from_oci_tool(
        &self,
        source: &ImportSource,
        source_digest: &str,
        package: &OciMcpPackageImport,
        tool: &OciToolImport,
    ) -> CapabilityDraft {
        let route = DraftRoute {
            protocol: "oci_mcp".to_string(),
            method: Some("TOOL".to_string()),
            endpoint: Some(package.image_ref.clone()),
            operation: Some(tool.name.clone()),
        };
        let mut risks = classify_schema_risks(&tool.input_schema);
        if package.digest_sha256.is_none() || package.provenance.is_none() {
            risks.push(ImportRisk {
                kind: ImportRiskKind::SupplyChainProvenance,
                level: ImportRiskLevel::High,
                reason: "Package provenance or digest is missing".to_string(),
                field: Some(package.image_ref.clone()),
            });
        }
        if package.license.is_none() {
            risks.push(ImportRisk {
                kind: ImportRiskKind::LicenseUnknown,
                level: ImportRiskLevel::Medium,
                reason: "Package license metadata is missing".to_string(),
                field: Some(package.name.clone()),
            });
        }

        self.build_draft(
            source,
            source_digest,
            &slugify(&tool.name),
            &tool.description,
            route,
            tool.input_schema.clone(),
            tool.output_schema.clone(),
            risks,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_draft(
        &self,
        source: &ImportSource,
        source_digest: &str,
        name: &str,
        description: &str,
        route: DraftRoute,
        input_schema: Value,
        output_schema: Value,
        mut risks: Vec<ImportRisk>,
        generated_yaml: Option<String>,
    ) -> CapabilityDraft {
        risks.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.level.cmp(&right.level))
                .then(left.reason.cmp(&right.reason))
        });
        risks.dedup_by(|left, right| left.kind == right.kind && left.field == right.field);

        let review_gates = gates_for_risks(&risks);
        let policy_defaults = policy_for_gates(
            &self.safe_defaults,
            &self.context_integrity_profile,
            &review_gates,
        );
        let id = format!("{}:{}", source_kind_slug(source.kind), slugify(name));
        let digest_input = serde_json::to_vec(&json!({
            "source_digest_sha256": source_digest,
            "id": &id,
            "route": &route,
            "input_schema": &input_schema,
            "output_schema": &output_schema,
            "risks": &risks,
        }))
        .unwrap_or_default();
        let draft_digest = sha256_hex(&digest_input);

        CapabilityDraft {
            id,
            name: slugify(name),
            source_kind: source.kind,
            title: human_title(name),
            description: description.to_string(),
            enabled: self.safe_defaults.drafts_enabled,
            route,
            input_schema,
            output_schema,
            trust_card: TrustCardDraft {
                source_name: source.name.clone(),
                source_kind: source.kind,
                source_digest_sha256: source_digest.to_string(),
                draft_digest_sha256: draft_digest,
                source_uri: source.uri.clone(),
                license: source.license.clone(),
                provenance: source.provenance.clone(),
                evidence: if source.provenance.is_some() {
                    TrustEvidenceLevel::Verified
                } else {
                    TrustEvidenceLevel::Generated
                },
            },
            risks,
            review_gates,
            policy_defaults,
            generated_yaml,
        }
    }

    fn finalize_plan(
        &self,
        source: ImportSource,
        source_digest_sha256: String,
        mut drafts: Vec<CapabilityDraft>,
    ) -> ImportPlan {
        drafts.sort_by(|left, right| left.id.cmp(&right.id));
        let review_gates = aggregate_gates(&drafts);
        let plan_digest_sha256 = plan_digest(&source, &source_digest_sha256, &drafts);

        ImportPlan {
            source,
            source_digest_sha256,
            plan_digest_sha256,
            drafts,
            review_gates,
            safe_defaults: self.safe_defaults.clone(),
            reversible: true,
        }
    }
}
