//! GraphQL schema import — converts SDL or introspection JSON into
//! bounded query/mutation `CapabilityDraft` values.
//!
//! ## Design
//!
//! 1. Parse SDL or introspection JSON
//! 2. Extract query and mutation fields
//! 3. Generate bounded drafts with max depth, max complexity, variable schema
//! 4. Mutations require review; queries are read-only safe
//! 5. Arbitrary caller-supplied query passthrough is rejected

use std::collections::HashMap;

use crate::{Error, Result};

use super::draft::{
    CapabilityDraft, DraftAuth, DraftExample, ImportSourceKind, ReviewState, SafetyClassification,
    TrustCardStub,
};

/// Importer for GraphQL schemas (SDL or introspection JSON).
pub struct GraphQlImporter {
    /// Base URL for the GraphQL endpoint.
    endpoint: String,
    /// Default max query depth.
    max_depth: u32,
    /// Default max query complexity.
    max_complexity: u32,
}

impl GraphQlImporter {
    /// Create a new GraphQL importer.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            max_depth: 5,
            max_complexity: 100,
        }
    }

    /// Set the maximum query depth.
    #[must_use]
    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set the maximum query complexity.
    #[must_use]
    pub fn with_max_complexity(mut self, complexity: u32) -> Self {
        self.max_complexity = complexity;
        self
    }

    /// Import from SDL (Schema Definition Language) string.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDL cannot be parsed.
    pub fn import_sdl(&self, sdl: &str) -> Result<Vec<CapabilityDraft>> {
        let fields = parse_graphql_sdl_fields(sdl)?;
        self.build_drafts(&fields)
    }

    /// Import from introspection JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the introspection result cannot be parsed.
    pub fn import_introspection(&self, json: &str) -> Result<Vec<CapabilityDraft>> {
        let fields = parse_introspection_fields(json)?;
        self.build_drafts(&fields)
    }

    /// Build CapabilityDraft values from parsed field info.
    fn build_drafts(&self, fields: &[GraphQlFieldInfo]) -> Result<Vec<CapabilityDraft>> {
        let mut drafts = Vec::new();
        let source_id = self.endpoint.clone();

        for field in fields {
            let safety = SafetyClassification::from_graphql_op(&field.op_type);
            let review_required = safety.requires_review();

            let trust_card = TrustCardStub {
                reviewer: None,
                notes: format!(
                    "Auto-generated from GraphQL {} schema at {}. Max depth: {}, Max complexity: {}",
                    field.op_type, self.endpoint, self.max_depth, self.max_complexity
                ),
                generated_at: String::new(),
                source_url: self.endpoint.clone(),
                source_hash: String::new(),
                risk_annotations: if review_required {
                    vec![format!(
                        "GraphQL {} operation — requires review before activation",
                        field.op_type
                    )]
                } else {
                    vec![]
                },
            };

            let draft = CapabilityDraft {
                source_kind: ImportSourceKind::GraphQl,
                source_id: source_id.clone(),
                protocol: "graphql".to_string(),
                name: format!("graphql_{}", field.name),
                description: field
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("GraphQL {} {}", field.op_type, field.name)),
                auth: DraftAuth {
                    auth_type: "bearer".to_string(),
                    key: "env:GRAPHQL_TOKEN".to_string(),
                    description: format!("Bearer token for {}", self.endpoint),
                    header: Some("Authorization".to_string()),
                    prefix: Some("Bearer".to_string()),
                    ..Default::default()
                },
                input_schema: build_graphql_input_schema(&field.args),
                output_schema: field.output_type.clone(),
                examples: vec![DraftExample {
                    description: format!("Example for {}", field.name),
                    input: build_example_input(&field.args),
                    output: serde_json::json!({"data": {}}),
                }],
                safety,
                review_state: if review_required {
                    ReviewState::Pending
                } else {
                    ReviewState::Approved
                },
                enabled: !review_required,
                trust_card: Some(trust_card),
                base_url: self.endpoint.clone(),
                path: String::new(),
                auth_required: true,
                max_depth: Some(self.max_depth),
                max_complexity: Some(self.max_complexity),
                tags: vec![format!("graphql-{}", field.op_type)],
                ..Default::default()
            };

            drafts.push(draft);
        }

        // Stable sort by name
        drafts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(drafts)
    }

    /// Reject unbounded query passthrough — caller-supplied arbitrary
    /// GraphQL queries are never accepted without review.
    ///
    /// # Errors
    ///
    /// Always returns an error rejecting unrestricted query passthrough.
    pub fn reject_passthrough() -> Result<Vec<CapabilityDraft>> {
        Err(Error::Config(
            "Arbitrary caller-supplied GraphQL query passthrough is disabled. \
             Import a schema or use reviewed bounded drafts instead."
                .to_string(),
        ))
    }
}

/// Parsed GraphQL field info.
#[derive(Debug, Clone)]
struct GraphQlFieldInfo {
    /// Operation type: query, mutation, subscription.
    op_type: String,
    /// Field name.
    name: String,
    /// Description from the schema.
    description: Option<String>,
    /// Arguments.
    args: Vec<GraphQlArg>,
    /// Output type as JSON Schema.
    output_type: serde_json::Value,
}

/// Parsed GraphQL argument.
#[derive(Debug, Clone)]
struct GraphQlArg {
    name: String,
    arg_type: String,
    required: bool,
    description: Option<String>,
    default_value: Option<serde_json::Value>,
}

/// Minimal SDL parser — extracts query and mutation fields with their args.
fn parse_graphql_sdl_fields(sdl: &str) -> Result<Vec<GraphQlFieldInfo>> {
    let mut fields = Vec::new();
    let mut current_type = String::new();
    let mut in_type = false;
    let mut in_field = false;
    let mut current_field: Option<GraphQlFieldInfo> = None;
    let mut current_description: Option<String> = None;

    for line in sdl.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Track descriptions (comments before fields or types)
        if trimmed.starts_with("\"") && trimmed.ends_with("\"") {
            current_description = Some(trimmed.trim_matches('"').to_string());
            continue;
        }

        // Detect type definitions
        if trimmed.starts_with("type ") {
            let rest = &trimmed[5..];
            if rest.contains("Query") || rest.contains("Mutation") || rest.contains("Subscription")
            {
                current_type = if rest.contains("Query") {
                    "query"
                } else if rest.contains("Mutation") {
                    "mutation"
                } else {
                    "subscription"
                }
                .to_string();
                in_type = true;
                current_description = None;
                continue;
            }
            in_type = false;
            continue;
        }

        if in_type {
            // Check for closing brace
            if trimmed == "}" {
                if let Some(field) = current_field.take() {
                    fields.push(field);
                }
                in_type = false;
                continue;
            }

            // Field definition
            if let Some(field_name) = trimmed
                .split(['(', ':'])
                .next()
                .map(|s| s.trim().to_string())
            {
                if !field_name.is_empty()
                    && !field_name.starts_with('}')
                    && !field_name.starts_with("__")
                {
                    // Extract args
                    let args = if let Some(args_start) = trimmed.find('(') {
                        let args_end = trimmed.find(')').unwrap_or(trimmed.len());
                        let args_str = &trimmed[args_start + 1..args_end];
                        parse_sdl_args(args_str)
                    } else {
                        Vec::new()
                    };

                    // Extract output type
                    let output_type = if let Some(colon_pos) = trimmed.rfind(':') {
                        let type_str = trimmed[colon_pos + 1..].trim();
                        let type_str = type_str.trim_end_matches('!');
                        sdl_type_to_json_schema(type_str)
                    } else {
                        serde_json::json!({"type": "object"})
                    };

                    let desc = current_description.take();

                    fields.push(GraphQlFieldInfo {
                        op_type: current_type.clone(),
                        name: field_name.clone(),
                        description: desc,
                        args,
                        output_type,
                    });
                }
            }
        }
    }

    if fields.is_empty() {
        return Err(Error::Config(
            "No query or mutation fields found in GraphQL SDL. Ensure the schema defines a Query or Mutation type."
                .to_string(),
        ));
    }

    Ok(fields)
}

/// Parse SDL arguments from a string like `name: String!, first: Int = 10`.
fn parse_sdl_args(args_str: &str) -> Vec<GraphQlArg> {
    let mut args = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for ch in args_str.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if let Some(arg) = parse_single_arg(current.trim()) {
                    args.push(arg);
                }
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if let Some(arg) = parse_single_arg(current.trim()) {
        args.push(arg);
    }

    args
}

/// Parse a single SDL argument definition.
fn parse_single_arg(arg_str: &str) -> Option<GraphQlArg> {
    let arg_str = arg_str.trim();
    if arg_str.is_empty() {
        return None;
    }

    let parts: Vec<&str> = arg_str.splitn(2, ':').collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].trim().to_string();
    let rest = parts[1].trim();

    let required = rest.ends_with('!');
    let type_str = if required {
        &rest[..rest.len() - 1]
    } else {
        rest
    };

    let (type_str, default_value) = if let Some(eq_pos) = type_str.find('=') {
        let t = type_str[..eq_pos].trim();
        let dv = type_str[eq_pos + 1..].trim();
        (
            t,
            Some(serde_json::Value::String(dv.to_string())),
        )
    } else {
        (type_str, None)
    };

    Some(GraphQlArg {
        name,
        arg_type: type_str.to_string(),
        required,
        description: None,
        default_value,
    })
}

/// Convert a GraphQL SDL type name to a JSON Schema type.
fn sdl_type_to_json_schema(type_str: &str) -> serde_json::Value {
    let type_str = type_str.trim();
    match type_str {
        "String" | "ID" => serde_json::json!({"type": "string"}),
        "Int" => serde_json::json!({"type": "integer"}),
        "Float" => serde_json::json!({"type": "number"}),
        "Boolean" => serde_json::json!({"type": "boolean"}),
        s if s.starts_with('[') => serde_json::json!({"type": "array"}),
        _ => serde_json::json!({"type": "object"}),
    }
}

/// Parse introspection JSON to extract query/mutation fields.
fn parse_introspection_fields(json: &str) -> Result<Vec<GraphQlFieldInfo>> {
    let root: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        Error::Config(format!("Failed to parse introspection JSON: {e}"))
    })?;

    let data = root.get("data").unwrap_or(&root);
    let schema = data.get("__schema").ok_or_else(|| {
        Error::Config("Introspection result missing '__schema' field".to_string())
    })?;

    let mut fields = Vec::new();

    // Process types for Query, Mutation, Subscription
    if let Some(types) = schema.get("types").and_then(|v| v.as_array()) {
        for ty in types {
            let type_name = ty
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = ty.get("kind").and_then(|v| v.as_str()).unwrap_or("");

            if kind != "OBJECT" {
                continue;
            }

            let op_type = match type_name {
                "Query" => "query",
                "Mutation" => "mutation",
                "Subscription" => "subscription",
                _ => continue,
            };

            if let Some(type_fields) = ty.get("fields").and_then(|v| v.as_array()) {
                for field in type_fields {
                    let name = field
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let description = field
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);

                    let args = if let Some(field_args) =
                        field.get("args").and_then(|v| v.as_array())
                    {
                        field_args
                            .iter()
                            .map(|a| {
                                let arg_name = a
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let arg_type = a
                                    .get("type")
                                    .and_then(|v| v.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("String")
                                    .to_string();
                                let required = a
                                    .get("type")
                                    .and_then(|v| v.get("kind"))
                                    .and_then(|v| v.as_str())
                                    == Some("NON_NULL");
                                let arg_desc = a
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .map(ToString::to_string);
                                GraphQlArg {
                                    name: arg_name,
                                    arg_type,
                                    required,
                                    description: arg_desc,
                                    default_value: a.get("defaultValue").cloned(),
                                }
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    let output_type = field
                        .get("type")
                        .map(|t| introspection_type_to_schema(t, types))
                        .unwrap_or(serde_json::json!({"type": "object"}));

                    fields.push(GraphQlFieldInfo {
                        op_type: op_type.to_string(),
                        name,
                        description,
                        args,
                        output_type,
                    });
                }
            }
        }
    }

    if fields.is_empty() {
        return Err(Error::Config(
            "No query or mutation fields found in introspection result".to_string(),
        ));
    }

    Ok(fields)
}

/// Build JSON Schema for GraphQL field arguments.
fn build_graphql_input_schema(args: &[GraphQlArg]) -> serde_json::Value {
    if args.is_empty() {
        return serde_json::json!({"type": "object"});
    }

    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for arg in args {
        let prop = match arg.arg_type.as_str() {
            "String" | "ID" => serde_json::json!({"type": "string"}),
            "Int" => serde_json::json!({"type": "integer"}),
            "Float" => serde_json::json!({"type": "number"}),
            "Boolean" => serde_json::json!({"type": "boolean"}),
            _ => serde_json::json!({"type": "object"}),
        };

        let mut prop_obj = prop.as_object().cloned().unwrap_or_default();
        if let Some(ref desc) = arg.description {
            prop_obj.insert("description".to_string(), serde_json::Value::String(desc.clone()));
        }
        if let Some(ref default) = arg.default_value {
            prop_obj.insert("default".to_string(), default.clone());
        }

        properties.insert(arg.name.clone(), serde_json::Value::Object(prop_obj));

        if arg.required {
            required.push(serde_json::Value::String(arg.name.clone()));
        }
    }

    if required.is_empty() {
        serde_json::json!({"type": "object", "properties": properties})
    } else {
        serde_json::json!({"type": "object", "properties": properties, "required": required})
    }
}

/// Build example input from GraphQL args.
fn build_example_input(args: &[GraphQlArg]) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for arg in args {
        let val = match arg.arg_type.as_str() {
            "String" | "ID" => serde_json::json!("example"),
            "Int" => serde_json::json!(1),
            "Float" => serde_json::json!(1.0),
            "Boolean" => serde_json::json!(true),
            _ => serde_json::json!({}),
        };
        obj.insert(arg.name.clone(), val);
    }
    serde_json::Value::Object(obj)
}

/// Convert an introspection type reference to JSON Schema.
fn introspection_type_to_schema(
    type_ref: &serde_json::Value,
    all_types: &[serde_json::Value],
) -> serde_json::Value {
    let kind = type_ref
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("SCALAR");
    let name = type_ref
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match kind {
        "SCALAR" => match name {
            "String" | "ID" => serde_json::json!({"type": "string"}),
            "Int" => serde_json::json!({"type": "integer"}),
            "Float" => serde_json::json!({"type": "number"}),
            "Boolean" => serde_json::json!({"type": "boolean"}),
            _ => serde_json::json!({"type": "string"}),
        },
        "NON_NULL" => {
            if let Some(of_type) = type_ref.get("ofType") {
                introspection_type_to_schema(of_type, all_types)
            } else {
                serde_json::json!({"type": "object"})
            }
        }
        "LIST" => serde_json::json!({"type": "array"}),
        "OBJECT" | "INTERFACE" | "UNION" => serde_json::json!({"type": "object"}),
        "ENUM" => {
            // Try to find enum values
            if let Some(enum_type) = all_types
                .iter()
                .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
            {
                if let Some(values) = enum_type.get("enumValues").and_then(|v| v.as_array()) {
                    let enum_vals: Vec<String> = values
                        .iter()
                        .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(ToString::to_string))
                        .collect();
                    return serde_json::json!({"type": "string", "enum": enum_vals});
                }
            }
            serde_json::json!({"type": "string"})
        }
        _ => serde_json::json!({"type": "object"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SDL: &str = r#"
type Query {
    """Get a user by ID"""
    user(id: ID!): User
    """List all users"""
    users(first: Int = 10): [User]
}

type Mutation {
    """Create a new user"""
    createUser(name: String!, email: String!): User
    """Delete a user"""
    deleteUser(id: ID!): Boolean
}

type User {
    id: ID!
    name: String!
    email: String
}
"#;

    #[test]
    fn parse_sdl_extracts_query_and_mutation_fields() {
        let fields = parse_graphql_sdl_fields(TEST_SDL).unwrap();
        // 2 queries + 2 mutations
        assert_eq!(fields.len(), 4, "expected 4 fields, got {}", fields.len());

        let query_names: Vec<&str> = fields
            .iter()
            .filter(|f| f.op_type == "query")
            .map(|f| f.name.as_str())
            .collect();
        assert!(query_names.contains(&"user"));
        assert!(query_names.contains(&"users"));

        let mutation_names: Vec<&str> = fields
            .iter()
            .filter(|f| f.op_type == "mutation")
            .map(|f| f.name.as_str())
            .collect();
        assert!(mutation_names.contains(&"createUser"));
        assert!(mutation_names.contains(&"deleteUser"));
    }

    #[test]
    fn import_sdl_query_drafts_are_read_only_approved() {
        let importer = GraphQlImporter::new("https://api.example.com/graphql");
        let drafts = importer.import_sdl(TEST_SDL).unwrap();

        let user_draft = drafts.iter().find(|d| d.name == "graphql_user").unwrap();
        assert_eq!(user_draft.safety, SafetyClassification::ReadOnly);
        assert_eq!(user_draft.review_state, ReviewState::Approved);
        assert!(user_draft.enabled);
        // AC.3: query fixtures produce reviewed-safe read draft
    }

    #[test]
    fn import_sdl_mutation_drafts_require_review() {
        let importer = GraphQlImporter::new("https://api.example.com/graphql");
        let drafts = importer.import_sdl(TEST_SDL).unwrap();

        let create_draft = drafts
            .iter()
            .find(|d| d.name == "graphql_createUser")
            .unwrap();
        // AC.3: mutation fixture produces review_required=true
        assert_eq!(create_draft.safety, SafetyClassification::Mutation);
        assert!(create_draft.review_required());
        assert!(!create_draft.enabled);
    }

    #[test]
    fn unbounded_query_passthrough_is_rejected() {
        // AC.3: unbounded query passthrough is rejected
        let result = GraphQlImporter::reject_passthrough();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("passthrough is disabled"),
            "expected passthrough rejection: {err}"
        );
    }

    #[test]
    fn drafts_include_max_depth_and_complexity() {
        let importer = GraphQlImporter::new("https://api.example.com/graphql")
            .with_max_depth(3)
            .with_max_complexity(50);
        let drafts = importer.import_sdl(TEST_SDL).unwrap();

        for draft in &drafts {
            assert_eq!(draft.max_depth, Some(3));
            assert_eq!(draft.max_complexity, Some(50));
        }
    }

    #[test]
    fn empty_sdl_returns_error() {
        let importer = GraphQlImporter::new("https://api.example.com/graphql");
        let result = importer.import_sdl("type Unrelated { foo: String }");
        assert!(result.is_err());
    }

    #[test]
    fn parse_sdl_with_descriptions() {
        let fields = parse_graphql_sdl_fields(TEST_SDL).unwrap();
        let user_field = fields.iter().find(|f| f.name == "user").unwrap();
        assert_eq!(
            user_field.description,
            Some("Get a user by ID".to_string())
        );
    }

    #[test]
    fn graphql_drafts_have_deterministic_order() {
        let importer = GraphQlImporter::new("https://api.example.com/graphql");
        let drafts1 = importer.import_sdl(TEST_SDL).unwrap();
        let drafts2 = importer.import_sdl(TEST_SDL).unwrap();

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2, "draft order must be deterministic");
    }
}
