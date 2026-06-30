//! Postman collection import — converts collection items, folders, auth,
//! variables, request bodies, tests/examples, and HTTP methods into
//! `CapabilityDraft` records with deterministic names and safety classifications.

use std::collections::HashMap;

use crate::{Error, Result};

use super::draft::{CapabilityDraft, DraftAuth, ImportSourceKind, ReviewState, SafetyClassification};

/// Importer for Postman collections (v2.0 and v2.1).
pub struct PostmanImporter {
    /// Prefix for generated capability names.
    prefix: Option<String>,
    /// Default base URL override.
    base_url_override: Option<String>,
}

impl PostmanImporter {
    /// Create a new Postman importer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: None,
            base_url_override: None,
        }
    }

    /// Set a prefix for generated capability names.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    /// Override the base URL from the collection.
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url_override = Some(url.to_string());
        self
    }

    /// Import a Postman collection JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON cannot be parsed as a Postman collection.
    pub fn import_json(&self, json: &str) -> Result<Vec<CapabilityDraft>> {
        let collection: PostmanCollection = serde_json::from_str(json).map_err(|e| {
            Error::Config(format!("Failed to parse Postman collection: {e}"))
        })?;

        let source_id = collection
            .info
            .name
            .clone()
            .unwrap_or_else(|| "postman-collection".to_string());

        // Resolve variables
        let variables = resolve_postman_variables(&collection.variable);

        // Extract auth info
        let auth_info = extract_postman_auth(&collection.auth);

        let mut drafts = Vec::new();

        // Process items recursively
        self.process_items(
            &collection.item,
            &variables,
            &auth_info,
            &source_id,
            &mut drafts,
        )?;

        // Stable sort by name
        drafts.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(drafts)
    }

    /// Recursively process Postman items and folders.
    fn process_items(
        &self,
        items: &[PostmanItem],
        variables: &HashMap<String, String>,
        auth_info: &DraftAuth,
        source_id: &str,
        drafts: &mut Vec<CapabilityDraft>,
    ) -> Result<()> {
        for item in items {
            // If this is a folder, recurse into its items
            if !item.item.is_empty() {
                self.process_items(&item.item, variables, auth_info, source_id, drafts)?;
            }

            // If this has a request, convert it
            if let Some(ref request) = item.request {
                if let Some(draft) =
                    self.convert_request(item, request, variables, auth_info, source_id)
                {
                    drafts.push(draft);
                }
            }
        }
        Ok(())
    }

    /// Convert a single Postman request to a CapabilityDraft.
    fn convert_request(
        &self,
        item: &PostmanItem,
        request: &PostmanRequest,
        variables: &HashMap<String, String>,
        auth_info: &DraftAuth,
        source_id: &str,
    ) -> Option<CapabilityDraft> {
        let method = request.method.to_uppercase();
        let raw_url = request.url.as_ref()?;
        let url = resolve_variables(raw_url, variables);

        // Parse URL into base_url and path
        let (base_url, path, query_params) = parse_postman_url(&url);

        let base_url = self
            .base_url_override
            .clone()
            .unwrap_or(base_url);

        // Generate name from item name, folder context, and method
        let name = self.generate_name(item, &method);

        let safety = SafetyClassification::from_http_method(&method);
        let review_required = safety.requires_review();

        // Build input schema from request body and headers
        let input_schema = build_postman_input_schema(request);

        // Build output schema from test/examples
        let output_schema = extract_postman_output(request);

        // Extract examples from request body and example responses
        let examples = extract_postman_examples(item, request);

        // Build headers from request
        let headers = extract_postman_headers(request, auth_info, variables);

        let draft = CapabilityDraft {
            source_kind: ImportSourceKind::Postman,
            source_id: source_id.to_string(),
            protocol: "rest".to_string(),
            name,
            description: item
                .name
                .clone()
                .unwrap_or_else(|| format!("{} request", method)),
            auth: auth_info.clone(),
            input_schema,
            output_schema,
            examples,
            safety,
            review_state: if review_required {
                ReviewState::Pending
            } else {
                ReviewState::Approved
            },
            enabled: !review_required,
            trust_card: None,
            http_method: method.clone(),
            base_url: base_url.clone(),
            path: path.clone(),
            request_body: request.body.as_ref().and_then(|b| {
                b.raw.clone().and_then(|raw| {
                    serde_json::from_str(&resolve_variables(&raw, variables)).ok()
                })
            }),
            headers: headers.clone(),
            query_params,
            auth_required: auth_info.auth_type != "none",
            tags: Vec::new(),
            ..Default::default()
        };

        Some(draft)
    }

    /// Generate a deterministic capability name.
    fn generate_name(&self, item: &PostmanItem, method: &str) -> String {
        let raw = item
            .name
            .as_deref()
            .unwrap_or("unnamed")
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>();

        // Remove duplicate underscores
        let mut result = String::new();
        let mut prev = false;
        for c in raw.chars() {
            if c == '_' {
                if !prev {
                    result.push(c);
                }
                prev = true;
            } else {
                result.push(c);
                prev = false;
            }
        }
        let cleaned = result.trim_matches('_').to_string();

        let base = format!("{}_{}", method.to_lowercase(), cleaned);

        if let Some(ref prefix) = self.prefix {
            format!("{}_{}", prefix, base)
        } else {
            base
        }
    }
}

// ── Postman JSON types ────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct PostmanCollection {
    info: PostmanInfo,
    #[serde(default)]
    item: Vec<PostmanItem>,
    #[serde(default)]
    auth: Option<PostmanAuth>,
    #[serde(default)]
    variable: Vec<PostmanVariable>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    schema: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanItem {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    request: Option<PostmanRequest>,
    #[serde(default)]
    item: Vec<PostmanItem>,
    #[serde(default)]
    response: Vec<PostmanResponse>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    header: Vec<PostmanHeader>,
    #[serde(default)]
    body: Option<PostmanBody>,
    #[serde(default)]
    auth: Option<PostmanAuth>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanHeader {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanBody {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    raw: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanResponse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    code: Option<u16>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanAuth {
    #[serde(rename = "type", default)]
    auth_type: String,
    #[serde(default)]
    apikey: Option<Vec<PostmanAuthValue>>,
    #[serde(default)]
    bearer: Option<Vec<PostmanAuthValue>>,
    #[serde(default)]
    basic: Option<Vec<PostmanAuthValue>>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanAuthValue {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanVariable {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn resolve_postman_variables(vars: &[PostmanVariable]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for v in vars {
        map.insert(format!("{{{{{}}}}}", v.key), v.value.clone());
    }
    map
}

fn resolve_variables(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (placeholder, value) in vars {
        result = result.replace(placeholder.as_str(), value.as_str());
    }
    result
}

fn parse_postman_url(url: &str) -> (String, String, HashMap<String, String>) {
    // Simple URL parsing — extract scheme+host as base_url and path+query as path
    if let Ok(parsed) = url::Url::parse(url) {
        let base = format!(
            "{}://{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or("localhost")
        );
        let path = parsed.path().to_string();
        let params: HashMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        (base, path, params)
    } else {
        // Fallback: treat as path only
        ("https://api.example.com".to_string(), url.to_string(), HashMap::new())
    }
}

fn extract_postman_auth(auth: &Option<PostmanAuth>) -> DraftAuth {
    let Some(auth) = auth else {
        return DraftAuth::default();
    };

    match auth.auth_type.as_str() {
        "apikey" => {
            let key = auth
                .apikey
                .as_ref()
                .and_then(|v| v.iter().find(|a| a.key == "value"))
                .map(|a| a.value.clone())
                .unwrap_or_else(|| "env:API_KEY".to_string());
            let header = auth
                .apikey
                .as_ref()
                .and_then(|v| v.iter().find(|a| a.key == "key"))
                .map(|a| a.value.clone());
            DraftAuth {
                auth_type: "api_key".to_string(),
                key,
                description: "API key from Postman collection".to_string(),
                header,
                prefix: None,
                ..Default::default()
            }
        }
        "bearer" => {
            let token = auth
                .bearer
                .as_ref()
                .and_then(|v| v.iter().find(|a| a.key == "token"))
                .map(|a| a.value.clone())
                .unwrap_or_else(|| "env:BEARER_TOKEN".to_string());
            DraftAuth {
                auth_type: "bearer".to_string(),
                key: token,
                description: "Bearer token from Postman collection".to_string(),
                header: Some("Authorization".to_string()),
                prefix: Some("Bearer".to_string()),
                ..Default::default()
            }
        }
        "basic" => DraftAuth {
            auth_type: "basic".to_string(),
            key: "env:BASIC_AUTH".to_string(),
            description: "HTTP Basic auth from Postman collection".to_string(),
            header: Some("Authorization".to_string()),
            prefix: Some("Basic".to_string()),
            ..Default::default()
        },
        _ => DraftAuth::default(),
    }
}

fn build_postman_input_schema(request: &PostmanRequest) -> serde_json::Value {
    let mut properties = serde_json::Map::new();

    // Add headers as properties (except auth headers)
    for header in &request.header {
        let key = header.key.to_lowercase();
        if key == "authorization" || key == "content-type" {
            continue;
        }
        properties.insert(
            header.key.clone(),
            serde_json::json!({"type": "string", "description": format!("Header: {}", header.key)}),
        );
    }

    // Add body schema if present
    if let Some(ref body) = request.body
        && let Some(ref raw) = body.raw
    {
        if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(body_props) = json_body.get("properties").and_then(|v| v.as_object()) {
                for (k, v) in body_props {
                    properties.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
    }

    if properties.is_empty() {
        serde_json::json!({"type": "object"})
    } else {
        serde_json::json!({"type": "object", "properties": properties})
    }
}

fn extract_postman_output(request: &PostmanRequest) -> serde_json::Value {
    // Default output schema — Postman doesn't define response schemas
    // natively, so we use a generic JSON object
    if let Some(ref body) = request.body
        && let Some(ref raw) = body.raw
    {
        // Try to infer from request body structure
        if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(raw) {
            if json_body.is_object() {
                return serde_json::json!({"type": "object"});
            }
            if json_body.is_array() {
                return serde_json::json!({"type": "array"});
            }
        }
    }

    serde_json::json!({"type": "object"})
}

fn extract_postman_examples(
    item: &PostmanItem,
    request: &PostmanRequest,
) -> Vec<super::draft::DraftExample> {
    let mut examples = Vec::new();

    // Input example from request body
    let input = request
        .body
        .as_ref()
        .and_then(|b| b.raw.as_deref())
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(serde_json::json!({}));

    // Output examples from response items
    for response in &item.response {
        let output = response
            .body
            .as_deref()
            .and_then(|body| serde_json::from_str(body).ok())
            .unwrap_or(serde_json::json!({}));

        let description = response
            .name
            .clone()
            .unwrap_or_else(|| format!("Response {}", response.code.unwrap_or(0)));

        examples.push(super::draft::DraftExample {
            description,
            input: input.clone(),
            output,
        });
    }

    // If no response examples, include at least the input shape
    if examples.is_empty() {
        examples.push(super::draft::DraftExample {
            description: "Request example".to_string(),
            input: input.clone(),
            output: serde_json::json!({"type": "object"}),
        });
    }

    examples
}

fn extract_postman_headers(
    request: &PostmanRequest,
    auth_info: &DraftAuth,
    variables: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for header in &request.header {
        let key = header.key.to_lowercase();
        if key == "authorization" && auth_info.auth_type != "none" {
            continue; // Auth injected separately
        }
        headers.insert(header.key.clone(), resolve_variables(&header.value, variables));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    const POSTMAN_V21_FIXTURE: &str = r#"{
  "info": {
    "name": "Test API Collection",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Get Users",
      "request": {
        "method": "GET",
        "url": "https://api.example.com/v1/users",
        "header": [
          { "key": "Accept", "value": "application/json" }
        ]
      },
      "response": [
        {
          "name": "User list",
          "body": "[{\"id\": 1, \"name\": \"Alice\"}]",
          "code": 200
        }
      ]
    },
    {
      "name": "Create User",
      "request": {
        "method": "POST",
        "url": "https://api.example.com/v1/users",
        "header": [
          { "key": "Content-Type", "value": "application/json" }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\"name\": \"Bob\", \"email\": \"bob@example.com\"}"
        }
      },
      "response": []
    },
    {
      "name": "Delete User",
      "request": {
        "method": "DELETE",
        "url": "https://api.example.com/v1/users/123"
      },
      "response": []
    }
  ],
  "auth": {
    "auth_type": "bearer",
    "bearer": [
      { "key": "token", "value": "{{BEARER_TOKEN}}" }
    ]
  },
  "variable": [
    { "key": "BASE_URL", "value": "https://api.example.com" }
  ]
}"#;

    #[test]
    fn import_postman_v21_collection() {
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        // 3 items
        assert_eq!(drafts.len(), 3);

        // Names are deterministic
        let names: Vec<&str> = drafts.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"post_create_user"));
        assert!(names.contains(&"delete_delete_user"));
        assert!(names.contains(&"get_get_users"));
    }

    #[test]
    fn postman_read_only_drafts_are_enabled() {
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let get_draft = drafts
            .iter()
            .find(|d| d.name == "get_get_users")
            .unwrap();
        assert_eq!(get_draft.safety, SafetyClassification::ReadOnly);
        assert!(get_draft.enabled);
    }

    #[test]
    fn postman_mutation_drafts_require_review() {
        // AC.4: mutating requests marked review-required
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let post_draft = drafts
            .iter()
            .find(|d| d.name == "post_create_user")
            .unwrap();
        assert!(post_draft.review_required());
        assert!(!post_draft.enabled);

        let delete_draft = drafts
            .iter()
            .find(|d| d.name == "delete_delete_user")
            .unwrap();
        assert!(delete_draft.review_required());
        assert!(!delete_draft.enabled);
    }

    #[test]
    fn postman_import_with_prefix() {
        let importer = PostmanImporter::new().with_prefix("mytest");
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        for draft in &drafts {
            assert!(
                draft.name.starts_with("mytest_"),
                "expected prefix mytest_: {}",
                draft.name
            );
        }
    }

    #[test]
    fn postman_import_is_deterministic() {
        let importer = PostmanImporter::new();
        let drafts1 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();
        let drafts2 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2);
    }

    #[test]
    fn postman_drafts_include_examples() {
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let get_draft = drafts
            .iter()
            .find(|d| d.name == "get_get_users")
            .unwrap();
        assert!(!get_draft.examples.is_empty(), "should have examples");
    }

    #[test]
    fn postman_auth_is_extracted() {
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        for draft in &drafts {
            assert_eq!(draft.auth.auth_type, "bearer");
            assert!(draft.auth_required);
        }
    }

    #[test]
    fn postman_invalid_json_returns_error() {
        let importer = PostmanImporter::new();
        let result = importer.import_json("not json");
        assert!(result.is_err());
    }
}
