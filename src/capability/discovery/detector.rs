//! `SpecDetector` — reliable format sniffing from raw content.
//!
//! Parses the content as JSON or YAML and inspects the root object for
//! canonical version keys to distinguish `OpenAPI` 3.x, Swagger 2.0, and
//! GraphQL introspection results.

use serde_json::Value;

/// Detects the exact spec format and version from raw content.
pub struct SpecDetector;

impl SpecDetector {
    /// Detect the API spec format from raw content (JSON or YAML).
    ///
    /// Returns `None` if the content cannot be parsed or does not match any
    /// known spec format.
    #[must_use]
    pub fn detect(content: &str) -> Option<super::SpecFormat> {
        // Try JSON first (faster parse for JSON specs)
        if let Ok(json) = serde_json::from_str::<Value>(content) {
            return Self::detect_from_value(&json);
        }
        // Try YAML (also covers JSON-subset YAML)
        if let Ok(val) = serde_yaml::from_str::<Value>(content) {
            return Self::detect_from_value(&val);
        }
        // GraphQL check on raw string (in case JSON parse fails partially)
        if content.contains("__schema") && content.contains("queryType") {
            return Some(super::SpecFormat::GraphQL);
        }
        None
    }

    /// Detect format from a parsed JSON/YAML value.
    fn detect_from_value(val: &Value) -> Option<super::SpecFormat> {
        // OpenAPI 3.x: root key "openapi" with value starting "3."
        if let Some(v) = val.get("openapi").and_then(Value::as_str)
            && v.starts_with('3')
        {
            return Some(super::SpecFormat::OpenApi3);
        }
        // Also accept "openapi" key without version check (forward-compatible)
        if val.get("openapi").is_some() {
            return Some(super::SpecFormat::OpenApi3);
        }

        // Swagger 2.0: root key "swagger" with value "2.0"
        if val.get("swagger").is_some() {
            return Some(super::SpecFormat::Swagger2);
        }

        // GraphQL introspection result: data.__schema or __schema
        if val.pointer("/data/__schema").is_some() || val.get("__schema").is_some() {
            return Some(super::SpecFormat::GraphQL);
        }

        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::discovery::SpecFormat;

    #[test]
    fn detect_openapi3_json() {
        let content = r#"{"openapi":"3.0.0","info":{"title":"Test","version":"1.0"},"paths":{}}"#;
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::OpenApi3));
    }

    #[test]
    fn detect_openapi3_yaml() {
        let content = "openapi: '3.1.0'\ninfo:\n  title: Test\n  version: '1.0'\npaths: {}";
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::OpenApi3));
    }

    #[test]
    fn detect_swagger2_json() {
        let content = r#"{"swagger":"2.0","info":{"title":"Test","version":"1.0"},"paths":{}}"#;
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::Swagger2));
    }

    #[test]
    fn detect_swagger2_yaml() {
        let content = "swagger: '2.0'\ninfo:\n  title: Test\n  version: '1.0'\npaths: {}";
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::Swagger2));
    }

    #[test]
    fn detect_graphql_with_data_wrapper() {
        let content = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}"#;
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::GraphQL));
    }

    #[test]
    fn detect_graphql_without_data_wrapper() {
        let content = r#"{"__schema":{"queryType":{"name":"Query"},"types":[]}}"#;
        assert_eq!(SpecDetector::detect(content), Some(SpecFormat::GraphQL));
    }

    #[test]
    fn detect_unknown_returns_none() {
        let content = r#"{"message":"Not found"}"#;
        assert_eq!(SpecDetector::detect(content), None);
    }

    #[test]
    fn detect_html_returns_none() {
        let content = "<html><body>Not a spec</body></html>";
        assert_eq!(SpecDetector::detect(content), None);
    }

    #[test]
    fn detect_empty_returns_none() {
        assert_eq!(SpecDetector::detect(""), None);
    }
}
