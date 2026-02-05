//! UX validation for MCP server tool definitions
//!
//! This module implements agent-UX best practices inspired by Phil Schmid's
//! "MCP is a UI for Agents" principles. It validates tool definitions against
//! standards for naming, descriptions, parameters, and response design.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  Capability     │
//! │  Definition     │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │  Rule Checker   │────▶│   Violations    │
//! │  (rules.rs)     │     │  (Error/Warn)   │
//! └─────────────────┘     └────────┬────────┘
//!                                  │
//!                                  ▼
//!                         ┌─────────────────┐
//!                         │  Report Builder │
//!                         │  (report.rs)    │
//!                         └─────────────────┘
//! ```

mod report;
mod rules;

pub use report::{ValidationReport, ViolationSeverity};
pub use rules::Violation;

use crate::capability::CapabilityDefinition;

/// Validate a capability definition against agent-UX best practices
pub fn validate_ux(capability: &CapabilityDefinition) -> ValidationReport {
    let mut violations = Vec::new();

    // Run all validation rules
    violations.extend(rules::check_tool_naming(capability));
    violations.extend(rules::check_description_quality(capability));
    violations.extend(rules::check_parameter_validation(capability));
    violations.extend(rules::check_response_design(capability));
    violations.extend(rules::check_naming_consistency(capability));

    ValidationReport::new(capability.name.clone(), violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityMetadata, ProvidersConfig, SchemaDefinition,
    };

    fn create_test_capability(name: &str, description: &str) -> CapabilityDefinition {
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: name.to_string(),
            description: description.to_string(),
            schema: SchemaDefinition::default(),
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
        }
    }

    #[test]
    fn test_validate_good_capability() {
        let cap = create_test_capability(
            "searchDocuments",
            "Search through user documents when they need to find specific files or content",
        );
        let report = validate_ux(&cap);
        // Only info-level suggestions are okay for a "good" capability
        for v in report.violations() {
            assert_eq!(
                v.severity,
                crate::validator::ViolationSeverity::Info,
                "Expected only info violations, got {:?}: {}",
                v.severity,
                v.message
            );
        }
    }

    #[test]
    fn test_validate_poor_naming() {
        let cap = create_test_capability("run", "Run something");
        let report = validate_ux(&cap);
        assert!(!report.violations().is_empty());
        assert!(report
            .violations()
            .iter()
            .any(|v| v.rule_id == "tool_name_generic"));
    }

    #[test]
    fn test_validate_short_description() {
        let cap = create_test_capability("searchDocs", "Search");
        let report = validate_ux(&cap);
        assert!(!report.violations().is_empty());
        assert!(report
            .violations()
            .iter()
            .any(|v| v.rule_id == "description_too_short"));
    }
}
