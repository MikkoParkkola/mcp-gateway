//! Skill document renderer.
//!
//! Converts [`CapabilityDefinition`] instances into two Markdown artefacts:
//!
//! - `SKILL.md` — a category-level index table (YAML front-matter + Markdown)
//! - `commands/<name>.md` — a per-capability reference doc
//!
//! The renderer is intentionally pure (no I/O) so it can be tested without a
//! filesystem and reused from both the CLI and the hot-reload path.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::capability::{AuthConfig, CapabilityDefinition, CapabilityMetadata};

/// A pair of rendered Markdown documents for a single category.
#[derive(Debug, Clone)]
pub struct SkillBundle {
    /// Category identifier (lowercased, used as directory name)
    pub category: String,
    /// Content for `SKILL.md`
    pub skill_index: String,
    /// Per-command docs: `(capability_name, markdown_content)`
    pub command_docs: Vec<(String, String)>,
}

/// Render agent skill bundles from a slice of capability definitions.
///
/// Capabilities are grouped by `metadata.category`.  Capabilities without a
/// category are placed into a synthetic `"general"` category.
#[must_use]
pub fn render_bundles(capabilities: &[CapabilityDefinition]) -> Vec<SkillBundle> {
    let grouped = group_by_category(capabilities);
    grouped
        .into_iter()
        .map(|(category, caps)| render_bundle(&category, &caps))
        .collect()
}

/// Render a single bundle from capabilities that share a category.
#[must_use]
pub fn render_bundle(category: &str, capabilities: &[&CapabilityDefinition]) -> SkillBundle {
    let skill_index = render_skill_index(category, capabilities);
    let command_docs = capabilities
        .iter()
        .map(|cap| (cap.name.clone(), render_command_doc(cap)))
        .collect();

    SkillBundle {
        category: category.to_owned(),
        skill_index,
        command_docs,
    }
}

/// Group capabilities by their `metadata.category`, falling back to `"general"`.
fn group_by_category<'a>(
    capabilities: &'a [CapabilityDefinition],
) -> HashMap<String, Vec<&'a CapabilityDefinition>> {
    let mut map: HashMap<String, Vec<&'a CapabilityDefinition>> = HashMap::new();
    for cap in capabilities {
        let key = effective_category(&cap.metadata);
        map.entry(key).or_default().push(cap);
    }
    map
}

fn effective_category(meta: &CapabilityMetadata) -> String {
    if meta.category.is_empty() {
        "general".to_owned()
    } else {
        meta.category.to_lowercase()
    }
}

// ── SKILL.md ─────────────────────────────────────────────────────────────────

fn render_skill_index(category: &str, capabilities: &[&CapabilityDefinition]) -> String {
    let display_name = capitalize(category);
    let description = generate_category_description(category, capabilities);
    let table = render_index_table(capabilities);

    format!(
        "---\nname: mcp-gateway-{category}\ndescription: {description}\n---\n\
         # MCP Gateway {display_name} Skills\n\n{table}\n\
         Use `loadSkill` to read detailed command documentation.\n"
    )
}

fn generate_category_description(category: &str, capabilities: &[&CapabilityDefinition]) -> String {
    let display = capitalize(category);
    let count = capabilities.len();
    format!(
        "{display} tools via MCP Gateway ({count} command{s})",
        s = plural(count)
    )
}

fn render_index_table(capabilities: &[&CapabilityDefinition]) -> String {
    let mut rows = String::from(
        "| Command | Description | Auth Required |\n\
         |---------|-------------|---------------|\n",
    );
    // Sort for deterministic output
    let mut sorted = capabilities.to_vec();
    sorted.sort_by_key(|c| &c.name);
    for cap in &sorted {
        let auth = if cap.auth.required { "yes" } else { "no" };
        let desc = truncate(&cap.description, 80);
        let _ = writeln!(rows, "| {} | {} | {} |", cap.name, desc, auth);
    }
    rows
}

// ── per-command doc ───────────────────────────────────────────────────────────

/// Render a standalone `commands/<name>.md` document.
#[must_use]
pub fn render_command_doc(cap: &CapabilityDefinition) -> String {
    let mut doc = format!("# {}\n{}\n\n", cap.name, cap.description);
    doc.push_str(&render_parameters_section(&cap.schema.input));
    doc.push_str(&render_auth_section(&cap.auth));
    doc.push_str(&render_cost_section(cap));
    doc.push_str(&render_guidance_section(cap));
    doc
}

fn render_parameters_section(schema: &serde_json::Value) -> String {
    let Some(props) = schema.get("properties").and_then(|v| v.as_object()) else {
        return String::new();
    };

    let required_set: std::collections::HashSet<&str> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut table = String::from(
        "## Parameters\n\
         | Name | Type | Required | Description |\n\
         |------|------|----------|-------------|\n",
    );

    // Sort for deterministic output
    let mut names: Vec<&str> = props.keys().map(String::as_str).collect();
    names.sort_unstable();
    for name in names {
        let prop = &props[name];
        let typ = prop.get("type").and_then(|v| v.as_str()).unwrap_or("any");
        let req = if required_set.contains(name) {
            "yes"
        } else {
            "no"
        };
        let desc = prop
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let _ = writeln!(table, "| {name} | {typ} | {req} | {desc} |");
    }

    table.push('\n');
    table
}

fn render_auth_section(auth: &AuthConfig) -> String {
    if !auth.required {
        return "## Authentication\nNone required.\n\n".to_owned();
    }

    let mut section = "## Authentication\n".to_owned();
    let _ = writeln!(section, "- **Type**: {}", auth.auth_type);

    if !auth.key.is_empty() {
        let _ = writeln!(section, "- **Credential**: `{}`", auth.key);
    }
    if !auth.scopes.is_empty() {
        let _ = writeln!(section, "- **Scopes**: {}", auth.scopes.join(", "));
    }
    if !auth.description.is_empty() {
        let _ = writeln!(section, "- {}", auth.description);
    }
    section.push('\n');
    section
}

fn render_cost_section(cap: &CapabilityDefinition) -> String {
    let cost = cap.primary_provider().map_or(0.0, |p| p.cost_per_call);

    let cost_category = &cap.metadata.cost_category;

    let mut section = "## Cost\n".to_owned();
    if cost > 0.0 {
        let _ = write!(section, "~${cost:.4} per call");
        if !cost_category.is_empty() {
            let _ = write!(section, " ({cost_category})");
        }
        section.push('\n');
    } else if !cost_category.is_empty() {
        let _ = writeln!(section, "{}", capitalize(cost_category));
    } else {
        section.push_str("Free\n");
    }
    section.push('\n');
    section
}

fn render_guidance_section(cap: &CapabilityDefinition) -> String {
    let mut points: Vec<String> = Vec::new();

    if cap.metadata.read_only {
        points.push("Safe to use without confirmation (read-only operation).".to_owned());
    } else {
        points.push("Mutating operation — confirm intent before invoking.".to_owned());
    }

    let cost = cap.primary_provider().map_or(0.0, |p| p.cost_per_call);
    if cost > 0.0 {
        points.push(format!("Costs ~${cost:.4} per call."));
    }

    if !cap.metadata.chains_with.is_empty() {
        points.push(format!(
            "Commonly used with: {}.",
            cap.metadata.chains_with.join(", ")
        ));
    }

    if cap.is_cacheable() {
        points.push(format!(
            "Responses cached for {} seconds ({}).",
            cap.cache.ttl, cap.cache.strategy
        ));
    }

    if !cap.metadata.produces.is_empty() {
        points.push(format!("Produces: {}.", cap.metadata.produces.join(", ")));
    }
    if !cap.metadata.consumes.is_empty() {
        points.push(format!("Requires: {}.", cap.metadata.consumes.join(", ")));
    }

    if points.is_empty() {
        return String::new();
    }

    let mut section = "## Agent Guidance\n".to_owned();
    for point in &points {
        let _ = writeln!(section, "- {point}");
    }
    section.push('\n');
    section
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        // Find a clean char boundary
        &s[..s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max)
            .last()
            .unwrap_or(max)]
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProviderConfig,
        ProvidersConfig, SchemaDefinition,
    };
    use serde_json::json;

    fn make_cap(
        name: &str,
        category: &str,
        read_only: bool,
        auth_required: bool,
    ) -> CapabilityDefinition {
        CapabilityDefinition {
            fulcrum: "1.0".to_owned(),
            name: name.to_owned(),
            description: format!("Description for {name}"),
            schema: SchemaDefinition {
                input: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" },
                        "limit": { "type": "integer", "description": "Max results" }
                    },
                    "required": ["query"]
                }),
                output: serde_json::Value::Null,
            },
            providers: {
                let mut named = std::collections::HashMap::new();
                named.insert(
                    "primary".to_owned(),
                    ProviderConfig {
                        service: "rest".to_owned(),
                        cost_per_call: 0.0,
                        timeout: 30,
                        config: Default::default(),
                    },
                );
                ProvidersConfig {
                    named,
                    fallback: vec![],
                }
            },
            auth: AuthConfig {
                required: auth_required,
                auth_type: if auth_required {
                    "api_key".to_owned()
                } else {
                    String::new()
                },
                key: if auth_required {
                    "env:API_KEY".to_owned()
                } else {
                    String::new()
                },
                ..Default::default()
            },
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata {
                category: category.to_owned(),
                read_only,
                ..Default::default()
            },
            transform: Default::default(),
            webhooks: Default::default(),
        }
    }

    // ── render_command_doc ────────────────────────────────────────────────────

    #[test]
    fn render_command_doc_contains_name_and_description() {
        // GIVEN: a minimal capability
        let cap = make_cap("my_tool", "search", true, false);
        // WHEN: rendered
        let doc = render_command_doc(&cap);
        // THEN: name and description appear
        assert!(doc.contains("# my_tool"));
        assert!(doc.contains("Description for my_tool"));
    }

    #[test]
    fn render_command_doc_parameters_table_has_required_column() {
        // GIVEN: capability with required "query" and optional "limit"
        let cap = make_cap("search_tool", "search", true, false);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: query is required, limit is not
        assert!(doc.contains("| query | string | yes |"));
        assert!(doc.contains("| limit | integer | no |"));
    }

    #[test]
    fn render_command_doc_auth_section_no_auth() {
        // GIVEN: no-auth capability
        let cap = make_cap("free_tool", "utility", true, false);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: "None required" in auth section
        assert!(doc.contains("None required."));
    }

    #[test]
    fn render_command_doc_auth_section_with_auth() {
        // GIVEN: api_key capability
        let cap = make_cap("paid_tool", "finance", false, true);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: auth type and key are shown
        assert!(doc.contains("api_key"));
        assert!(doc.contains("env:API_KEY"));
    }

    #[test]
    fn render_command_doc_guidance_read_only_flag() {
        // GIVEN: read-only capability
        let cap = make_cap("readonly_tool", "search", true, false);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: safe-to-use note present
        assert!(doc.contains("Safe to use without confirmation"));
    }

    #[test]
    fn render_command_doc_guidance_mutating_flag() {
        // GIVEN: mutating capability
        let cap = make_cap("create_tool", "productivity", false, true);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: confirm note present
        assert!(doc.contains("Mutating operation"));
    }

    #[test]
    fn render_command_doc_cost_section_free() {
        // GIVEN: zero-cost capability
        let cap = make_cap("free_cap", "utility", true, false);
        // WHEN
        let doc = render_command_doc(&cap);
        // THEN: "Free" in cost section
        assert!(doc.contains("Free"));
    }

    // ── SKILL.md (index) ──────────────────────────────────────────────────────

    #[test]
    fn render_skill_index_has_valid_yaml_frontmatter() {
        // GIVEN: two capabilities in the "search" category
        let caps: Vec<CapabilityDefinition> = vec![
            make_cap("search_a", "search", true, false),
            make_cap("search_b", "search", true, false),
        ];
        // WHEN
        let refs: Vec<&CapabilityDefinition> = caps.iter().collect();
        let index = render_skill_index("search", &refs);
        // THEN: YAML front-matter delimiters present
        assert!(index.starts_with("---\n"));
        assert!(index.contains("name: mcp-gateway-search"));
        assert!(index.contains("---\n"));
    }

    #[test]
    fn render_skill_index_table_has_auth_column() {
        // GIVEN: one capability requiring auth, one not
        let caps: Vec<CapabilityDefinition> = vec![
            make_cap("tool_a", "test", true, false),
            make_cap("tool_b", "test", false, true),
        ];
        let refs: Vec<&CapabilityDefinition> = caps.iter().collect();
        // WHEN
        let index = render_skill_index("test", &refs);
        // THEN: table shows yes/no in auth column
        assert!(index.contains("| no |"));
        assert!(index.contains("| yes |"));
    }

    // ── render_bundles ────────────────────────────────────────────────────────

    #[test]
    fn render_bundles_groups_by_category() {
        // GIVEN: capabilities across two categories
        let caps: Vec<CapabilityDefinition> = vec![
            make_cap("a1", "search", true, false),
            make_cap("a2", "search", true, false),
            make_cap("b1", "finance", false, true),
        ];
        // WHEN
        let bundles = render_bundles(&caps);
        // THEN: two bundles, correct category sizes
        assert_eq!(bundles.len(), 2);
        let search = bundles.iter().find(|b| b.category == "search").unwrap();
        assert_eq!(search.command_docs.len(), 2);
        let finance = bundles.iter().find(|b| b.category == "finance").unwrap();
        assert_eq!(finance.command_docs.len(), 1);
    }

    #[test]
    fn render_bundles_uncategorised_goes_to_general() {
        // GIVEN: a capability with no category
        let cap = make_cap("misc_tool", "", true, false);
        // WHEN
        let bundles = render_bundles(&[cap]);
        // THEN: placed in "general" bundle
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].category, "general");
    }

    // ── truncate helper ───────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 80), "hello");
    }

    #[test]
    fn truncate_long_string_at_boundary() {
        let s = "a".repeat(100);
        assert_eq!(truncate(&s, 80).len(), 80);
    }

    // ── capitalize helper ─────────────────────────────────────────────────────

    #[test]
    fn capitalize_lowercase_input() {
        assert_eq!(capitalize("search"), "Search");
    }

    #[test]
    fn capitalize_empty_string() {
        assert_eq!(capitalize(""), "");
    }
}
