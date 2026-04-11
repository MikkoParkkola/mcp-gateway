//! Quality scoring for discovered capabilities.
//!
//! Scores each `GeneratedCapability` on a 0-100 scale based on factors that
//! make an endpoint useful to an LLM tool-use agent.
//!
//! Since `GeneratedCapability` contains only `name` and `yaml` (not a parsed
//! struct), we heuristically scan the generated YAML content.
//!
//! ## Scoring factors (max 100)
//!
//! | Factor | Points | Rationale |
//! |--------|--------|-----------|
//! | Has description | +30 | LLM needs to understand tool purpose |
//! | Has >=1 required param | +15 | Structured I/O > zero-arg endpoints |
//! | Has <=5 total params | +15 | Too many params confuse LLMs |
//! | Method is GET or POST | +10 | Standard HTTP methods |
//! | Name is descriptive (>5 chars, not trivial) | +10 | Meaningful tool name |
//! | Has response schema | +10 | Output typing aids tool composition |
//! | Description >20 chars | +10 | Richer descriptions score higher |

use serde::Serialize;

use crate::capability::GeneratedCapability;

/// Quality score for a discovered endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointQuality {
    /// Capability name.
    pub name: String,
    /// Score 0-100. Higher = more useful to an LLM.
    pub score: u32,
    /// Human-readable reasons for the score.
    pub reasons: Vec<String>,
}

/// Score a generated capability for LLM usefulness.
///
/// Operates on the YAML content since `GeneratedCapability` does not expose
/// a parsed definition struct. Heuristics are intentionally simple so they
/// remain stable across YAML formatting changes.
#[must_use]
pub fn score_capability(cap: &GeneratedCapability) -> EndpointQuality {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let yaml = &cap.yaml;

    // Factor 1: Has a non-empty description (+30)
    // The converter emits `description: <value>` for every capability.
    if has_non_trivial_description(yaml) {
        score += 30;
        reasons.push("has description".into());
    }

    // Factor 2: Has at least one required parameter (+15)
    // OpenApiConverter emits `required: [...]` in the input schema.
    if yaml.contains("required:") && !yaml.contains("required: []") {
        score += 15;
        reasons.push("has required params".into());
    }

    // Factor 3: Parameter count 1-5 (+15), >5 penalised (no points)
    let param_count = count_input_params(yaml);
    if param_count > 0 && param_count <= 5 {
        score += 15;
        reasons.push(format!("{param_count} params (manageable)"));
    } else if param_count > 5 {
        reasons.push(format!("{param_count} params (complex)"));
    }

    // Factor 4: Standard HTTP method (+10)
    if yaml.contains("method: GET") || yaml.contains("method: POST") {
        score += 10;
        reasons.push("standard method".into());
    }

    // Factor 5: Descriptive name — >5 chars and not just "get_" prefix (+10)
    let name_len = cap.name.len();
    if name_len > 5 && !is_trivial_name(&cap.name) {
        score += 10;
        reasons.push("descriptive name".into());
    }

    // Factor 6: Has response schema (+10)
    // OpenApiConverter writes the output schema block.
    if has_response_schema(yaml) {
        score += 10;
        reasons.push("has response schema".into());
    }

    // Factor 7: Rich description (>20 chars) (+10)
    if has_rich_description(yaml) {
        score += 10;
        reasons.push("rich description".into());
    }

    EndpointQuality {
        name: cap.name.clone(),
        score,
        reasons,
    }
}

/// Sort capabilities by quality score descending.
///
/// Returns pairs of `(capability, quality)` so callers can log scores.
#[must_use]
pub fn rank_capabilities(
    caps: Vec<GeneratedCapability>,
) -> Vec<(GeneratedCapability, EndpointQuality)> {
    let mut scored: Vec<_> = caps
        .into_iter()
        .map(|c| {
            let q = score_capability(&c);
            (c, q)
        })
        .collect();
    scored.sort_by(|a, b| b.1.score.cmp(&a.1.score));
    scored
}

// ============================================================================
// Helpers
// ============================================================================

/// Check if the YAML contains a non-trivial description value.
///
/// The converter emits descriptions as either:
/// - `description: Single line value`
/// - `description: |\n  Multi-line`
fn has_non_trivial_description(yaml: &str) -> bool {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("description:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            // Skip the block scalar indicator alone
            if !value.is_empty() && value != "|" && value != ">" {
                return true;
            }
        }
    }
    false
}

/// Check if the description is rich (>20 significant chars).
fn has_rich_description(yaml: &str) -> bool {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("description:") {
            let value = rest
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('|')
                .trim();
            if value.len() > 20 {
                return true;
            }
        }
    }
    false
}

/// Count the number of input parameter properties in the YAML.
///
/// Heuristic: count lines that look like `  param_name:` inside the
/// `schema.input.properties` block. We approximate this by counting property
/// key lines that appear after `properties:` and before the next top-level
/// YAML key.
fn count_input_params(yaml: &str) -> usize {
    let mut in_properties = false;
    let mut count = 0usize;
    let mut base_indent: Option<usize> = None;

    for line in yaml.lines() {
        if line.trim_start().starts_with("properties:") {
            in_properties = true;
            base_indent = Some(line.len() - line.trim_start().len());
            continue;
        }

        if in_properties {
            if line.trim().is_empty() {
                continue;
            }

            let indent = line.len() - line.trim_start().len();
            let content = line.trim();

            // If we hit a line at the same or lower indent as `properties:`,
            // we've left the block.
            if let Some(base) = base_indent {
                if indent <= base && !content.is_empty() {
                    in_properties = false;
                    continue;
                }
                // Direct children of `properties:` are property names.
                // They appear at `base + 2` or `base + 4` indentation
                // and end with `:`.
                if (indent == base + 2 || indent == base + 4)
                    && (content.ends_with(':') || content.contains(": "))
                {
                    count += 1;
                }
            }
        }
    }

    count
}

/// Check if the YAML contains a non-trivial output/response schema.
fn has_response_schema(yaml: &str) -> bool {
    let mut in_output = false;
    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed == "output:" {
            in_output = true;
            continue;
        }
        if in_output {
            if trimmed.is_empty() {
                continue;
            }
            // If the output block has any content besides `{}` it's a real schema
            if trimmed != "{}" && !trimmed.starts_with('#') {
                return true;
            }
            // Hit a new top-level key — output block is empty
            if !line.starts_with(' ') && !line.starts_with('\t') {
                break;
            }
        }
    }
    false
}

/// A name is "trivial" if it is just a short method prefix with nothing useful.
fn is_trivial_name(name: &str) -> bool {
    // Names that are just HTTP method + underscore or similar
    matches!(
        name,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cap(name: &str, yaml: &str) -> GeneratedCapability {
        GeneratedCapability {
            name: name.to_string(),
            yaml: yaml.to_string(),
        }
    }

    const HIGH_QUALITY_YAML: &str = r#"
fulcrum: "1.0"
name: get_current_weather
description: "Get current weather conditions for a city"

schema:
  input:
    type: object
    properties:
      city:
        type: string
        description: City name
      units:
        type: string
    required:
      - city
  output:
    type: object
    properties:
      temperature:
        type: number

providers:
  primary:
    service: rest
    config:
      base_url: https://api.weather.com
      path: /current
      method: GET

auth:
  required: false
"#;

    const LOW_QUALITY_YAML: &str = r#"
fulcrum: "1.0"
name: op
description:

schema:
  input:
    type: object
    properties: {}
    required: []
  output:
    {}

providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /op
      method: OPTIONS

auth:
  required: false
"#;

    #[test]
    fn high_quality_cap_scores_well() {
        let cap = make_cap("get_current_weather", HIGH_QUALITY_YAML);
        let q = score_capability(&cap);
        assert!(
            q.score >= 50,
            "expected score >= 50, got {} with reasons: {:?}",
            q.score,
            q.reasons
        );
    }

    #[test]
    fn low_quality_cap_scores_low() {
        let cap = make_cap("op", LOW_QUALITY_YAML);
        let q = score_capability(&cap);
        assert!(
            q.score <= 30,
            "expected score <= 30, got {} with reasons: {:?}",
            q.score,
            q.reasons
        );
    }

    #[test]
    fn rank_capabilities_descending() {
        let caps = vec![
            make_cap("op", LOW_QUALITY_YAML),
            make_cap("get_current_weather", HIGH_QUALITY_YAML),
        ];
        let ranked = rank_capabilities(caps);
        assert_eq!(ranked[0].0.name, "get_current_weather");
        assert_eq!(ranked[1].0.name, "op");
        assert!(ranked[0].1.score >= ranked[1].1.score);
    }

    #[test]
    fn score_gives_standard_method_bonus() {
        let get_yaml = HIGH_QUALITY_YAML.to_string();
        let options_yaml = HIGH_QUALITY_YAML.replace("method: GET", "method: OPTIONS");
        let get_cap = make_cap("test_get", &get_yaml);
        let options_cap = make_cap("test_options", &options_yaml);
        let get_score = score_capability(&get_cap).score;
        let options_score = score_capability(&options_cap).score;
        assert!(
            get_score > options_score,
            "GET should score higher than OPTIONS"
        );
    }

    #[test]
    fn score_response_schema_bonus() {
        let with_schema = make_cap("test", HIGH_QUALITY_YAML);
        let q = score_capability(&with_schema);
        assert!(q.reasons.iter().any(|r| r == "has response schema"));
    }
}
