//! Deduplication filter for discovered capabilities.
//!
//! Filters out capabilities whose names match existing ones in the output
//! directory, preventing accidental overwrites of hand-crafted YAML files.

use tracing::info;

use crate::capability::GeneratedCapability;

/// Filter out capabilities whose names match existing ones.
///
/// A capability is considered a duplicate if its `name` appears in
/// `existing_names` (exact match, case-sensitive).
#[must_use]
pub fn deduplicate(
    candidates: Vec<GeneratedCapability>,
    existing_names: &[String],
) -> Vec<GeneratedCapability> {
    candidates
        .into_iter()
        .filter(|cap| {
            if existing_names.contains(&cap.name) {
                info!(name = %cap.name, "Skipping: capability already exists");
                false
            } else {
                true
            }
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cap(name: &str) -> GeneratedCapability {
        GeneratedCapability {
            name: name.to_string(),
            yaml: String::new(),
        }
    }

    #[test]
    fn dedup_removes_matching_names() {
        let caps = vec![make_cap("weather_current"), make_cap("weather_forecast")];
        let existing = vec!["weather_current".to_string()];
        let result = deduplicate(caps, &existing);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "weather_forecast");
    }

    #[test]
    fn dedup_keeps_all_when_no_matches() {
        let caps = vec![make_cap("new_tool"), make_cap("another_tool")];
        let existing: Vec<String> = vec![];
        let result = deduplicate(caps, &existing);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_empty_input() {
        let result = deduplicate(vec![], &["some_name".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_removes_all_when_all_exist() {
        let caps = vec![make_cap("a"), make_cap("b"), make_cap("c")];
        let existing = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = deduplicate(caps, &existing);
        assert!(result.is_empty());
    }

    #[test]
    fn dedup_is_case_sensitive() {
        let caps = vec![make_cap("Weather")];
        let existing = vec!["weather".to_string()];
        let result = deduplicate(caps, &existing);
        // Case-sensitive: "Weather" != "weather", so it should pass through
        assert_eq!(result.len(), 1);
    }
}
