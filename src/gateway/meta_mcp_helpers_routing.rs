// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The initialize routing guide, built from the few capability fields it
//! reads (MIK-8014 PERF.8a). Re-exported from [`super::meta_mcp_helpers`].

/// Build dynamic routing instructions from capability metadata.
///
/// Groups capabilities by `metadata.category` and lists representative tools.
/// Returns an empty string when no capabilities are provided.
/// Kept for tests, which build the guide from whole definitions.
#[cfg(test)]
pub(crate) fn build_routing_instructions(
    capabilities: &[crate::capability::CapabilityDefinition],
    capability_backend_name: &str,
) -> String {
    let entries: Vec<RoutingEntry<'_>> = capabilities
        .iter()
        .map(|cap| RoutingEntry {
            name: &cap.name,
            category: &cap.metadata.category,
            chains_with: &cap.metadata.chains_with,
        })
        .collect();
    build_routing_guide(&entries, capability_backend_name)
}

/// What the routing guide reads of one capability (MIK-8014 PERF.8a).
pub(crate) struct RoutingEntry<'a> {
    pub(crate) name: &'a str,
    pub(crate) category: &'a str,
    pub(crate) chains_with: &'a [String],
}

/// The initialize routing guide, built from the fields it reads.
pub(crate) fn build_routing_guide(
    capabilities: &[RoutingEntry<'_>],
    capability_backend_name: &str,
) -> String {
    use std::collections::BTreeMap;

    if capabilities.is_empty() {
        return String::new();
    }

    // Group tools by category, preserving insertion order via BTreeMap
    let mut by_category: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for cap in capabilities {
        let category = if cap.category.is_empty() {
            "general".to_string()
        } else {
            cap.category.to_string()
        };

        by_category
            .entry(category)
            .or_default()
            .push(format!("{}/{}", capability_backend_name, cap.name));
    }

    // Also track chains_with hints per category: source_tool -> [downstream_tools]
    let mut chains: Vec<(String, Vec<String>)> = Vec::new();
    for cap in capabilities {
        if !cap.chains_with.is_empty() {
            chains.push((cap.name.to_string(), cap.chains_with.to_vec()));
        }
    }

    let mut lines = vec!["\nRouting Guide (by task type):".to_string()];

    for (category, tools) in &by_category {
        let tool_sample = tools.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
        let suffix = if tools.len() > 2 {
            format!(" (+{})", tools.len() - 2)
        } else {
            String::new()
        };
        lines.push(format!("- {category}: {tool_sample}{suffix}"));
    }

    if !chains.is_empty() {
        lines.push("\nComposition chains (tool -> next steps):".to_string());
        for (source, targets) in &chains {
            lines.push(format!("  {source} -> {}", targets.join(", ")));
        }
    }

    lines.join("\n")
}
