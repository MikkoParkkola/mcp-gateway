// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability-inventory claims: the counts and per-category tallies the
//! public docs give match the shipped capability catalog. Moved from the parent
//! test file for the file-size ceiling.

use super::*;
use walkdir::WalkDir;

/// The shipped capability YAMLs: every `.yaml` under `capabilities/` except
/// the `examples/` templates. Every count and lookup below goes through this,
/// so a template can neither be counted nor satisfy a held-name check.
fn shipped_capability_yaml_files() -> impl Iterator<Item = walkdir::DirEntry> {
    WalkDir::new(repo_file("capabilities"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
        .filter(|entry| {
            !entry
                .path()
                .components()
                .any(|component| component.as_os_str() == "examples")
        })
}

fn capability_yaml_exists(name: &str) -> bool {
    shipped_capability_yaml_files()
        .any(|entry| entry.file_name().to_str() == Some(&format!("{name}.yaml")))
}

fn count_capability_yaml_files() -> usize {
    shipped_capability_yaml_files().count()
}

fn count_capability_yaml_files_by_category() -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::new();

    for entry in shipped_capability_yaml_files() {
        let relative = entry
            .path()
            .strip_prefix(repo_file("capabilities"))
            .expect("capability path should strip repo prefix");
        let category = relative
            .components()
            .next()
            .expect("capability YAML should live under a category directory")
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        *counts.entry(category).or_insert(0usize) += 1;
    }

    counts.into_iter().collect()
}

#[test]
fn capability_inventory_claim_matches_current_repo_catalog() {
    let claims = load_claims();
    let actual_count = count_capability_yaml_files();

    assert_eq!(
        actual_count,
        claims.capability_count + claims.held_capabilities.len(),
        "public claims file should count the shipped YAML inventory minus the held capabilities"
    );
    let held_names: std::collections::BTreeSet<&str> = claims
        .held_capabilities
        .iter()
        .map(|held| held.name.as_str())
        .collect();
    assert_eq!(
        held_names.len(),
        claims.held_capabilities.len(),
        "held_capabilities lists a capability twice, which would subtract it twice"
    );
    for held in &claims.held_capabilities {
        assert!(
            !held.reason.is_empty() && capability_yaml_exists(&held.name),
            "held capability {} must exist and say why it is held",
            held.name
        );
    }
    for held in &claims.held_operations {
        assert!(
            !held.reason.is_empty()
                && capability_yaml_exists(&held.capability)
                && !held.operation.is_empty(),
            "held operation {}.{} must exist and say why",
            held.capability,
            held.operation
        );
    }
    assert!(
        claims.capability_count >= capability_floor(claims.capability_count),
        "actual capability count should satisfy the marketed README floor"
    );
}

#[test]
fn capability_catalog_docs_match_current_inventory() {
    let claims = load_claims();
    let marketed_floor = capability_floor(claims.capability_count);
    let capabilities_readme = read_repo_file("capabilities/README.md");
    let community_registry = read_repo_file("docs/COMMUNITY_REGISTRY.md");

    assert!(
        capabilities_readme.contains(&format!(
            "**{} built-in capabilities**",
            claims.capability_count
        )),
        "capabilities README should advertise the canonical exact capability inventory"
    );
    assert!(
        capabilities_readme.contains(&format!("marketed publicly as **{marketed_floor}+**")),
        "capabilities README should mention the canonical marketed capability floor"
    );
    assert!(
        capabilities_readme
            .contains("find capabilities -name '*.yaml' -not -path '*/examples/*' | wc -l"),
        "capabilities README should document how to derive the exact YAML inventory"
    );
    assert!(
        !capabilities_readme.contains("52+ curated capabilities"),
        "capabilities README should not advertise the obsolete starter-capability count"
    );
    assert!(
        !capabilities_readme.contains("These 30+ capabilities need no API keys"),
        "capabilities README should not keep the stale zero-config subset claim"
    );

    for held in &claims.held_capabilities {
        assert!(
            capabilities_readme.contains(&format!("`{}`", held.name)),
            "capabilities README should name the held capability {}",
            held.name
        );
    }
    for held in &claims.held_operations {
        assert!(
            capabilities_readme.contains(&format!("`{}` `{}`", held.capability, held.operation)),
            "capabilities README should name the held operation {}.{}",
            held.capability,
            held.operation
        );
    }

    assert!(
        capabilities_readme.contains(&format!(
            "raw inventory: all {} files, the held entries included",
            claims.capability_count + claims.held_capabilities.len()
        )),
        "capabilities README should label its category table as the raw inventory"
    );
    for (category, count) in count_capability_yaml_files_by_category() {
        assert!(
            capabilities_readme.contains(&format!("| **{category}/** | {count} |")),
            "capabilities README should include the live {category}/ count"
        );
    }

    assert!(
        community_registry.contains(&format!(
            "All {marketed_floor}+ built-in capabilities ship with mcp-gateway."
        )),
        "community registry docs should advertise the canonical marketed capability floor"
    );
    assert!(
        community_registry.contains(&format!(
            "exact tracked inventory is currently {} YAMLs, of which {} {} held",
            claims.capability_count + claims.held_capabilities.len(),
            claims.held_capabilities.len(),
            if claims.held_capabilities.len() == 1 {
                "is"
            } else {
                "are"
            }
        )),
        "community registry docs should mention the canonical exact YAML inventory"
    );
    assert!(
        !community_registry.contains("All 52+ capabilities ship with mcp-gateway"),
        "community registry docs should not advertise the obsolete capability count"
    );
    assert!(
        !community_registry.contains("standard category subdirectories (`finance/`, `knowledge/`, `search/`, `utility/`, `entertainment/`, `communication/`, `food/`, `geo/`)"),
        "community registry docs should not hard-code the obsolete category list"
    );
}
