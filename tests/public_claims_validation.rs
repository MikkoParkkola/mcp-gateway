use std::{collections::BTreeMap, fs, path::PathBuf};

use walkdir::WalkDir;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn built_in_capability_paths() -> Vec<PathBuf> {
    let capabilities_root = repo_file("capabilities");
    let mut paths: Vec<_> = WalkDir::new(&capabilities_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
        .filter(|entry| {
            !entry
                .path()
                .components()
                .any(|part| part.as_os_str() == "examples")
        })
        .map(|entry| entry.into_path())
        .collect();
    paths.sort();
    paths
}

fn capability_category_counts() -> BTreeMap<String, usize> {
    let capabilities_root = repo_file("capabilities");
    let mut counts = BTreeMap::new();

    for path in built_in_capability_paths() {
        let relative = path
            .strip_prefix(&capabilities_root)
            .expect("capability path should stay under capabilities/");
        let category = relative
            .components()
            .next()
            .expect("capability path should include a category")
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        *counts.entry(category).or_insert(0) += 1;
    }

    counts
}

#[test]
fn capability_docs_match_live_inventory() {
    let capability_count = built_in_capability_paths().len();
    assert_eq!(
        capability_count, 72,
        "update docs and this guard when inventory changes"
    );

    let readme = fs::read_to_string(repo_file("README.md")).expect("read README");
    assert!(readme.contains("70+ built-in capabilities"));
    assert!(!readme.contains("70+ starter capabilities"));
    assert!(!readme.contains("~500ms"));

    let community_registry = fs::read_to_string(repo_file("docs/COMMUNITY_REGISTRY.md"))
        .expect("read community registry");
    assert!(community_registry.contains(&format!(
        "All {capability_count} built-in capabilities ship with mcp-gateway."
    )));
    assert!(!community_registry.contains("All 52+ capabilities"));

    let benchmarks = fs::read_to_string(repo_file("docs/BENCHMARKS.md")).expect("read benchmarks");
    assert!(!benchmarks.contains("Last updated:"));
    assert!(benchmarks.contains(&format!(
        "| Built-in Capability YAMLs | {capability_count} |"
    )));

    let capabilities_readme =
        fs::read_to_string(repo_file("capabilities/README.md")).expect("read capabilities README");
    assert!(
        capabilities_readme.contains(&format!("**{capability_count} built-in capability YAMLs**"))
    );
    assert!(!capabilities_readme.contains("52+"));

    for (category, count) in capability_category_counts() {
        let expected_line = format!("| **{category}/** | {count} |");
        assert!(
            capabilities_readme.contains(&expected_line),
            "missing category inventory line: {expected_line}"
        );
    }
}
