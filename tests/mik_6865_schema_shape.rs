// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! MCPGW.SCHEMA.2: every in-repo capability input schema is classified.
//!
//! Live MCP backends are not in git; this audit covers the checked-in
//! catalog. Unclassified is unrepresentable (`SchemaShapeRisk` is closed).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use mcp_gateway::capability::{
    SchemaShapeRisk, audit_schema_shapes, classify_schema_shape, parse_capability,
};

fn capability_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dirent");
        let path = entry.path();
        if path.is_dir() {
            capability_yaml_files(&path, out);
        } else if path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            out.push(path);
        }
    }
}

fn load_capability_schemas() -> Vec<(String, serde_json::Value)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut files = Vec::new();
    capability_yaml_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "expected capability YAML under {}",
        root.display()
    );
    let mut loaded = Vec::new();
    for path in files {
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let cap =
            parse_capability(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        loaded.push((cap.name, cap.schema.input));
    }
    loaded
}

#[test]
fn every_capability_input_schema_is_classified() {
    let loaded = load_capability_schemas();
    let pairs: Vec<(&str, &serde_json::Value)> = loaded
        .iter()
        .map(|(name, schema)| (name.as_str(), schema))
        .collect();
    let audit = audit_schema_shapes(pairs);
    assert_eq!(audit.len(), loaded.len());
    for row in &audit {
        assert!(
            matches!(
                row.shape_risk,
                SchemaShapeRisk::Flat
                    | SchemaShapeRisk::NestedScalarArray
                    | SchemaShapeRisk::NestedObjectArray
            ),
            "capability {} unclassified",
            row.tool
        );
    }
}

#[test]
fn schema_shape_audit_file_matches_catalog() {
    let loaded = load_capability_schemas();
    let mut computed: BTreeMap<String, SchemaShapeRisk> = loaded
        .iter()
        .map(|(name, schema)| (name.clone(), classify_schema_shape(schema)))
        .collect();
    assert_eq!(
        computed.len(),
        loaded.len(),
        "duplicate capability names would collapse the audit"
    );

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("probe/schema-shape-audit.json");
    if std::env::var_os("GENERATE_SCHEMA_SHAPE_AUDIT").is_some() {
        fs::create_dir_all(path.parent().expect("probe dir")).expect("create probe/");
        let body = serde_json::to_string_pretty(&computed).expect("serialize audit");
        fs::write(&path, format!("{body}\n")).expect("write audit");
        return;
    }
    let on_disk: BTreeMap<String, SchemaShapeRisk> = serde_json::from_str(
        &fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    // The checked-in file may also carry meta-tool rows (`meta:...`). Drop
    // those before comparing against the capability catalog.
    computed.retain(|k, _| !k.starts_with("meta:"));
    let catalog_on_disk: BTreeMap<_, _> = on_disk
        .into_iter()
        .filter(|(k, _)| !k.starts_with("meta:"))
        .collect();
    assert_eq!(
        computed, catalog_on_disk,
        "probe/schema-shape-audit.json is stale; regenerate from the catalog"
    );
}
