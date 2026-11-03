// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` runs the 4.0.0 grant-row migration on the grants file
//! the config names, so a legacy row naming no one no longer blocks startup.

use super::MIGRATIONS;

#[tokio::test]
async fn the_upgrade_removes_a_nameless_grant_row_from_the_configured_grants() {
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants.yaml");
    let config = format!(
        "security:\n  identity_grants:\n    enabled: true\n    path: {}\n",
        grants.display()
    );
    std::fs::write(dir.path().join("gateway.yaml"), config).unwrap();
    let body = "schema_version: identity_grants.v1\ngrants:\n- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: mcp-gateway identity grants grant\n  reason: empty\n";
    mcp_gateway::config_persistence::write_text_atomic(&grants, body).unwrap();
    assert!(
        mcp_gateway::identity_grants::read_identity_grants_file(&grants)
            .await
            .is_err()
    );

    let migration = MIGRATIONS
        .iter()
        .find(|m| m.description.contains("names no one"))
        .expect("registered");
    assert_eq!(migration.applies_below, "4.0.0");
    assert_eq!(
        migration.writes,
        super::Writes::OwnFile,
        "it backs up its own file"
    );
    (migration.apply)(dir.path()).unwrap();

    let read = mcp_gateway::identity_grants::read_identity_grants_file(&grants)
        .await
        .expect("loads after the upgrade");
    assert!(read.grants.is_empty());
    assert!(dir.path().join("grants.yaml.bak.pre-4.0.0").exists());
}
