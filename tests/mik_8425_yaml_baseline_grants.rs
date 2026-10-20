// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0: identity grants as the gateway reads and writes them with
//! `serde-yaml` 0.9.34, recorded before the parser is replaced (gate G1).
//!
//! A grants file the gateway writes must stay readable by a gateway rolled
//! back to `serde-yaml`. So the YAML writer's exact bytes are the golden: the
//! `!exact` tag form, never the map form. The JSON writer and
//! `grant_digest` (over the JSON form) must not move at all, because stored
//! journals carry those digests.
//!
//! Every read and write goes through the public file functions, the path an
//! operator's gateway takes.

#[path = "common/mik_8425_golden.rs"]
mod golden;

// Not called here: `golden` names `crate::yaml::Value`, so this crate
// declares the module it resolves.
#[path = "common/yaml.rs"]
mod yaml;

use mcp_gateway::identity_grants::journal::grant_digest;
use mcp_gateway::identity_grants::{read_identity_grants_file, write_identity_grants_file};
use std::fmt::Write as _;

const QUALIFIED: &str = "schema_version: identity_grants.v1
grants:
- grant_id: g-mtls
  subject:
    authority: api_key
    subject: alice
  agent: !exact {source: mtls, id: 'spiffe://example.test/runner'}
  capability: calendar_read
  scope: read
  owner:
    authority: api_key
    subject: alice
  provenance: mcp-gateway identity grants grant
  reason: ci runner
- grant_id: g-jwt
  subject:
    authority: api_key
    subject: alice
  agent: !exact {source: jwt, id: build-bot}
  capability: calendar_read
  scope: execute
  owner:
    authority: api_key
    subject: alice
  provenance: mcp-gateway identity grants grant
  reason: bot
- grant_id: g-any
  subject:
    authority: api_key
    subject: alice
  agent: any
  capability: calendar_read
  scope: execute
  owner:
    authority: api_key
    subject: alice
  provenance: mcp-gateway identity grants grant
  reason: any
";

/// Copy `text` into `dir/name` readable by its owner only: the grants reader
/// refuses a file others can change, which would otherwise read as a parse
/// refusal and record the wrong reason.
fn owner_only(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, text).expect("write grants");
    path
}

async fn report() -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = owner_only(dir.path(), "in.yaml", QUALIFIED);
    let file = read_identity_grants_file(&input)
        .await
        .expect("a qualified 4.0 grants file reads");

    let mut out = String::new();
    for grant in &file.grants {
        let _ = writeln!(out, "digest {}\t{}", grant.grant_id, grant_digest(grant));
    }
    for name in ["out.yaml", "out.json"] {
        let path = dir.path().join(name);
        write_identity_grants_file(&path, &file)
            .await
            .expect("grants write");
        let written = std::fs::read_to_string(&path).expect("read back written grants");
        let _ = writeln!(out, "write {name}\t{}", golden::digest(written.as_bytes()));
        let _ = writeln!(out, "text {name}\t{}", golden::one_line(&written));
        let again = read_identity_grants_file(&path)
            .await
            .expect("the gateway reads the file it wrote");
        let _ = writeln!(out, "round-trip {name}\t{}", again == file);
    }
    for (name, fixture) in [
        (
            "3x.yaml",
            "tests/fixtures/identity_grants_3x/grants-3.4.0.yaml",
        ),
        (
            "3x.json",
            "tests/fixtures/identity_grants_3x/grants-3.4.0.json",
        ),
    ] {
        let text = std::fs::read_to_string(golden::repo_root().join(fixture)).expect("fixture");
        let path = owner_only(dir.path(), name, &text);
        let outcome = read_identity_grants_file(&path).await.map_or_else(
            |e| {
                let bare = e.contains("bare id");
                format!("refused names-bare-id={bare}")
            },
            |_| "READ".to_owned(),
        );
        let _ = writeln!(out, "legacy {name}\t{outcome}");
    }
    out
}

/// Digests, written bytes and legacy refusals are as recorded. The YAML
/// text row must show `!exact` tags; a map-form `exact:` there fails G1.
#[tokio::test]
async fn grants_read_and_write_as_recorded() {
    let report = report().await;
    assert!(
        report.contains("agent: !exact"),
        "the YAML writer must emit the tag form serde-yaml reads: {report}"
    );
    golden::assert_golden("grants.txt", &report);
}

/// Prints the golden for review; never part of a normal run.
#[tokio::test]
#[ignore = "records tests/fixtures/mik_8425_yaml/grants.txt; run with --ignored --nocapture"]
async fn record_grants_golden() {
    print!(
        "----- BEGIN grants.txt -----\n{}----- END grants.txt -----\n",
        report().await
    );
}
