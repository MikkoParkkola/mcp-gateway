// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/CLIENTS.md`: the client matrix matches the exporter, and every
//! verified row points at a recorded run that carries what the row claims.
//!
//! The exporter's client list and path helpers are binary-private, so they are
//! read as source text; `ExportTarget` is public and is read through clap.

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Parser as _, ValueEnum as _};
use mcp_gateway::cli::{Cli, ExportTarget};

const DOC: &str = include_str!("../docs/CLIENTS.md");
const EXPORT_SRC: &str = include_str!("../src/commands/config_export/mod.rs");
const PATHS_SRC: &str = include_str!("../src/commands/paths.rs");
const MATRIX: &str = include_str!("../docs/release/v4.0.0-supported-matrix.md");

/// Rows of the table whose header's first cell is `header`, as cells.
fn table(doc: &str, header: &str) -> Vec<Vec<String>> {
    let mut lines = doc.lines().skip_while(|l| {
        l.strip_prefix('|')
            .and_then(|r| r.split('|').next())
            .is_none_or(|c| c.trim() != header)
    });
    assert!(lines.next().is_some(), "table `{header}` not found");
    lines
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            let inner = l.trim().trim_start_matches('|').trim_end_matches('|');
            inner.split('|').map(|c| c.trim().to_string()).collect()
        })
        .collect()
}

/// Every `` `code` `` span in `text`.
fn code_spans(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// The export-target table: (client, target, key, location, status).
fn export_rows() -> Vec<(String, String, String, String, String)> {
    let rows = table(DOC, "Client");
    assert!(rows.len() >= 7, "export table has only {} rows", rows.len());
    rows.into_iter()
        .map(|c| {
            assert_eq!(c.len(), 5, "row {c:?} does not have five cells");
            let target = c[1].trim_matches('`').to_string();
            let key = c[2].trim_matches('`').to_string();
            (c[0].clone(), target, key, c[3].clone(), c[4].clone())
        })
        .collect()
}

/// `ClientSpec { label, .., servers_key }` pairs in the exporter source.
fn exporter_keys() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for spec in EXPORT_SRC.split("ClientSpec {").skip(1) {
        let field = |name: &str| {
            let rest = spec.split(&format!("{name}: \"")).nth(1)?;
            Some(rest.split('"').next()?.to_string())
        };
        if let (Some(label), Some(key)) = (field("label"), field("servers_key")) {
            out.insert((label, key));
        }
    }
    out
}

/// Every path literal the exporter writes to: `home_path("…")` in either
/// source file becomes `~/…`, `cwd.join("…")` stays workspace-relative.
fn exporter_paths() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // Production code only: the path helpers before their test module, and
    // the exporter's `client_specs` body.
    let helpers = PATHS_SRC.split("#[cfg(test)]").next().unwrap();
    let specs = EXPORT_SRC
        .split("fn client_specs(")
        .nth(1)
        .expect("client_specs in the exporter");
    let specs = &specs[..specs.find("\n}\n").expect("end of client_specs")];
    for (src, open, prefix) in [
        (helpers, "home_path(\"", "~/"),
        (specs, "home_path(\"", "~/"),
        (specs, "cwd.join(\"", ""),
    ] {
        for piece in src.split(open).skip(1) {
            let lit = piece.split('"').next().unwrap_or("");
            out.insert(format!("{prefix}{lit}"));
        }
    }
    out
}

#[test]
fn every_export_target_has_a_row_and_parses() {
    let rows = export_rows();
    let listed: BTreeSet<String> = rows.iter().map(|r| r.1.clone()).collect();
    let mut expected = BTreeSet::new();
    for target in ExportTarget::value_variants() {
        let name = target.to_possible_value().unwrap().get_name().to_string();
        if name != "all" && name != "generic" {
            expected.insert(name);
        }
    }
    assert_eq!(
        listed, expected,
        "export targets in the table and in the CLI differ"
    );
    for target in listed.iter().map(String::as_str).chain(["generic", "all"]) {
        let args = ["mcp-gateway", "setup", "export", "--target", target];
        if let Err(e) = Cli::try_parse_from(args) {
            panic!("`mcp-gateway setup export --target {target}` does not parse: {e}");
        }
    }
}

#[test]
fn keys_and_locations_match_the_exporter() {
    let rows = export_rows();
    let documented: BTreeSet<(String, String)> = rows
        .iter()
        .map(|r| {
            let label = r.0.split(" (").next().unwrap().to_string();
            (label, r.2.clone())
        })
        .collect();
    assert_eq!(
        documented,
        exporter_keys(),
        "client names or config keys differ from the exporter's ClientSpec list"
    );
    let mut paths = BTreeSet::new();
    for row in &rows {
        paths.extend(code_spans(&row.3));
    }
    assert_eq!(
        paths,
        exporter_paths(),
        "documented locations differ from the paths the exporter writes"
    );
}

/// A verified cell: `Verified: <version>, <date>, owner <name>, gateway
/// `<commit>`, ... ([run](<file>))`.
struct Verified {
    version: String,
    date: String,
    owner: String,
    commit: String,
    file: String,
}

fn parse_verified(status: &str) -> Option<Verified> {
    let rest = status.strip_prefix("Verified: ")?;
    let mut parts = rest.split(", ");
    let version = parts.next()?.to_string();
    let date = parts.next()?.to_string();
    let owner = parts.next()?.strip_prefix("owner ")?.to_string();
    let commit = code_spans(parts.next()?.strip_prefix("gateway ")?)
        .into_iter()
        .next()?;
    let file = rest.split("](").nth(1)?.split(')').next()?.to_string();
    Some(Verified {
        version,
        date,
        owner,
        commit,
        file,
    })
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && s.chars()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// Every row is verified from a recorded run or says Unverified, and a
/// verified row's version, date, owner and gateway commit are all in the run.
#[test]
fn every_row_is_backed_by_a_recorded_run_or_unverified() {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut statuses: Vec<(String, String)> =
        export_rows().into_iter().map(|r| (r.0, r.4)).collect();
    let other = DOC
        .split("## Clients without an export target")
        .nth(1)
        .expect("section for clients without an export target");
    let other_rows = table(other, "Client");
    assert!(
        !other_rows.is_empty(),
        "no rows for clients without an export target"
    );
    statuses.extend(other_rows.into_iter().map(|c| (c[0].clone(), c[2].clone())));
    let mut verified = 0;
    for (client, status) in &statuses {
        if status.starts_with("Unverified") {
            continue;
        }
        let v = parse_verified(status).unwrap_or_else(|| {
            panic!("{client}: status is neither `Unverified` nor a full `Verified:` cell")
        });
        assert!(
            is_iso_date(&v.date),
            "{client}: `{}` is not an ISO date",
            v.date
        );
        assert!(
            v.file.starts_with("release/verify/"),
            "{client}: evidence must be a recorded run under docs/release/verify/"
        );
        let run = std::fs::read_to_string(docs.join(&v.file))
            .unwrap_or_else(|_| panic!("{client}: evidence file {} is missing", v.file));
        for (what, value) in [
            ("version", &v.version),
            ("date", &v.date),
            ("owner", &v.owner),
            ("gateway commit", &v.commit),
        ] {
            assert!(
                run.contains(value.as_str()),
                "{client}: the recorded run does not contain the {what} `{value}`"
            );
        }
        verified += 1;
    }
    assert!(
        verified >= 1,
        "no verified row found; the parser no longer matches"
    );
}

/// The verified rows here and in the supported matrix name the same clients
/// and versions.
#[test]
fn verified_rows_agree_with_the_supported_matrix() {
    let here: BTreeSet<(String, String)> = export_rows()
        .into_iter()
        .filter_map(|r| {
            let v = parse_verified(&r.4)?;
            Some((r.0.split(" (").next().unwrap().to_string(), v.version))
        })
        .collect();
    let recorded = MATRIX
        .split("Rows recorded so far:")
        .nth(1)
        .expect("supported matrix lost its recorded rows");
    let there: BTreeSet<(String, String)> = table(recorded, "Client")
        .into_iter()
        .map(|c| (c[0].split(" (").next().unwrap().to_string(), c[1].clone()))
        .collect();
    assert!(
        !there.is_empty(),
        "no recorded rows parsed from the supported matrix"
    );
    assert_eq!(
        here, there,
        "verified clients differ between CLIENTS.md and the supported matrix"
    );
}
