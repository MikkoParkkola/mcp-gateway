// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/CLIENTS.md`: the client matrix matches the exporter, and every
//! verified row points at a recorded run that carries what the row claims.
//!
//! The exporter's client list and path helpers are binary-private, so they are
//! read as source text; `ExportTarget` is public and is read through clap.

use std::collections::{BTreeMap, BTreeSet};
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

/// The body of `fn name(` in `src`, up to the closing brace at column 0.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let body = src
        .split(&format!("fn {name}("))
        .nth(1)
        .unwrap_or_else(|| panic!("fn {name} not found"));
    &body[..body
        .find("\n}\n")
        .unwrap_or_else(|| panic!("end of fn {name}"))]
}

/// Quoted literals after `open` in `src`, each prefixed.
fn literals(src: &str, open: &str, prefix: &str) -> BTreeSet<String> {
    src.split(open)
        .skip(1)
        .map(|p| format!("{prefix}{}", p.split('"').next().unwrap_or("")))
        .collect()
}

/// What the exporter does per client: label -> (config key, paths written).
/// A path is a `home_path("…")` (shown as `~/…`) or `cwd.join("…")` literal,
/// or a helper in `src/commands/paths.rs` whose literals are all its paths.
fn exporter_clients() -> BTreeMap<String, (String, BTreeSet<String>)> {
    let specs = fn_body(EXPORT_SRC, "client_specs");
    let helpers = PATHS_SRC.split("#[cfg(test)]").next().unwrap();
    let mut out = BTreeMap::new();
    for spec in specs.split("ClientSpec {").skip(1) {
        let spec = &spec[..spec.find('}').unwrap_or(spec.len())];
        let field = |name: &str| -> String {
            let line = spec
                .lines()
                .find(|l| l.trim_start().starts_with(&format!("{name}:")))
                .unwrap_or_else(|| panic!("ClientSpec without `{name}`: {spec}"));
            line.split_once(':')
                .unwrap()
                .1
                .trim()
                .trim_end_matches(',')
                .to_string()
        };
        let unquote = |v: String| v.trim_matches('"').to_string();
        let label = unquote(field("label"));
        let key = unquote(field("servers_key"));
        let path = field("path");
        let paths = if path.starts_with("home_path(") {
            literals(&path, "home_path(\"", "~/")
        } else if path.starts_with("cwd.join(") {
            literals(&path, "cwd.join(\"", "")
        } else {
            let helper = path.trim_end_matches("()");
            literals(fn_body(helpers, helper), "home_path(\"", "~/")
        };
        assert!(!paths.is_empty(), "{label}: no path found in `{path}`");
        out.insert(label, (key, paths));
    }
    out
}

/// `--target` value -> client label, from the exporter's `match target` arms.
fn target_labels() -> BTreeMap<String, String> {
    let specs = fn_body(EXPORT_SRC, "client_specs");
    let mut out = BTreeMap::new();
    for arm in specs.split("ExportTarget::").skip(1) {
        let variant: String = arm
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        let Some(label) = arm.split("s.label == \"").nth(1) else {
            continue;
        };
        let label = label.split('"').next().unwrap().to_string();
        let mut kebab = String::new();
        for (i, c) in variant.chars().enumerate() {
            if c.is_ascii_uppercase() && i > 0 {
                kebab.push('-');
            }
            kebab.push(c.to_ascii_lowercase());
        }
        out.insert(kebab, label);
    }
    out
}

fn label_of(client: &str) -> String {
    client.split(" (").next().unwrap().to_string()
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

/// Each row's target, config key and locations are the exporter's for that
/// client, compared per row so a swapped mapping fails too.
#[test]
fn each_row_matches_the_exporter_for_that_client() {
    let clients = exporter_clients();
    let targets = target_labels();
    let rows = export_rows();
    assert_eq!(
        rows.len(),
        clients.len(),
        "rows and exporter clients differ in number"
    );
    for (client, target, key, location, _) in &rows {
        let label = label_of(client);
        assert_eq!(
            targets.get(target),
            Some(&label),
            "`--target {target}` exports {:?}, but the row says {label}",
            targets.get(target)
        );
        let (real_key, real_paths) = clients
            .get(&label)
            .unwrap_or_else(|| panic!("the exporter has no client named {label}"));
        assert_eq!(key, real_key, "{label}: config key");
        let documented: BTreeSet<String> = code_spans(location).into_iter().collect();
        assert_eq!(&documented, real_paths, "{label}: locations");
    }
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

/// (client, status) for every row of both tables.
fn all_statuses() -> Vec<(String, String)> {
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
    statuses
}

/// The `| Field | value |` cell of a recorded run.
fn run_field<'a>(run: &'a str, field: &str) -> &'a str {
    run.lines()
        .find(|l| l.starts_with(&format!("| {field} |")))
        .unwrap_or_else(|| panic!("the recorded run has no `{field}` row"))
}

/// Every row is verified from a recorded run or says Unverified. A verified
/// row's client and version, date, owner and gateway commit must each be in
/// the matching field of the run it links.
#[test]
fn every_row_is_backed_by_a_recorded_run_or_unverified() {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut verified = 0;
    for (client, status) in all_statuses() {
        if status.starts_with("Unverified") {
            continue;
        }
        let v = parse_verified(&status).unwrap_or_else(|| {
            panic!("{client}: status is neither `Unverified` nor a full `Verified:` cell")
        });
        for (what, value) in [
            ("version", &v.version),
            ("owner", &v.owner),
            ("gateway commit", &v.commit),
        ] {
            assert!(!value.trim().is_empty(), "{client}: empty {what}");
        }
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
        let client_cell = run_field(&run, "Client");
        assert!(
            client_cell.contains(&label_of(&client)) && client_cell.contains(&v.version),
            "{client}: the run's Client field does not name this client at {}",
            v.version
        );
        assert!(
            run_field(&run, "Date").contains(&v.date),
            "{client}: run date"
        );
        assert!(
            run_field(&run, "Owner").contains(&v.owner),
            "{client}: run owner"
        );
        assert!(
            run_field(&run, "Gateway").contains(&v.commit),
            "{client}: run gateway commit"
        );
        verified += 1;
    }
    assert!(
        verified >= 1,
        "no verified row found; the parser no longer matches"
    );
}

/// The verified rows here, from both tables, and the supported matrix's
/// recorded rows are the same records: client, version, date, owner and
/// evidence file.
#[test]
fn verified_rows_agree_with_the_supported_matrix() {
    let here: BTreeSet<[String; 5]> = all_statuses()
        .into_iter()
        .filter_map(|(client, status)| {
            let v = parse_verified(&status)?;
            Some([label_of(&client), v.version, v.date, v.owner, v.file])
        })
        .collect();
    let recorded = MATRIX
        .split("Rows recorded so far:")
        .nth(1)
        .expect("supported matrix lost its recorded rows");
    let there: BTreeSet<[String; 5]> = table(recorded, "Client")
        .into_iter()
        .map(|c| {
            let file = code_spans(&c[4])
                .into_iter()
                .find(|s| s.starts_with("docs/release/verify/"))
                .unwrap_or_default()
                .trim_start_matches("docs/")
                .to_string();
            [
                label_of(&c[0]),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                file,
            ]
        })
        .collect();
    assert!(
        !there.is_empty(),
        "no recorded rows parsed from the supported matrix"
    );
    assert_eq!(
        here, there,
        "verified records differ between CLIENTS.md and the supported matrix"
    );
}
