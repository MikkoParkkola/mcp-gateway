// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/CLIENTS.md`: the client matrix matches the exporter, and every
//! verified row points at a recorded run that carries what the row claims.
//!
//! The exporter's client list and path helpers are binary-private, so they are
//! read as source text; `ExportTarget` is public and is read through clap.

#[cfg(feature = "config-export")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;

// The export rows read `mcp-gateway export`, a `config-export` subcommand.
#[cfg(feature = "config-export")]
use clap::{Parser as _, ValueEnum as _};
#[cfg(feature = "config-export")]
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
#[cfg(feature = "config-export")]
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
#[cfg(feature = "config-export")]
fn literals(src: &str, open: &str, prefix: &str) -> BTreeSet<String> {
    src.split(open)
        .skip(1)
        .map(|p| format!("{prefix}{}", p.split('"').next().unwrap_or("")))
        .collect()
}

/// What the exporter does per client: label -> (config key, paths written).
/// A path is a `home_path("…")` (shown as `~/…`) or `cwd.join("…")` literal,
/// or a helper in `src/commands/paths.rs` whose literals are all its paths.
#[cfg(feature = "config-export")]
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
            let body = fn_body(helpers, path.trim_end_matches("()"));
            let per_platform: BTreeSet<String> = platform_paths_in(body)
                .into_iter()
                .map(|(_, p)| p)
                .collect();
            if per_platform.is_empty() {
                literals(body, "home_path(\"", "~/")
            } else {
                per_platform
            }
        };
        assert!(!paths.is_empty(), "{label}: no path found in `{path}`");
        out.insert(label, (key, paths));
    }
    out
}

/// (platform word, path) for every platform-specific literal in the path
/// helpers, from the `#[cfg]` line above each `return`.
#[cfg(feature = "config-export")]
fn platform_paths() -> Vec<(&'static str, String)> {
    platform_paths_in(PATHS_SRC.split("#[cfg(test)]").next().unwrap())
}

/// As [`platform_paths`], for one helper body. A `config_dir_path("…")` is
/// the OS config directory: `$XDG_CONFIG_HOME/…` on Linux, `%APPDATA%/…` on
/// Windows.
#[cfg(feature = "config-export")]
fn platform_paths_in(src: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let mut cfg = "";
    for line in src.lines().map(str::trim) {
        if line.starts_with("#[cfg(") {
            cfg = line;
            continue;
        }
        let (rest, config_dir) = if let Some(rest) = line.strip_prefix("return home_path(\"") {
            (rest, false)
        } else if let Some(rest) = line.strip_prefix("return config_dir_path(\"") {
            (rest, true)
        } else {
            continue;
        };
        {
            let word = match cfg {
                c if c.contains("not(any(") => "Windows",
                c if c.contains("not(") => "elsewhere",
                c if c.contains("\"macos\"") => "macOS",
                c if c.contains("\"linux\"") => "Linux",
                other => panic!("unrecognised cfg `{other}` in src/commands/paths.rs"),
            };
            let lit = rest.split('"').next().unwrap();
            let path = match (config_dir, word) {
                (false, _) => format!("~/{lit}"),
                (true, "Linux") => format!("$XDG_CONFIG_HOME/{lit}"),
                (true, "Windows") => format!("%APPDATA%/{lit}"),
                (true, other) => panic!("config_dir_path under `{other}` has no documented form"),
            };
            out.push((word, path));
        }
    }
    out
}

/// `--target` value -> client label, from the exporter's `match target` arms.
#[cfg(feature = "config-export")]
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

#[cfg(feature = "config-export")]
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
#[cfg(feature = "config-export")]
#[test]
fn each_row_matches_the_exporter_for_that_client() {
    let clients = exporter_clients();
    let targets = target_labels();
    let clap_names: BTreeSet<String> = ExportTarget::value_variants()
        .iter()
        .map(|t| t.to_possible_value().unwrap().get_name().to_string())
        .collect();
    for target in targets.keys() {
        assert!(
            clap_names.contains(target),
            "derived target `{target}` is not a clap value"
        );
    }
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
        for (platform, path) in platform_paths() {
            if real_paths.contains(&path) {
                assert!(
                    location.contains(&format!("{platform} `{path}`")),
                    "{label}: `{path}` must be labelled {platform}"
                );
            }
        }
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
    let file = rest.split("[run](").nth(1)?.split(')').next()?.to_string();
    Some(Verified {
        version,
        date,
        owner,
        commit,
        file,
    })
}

/// A concrete version: dot-separated numbers (at least two), optionally
/// followed by `-` and a pre-release of letters, digits and dots. `2.x`,
/// `2.1.*`, `latest` and a bare `2` are not concrete.
fn is_concrete_version(v: &str) -> bool {
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && pre.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
        && !(v.contains('-') && pre.is_empty())
}

/// Whether a run's Gateway field names release 4.0.0 exactly, not
/// `14.0.0`, `4.0.01` or a `4.0.0-rc.1` pre-release.
fn is_gateway_4_0_0(cell: &str) -> bool {
    has_token(cell, "4.0.0")
}

/// A real calendar date in ISO-8601 form, four-digit year first.
fn is_iso_date(s: &str) -> bool {
    s.len() == 10 && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
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

/// The value cell of a recorded run's `| Field | value |` row.
fn run_field<'a>(run: &'a str, field: &str) -> &'a str {
    let line = run
        .lines()
        .find(|l| l.starts_with(&format!("| {field} |")))
        .unwrap_or_else(|| panic!("the recorded run has no `{field}` row"));
    line[field.len() + 4..].trim().trim_end_matches('|').trim()
}

/// Whether `cell` holds `token` as a whole token: not a prefix of a longer
/// version, word or hash.
fn has_token(cell: &str, token: &str) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+');
    !token.is_empty()
        && cell.match_indices(token).any(|(i, _)| {
            let before = cell[..i].chars().next_back();
            let rest = &cell[i + token.len()..];
            // A `.` ends a sentence only when no version component follows it.
            let continues = rest.starts_with('.')
                && rest[1..].starts_with(|c: char| c.is_ascii_alphanumeric())
                || rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '+');
            !before.is_some_and(part) && !continues
        })
}

/// Whether `cell` begins with the whole value `value`: it is the entire cell
/// or is followed by `;`, `,` or ` (`, so `Mikko` does not match
/// `Mikko Parkkola` and `Claude` does not match `Claude Code`.
fn leads_with(cell: &str, value: &str) -> bool {
    !value.is_empty()
        && cell.strip_prefix(value).is_some_and(|rest| {
            rest.is_empty()
                || rest.starts_with(';')
                || rest.starts_with(',')
                || rest.starts_with(" (")
        })
}

#[test]
fn run_field_matching_is_exact() {
    let run = "| Client | Claude Code (CLI), `2.1.280 (Claude Code)` |\n| Owner | |\n\
               | Date | 2026-09-23 (UTC 00:05) |\n| Gateway | built at `e3c8645f` (x) |\n";
    let client = run_field(run, "Client");
    assert!(has_token(client, "2.1.280"));
    for wrong in ["2.1.28", "2.1", "2"] {
        assert!(!has_token(client, wrong), "{wrong} must not match 2.1.280");
    }
    assert!(!has_token("`2.1.280.1`", "2.1.280"));
    assert!(!has_token("`2.1.280+build.1`", "2.1.280"));
    assert!(is_iso_date("2026-09-23"));
    assert!(is_gateway_4_0_0(
        "`mcp-gateway --version` → `mcp-gateway 4.0.0`, built at `e3c8645f`"
    ));
    for other in [
        "mcp-gateway 14.0.0",
        "mcp-gateway 4.0.01",
        "mcp-gateway 4.0.0-rc.1",
        "mcp-gateway 3.5.0",
    ] {
        assert!(!is_gateway_4_0_0(other), "{other} is not 4.0.0");
    }
    assert!(is_concrete_version("2.1.280") && is_concrete_version("0.11.4-rc.1"));
    for placeholder in ["2.x", "2.1.*", "latest", "current", "2", "2.1-"] {
        assert!(
            !is_concrete_version(placeholder),
            "{placeholder} is not concrete"
        );
    }
    assert!(!is_iso_date("2026-13-40"));
    let cell = "Verified: 2.1.280, 2026-09-23, owner A, gateway `e3c8645f`, see [notes](other.md) ([run](release/verify/x.md))";
    assert_eq!(parse_verified(cell).unwrap().file, "release/verify/x.md");
    assert!(has_token("ran 2.1.280.", "2.1.280"));
    assert!(leads_with(client, "Claude Code"));
    assert!(!leads_with(client, "Claude"));
    assert_eq!(run_field(run, "Owner"), "");
    assert!(!leads_with(run_field(run, "Owner"), "Owner"));
    assert!(leads_with("Mikko Parkkola; run by x", "Mikko Parkkola"));
    assert!(!leads_with("Mikko Parkkola; run by x", "Mikko"));
    assert!(leads_with(run_field(run, "Date"), "2026-09-23"));
    assert!(!leads_with(run_field(run, "Date"), "2026-09-2"));
    assert!(has_token(run_field(run, "Gateway"), "e3c8645f"));
    assert!(!has_token(run_field(run, "Gateway"), "e3c8645"));
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
            is_concrete_version(&v.version),
            "{client}: version `{}` is not a specific client version",
            v.version
        );
        assert!(
            (7..=40).contains(&v.commit.len()) && v.commit.chars().all(|c| c.is_ascii_hexdigit()),
            "{client}: gateway `{}` is not a commit id",
            v.commit
        );
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
            leads_with(client_cell, &label_of(&client)) && has_token(client_cell, &v.version),
            "{client}: the run's Client field does not name this client at {}",
            v.version
        );
        assert!(
            leads_with(run_field(&run, "Date"), &v.date),
            "{client}: run date"
        );
        assert!(
            leads_with(run_field(&run, "Owner"), &v.owner),
            "{client}: run owner"
        );
        assert!(
            has_token(run_field(&run, "Gateway"), &v.commit),
            "{client}: run gateway commit"
        );
        assert!(
            is_gateway_4_0_0(run_field(&run, "Gateway")),
            "{client}: the recorded run is not against a 4.0.0 gateway"
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
    let here_commits: Vec<(String, String)> = all_statuses()
        .into_iter()
        .filter_map(|(client, status)| Some((label_of(&client), parse_verified(&status)?.commit)))
        .collect();
    let recorded = MATRIX
        .split("Rows recorded so far:")
        .nth(1)
        .expect("supported matrix lost its recorded rows");
    let there: BTreeSet<[String; 5]> = table(recorded, "Client")
        .into_iter()
        .map(|c| {
            let commit = here_commits
                .iter()
                .find(|(k, _)| *k == label_of(&c[0]))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            assert!(
                has_token(&c[4], &commit),
                "supported matrix row {} does not name gateway commit `{commit}`",
                c[0]
            );
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
