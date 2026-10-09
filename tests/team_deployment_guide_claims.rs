// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/TEAM_DEPLOYMENT.md`: what the guide tells an operator to type is
//! checked against the code, so the guide goes red when either one drifts.
//!
//! - its gateway config block loads through the public `Config::load`;
//! - every config key it names in prose is one the gateway reads;
//! - its Helm values exist in the chart, with the chart's enum and defaults;
//! - its defaults table matches `Config::default()`;
//! - its `mcp-gateway` commands parse;
//! - its relative links and anchors resolve.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use mcp_gateway::config::{CleartextHttp, Config};

const DOC: &str = include_str!("../docs/TEAM_DEPLOYMENT.md");
const VALUES: &str = include_str!("../deploy/helm/mcp-gateway/values.yaml");
const SCHEMA: &str = include_str!("../deploy/helm/mcp-gateway/values.schema.json");
const HELM_MARKER: &str = "# Helm values";

fn write(path: &Path, body: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(path, body).expect("write file");
}

/// Bodies of the fenced blocks opened with ```` ```lang ````.
fn fenced(doc: &str, lang: &str) -> Vec<String> {
    let open = format!("```{lang}");
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in doc.lines() {
        match current.as_mut() {
            None if line.trim_end() == open => current = Some(String::new()),
            Some(_) if line.trim_end() == "```" => blocks.push(current.take().unwrap()),
            Some(body) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    blocks
}

/// The document with fenced blocks removed, as (line, section heading).
fn prose(doc: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_fence = false;
    let mut section = String::new();
    for line in doc.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(h) = line.strip_prefix("## ") {
            section = h.trim().to_string();
        }
        out.push((line.to_string(), section.clone()));
    }
    out
}

/// Every `` `code` `` span on a line.
fn code_spans(line: &str) -> Vec<String> {
    line.split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

fn is_dotted_key(span: &str) -> bool {
    let parts: Vec<&str> = span.split('.').collect();
    parts.len() > 1
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Load `yaml` (plus an `env_files` entry defining `env`) from a temp dir.
fn load(yaml: &str, env: &str) -> mcp_gateway::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join("gateway.env");
    write(&env_path, env);
    let path = dir.path().join("gateway.yaml");
    write(
        &path,
        &format!("env_files: ['{}']\n{yaml}", env_path.display()),
    );
    Config::load(Some(&path))
}

/// Whether the gateway reads config key `dotted`: a file setting it (to a
/// string) is not refused as an unrecognised or unknown key. A type error means
/// the key was read.
fn gateway_reads(dotted: &str) -> bool {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut yaml = String::new();
    for (depth, part) in parts.iter().enumerate() {
        let indent = "  ".repeat(depth);
        let value = if depth + 1 == parts.len() {
            " \"probe\""
        } else {
            ""
        };
        yaml.push_str(&indent);
        yaml.push_str(part);
        yaml.push(':');
        yaml.push_str(value);
        yaml.push('\n');
    }
    match load(&yaml, "TEAM_GUIDE_UNUSED=1\n") {
        Ok(_) => true,
        Err(e) => {
            let msg = e.to_string();
            // Any key-check refusal fails the probe, including one naming an
            // ancestor of the probed key rather than its leaf.
            if msg.contains("Unrecognised config key") || msg.contains("unknown field") {
                return false;
            }
            // A type error is raised while extracting, before the key check:
            // it proves the key is read only when it names this exact key,
            // not an ancestor that could not hold a mapping.
            if msg.contains("invalid type") || msg.contains("invalid value") {
                return msg.contains(&format!("{dotted}\""));
            }
            // Validation runs after the key check, so the key was read.
            true
        }
    }
}

fn values() -> serde_yaml::Value {
    serde_yaml::from_str(VALUES).expect("values.yaml parses")
}

fn helm_value<'v>(root: &'v serde_yaml::Value, dotted: &str) -> Option<&'v serde_yaml::Value> {
    dotted.split('.').try_fold(root, |node, key| node.get(key))
}

/// The chart schema's `enum` for a values path, if it declares one.
fn schema_enum(dotted: &str) -> Option<BTreeSet<String>> {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).expect("schema parses");
    let mut node = &schema;
    for key in dotted.split('.') {
        node = node.get("properties")?.get(key)?;
    }
    Some(
        node.get("enum")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    )
}

/// First-column cells of the table whose header's first cell is `header`,
/// with backticks stripped, and which row carries ` (default)`.
fn table(doc: &str, header: &str) -> (Vec<(String, String)>, Option<String>) {
    let mut rows = Vec::new();
    let mut default = None;
    let mut lines = doc.lines().skip_while(|l| {
        l.strip_prefix('|')
            .and_then(|r| r.split('|').next())
            .is_none_or(|c| c.trim() != header)
    });
    assert!(
        lines.next().is_some(),
        "table `{header}` not found in the guide"
    );
    for line in lines.skip(1) {
        let Some(rest) = line.strip_prefix('|') else {
            break;
        };
        let cells: Vec<&str> = rest.split('|').map(str::trim).collect();
        let first = cells[0];
        let value = first.replace(" (default)", "").replace('`', "");
        if first.contains("(default)") {
            default = Some(value.clone());
        }
        rows.push((value, cells.get(1).unwrap_or(&"").replace('`', "")));
    }
    (rows, default)
}

#[test]
fn gateway_config_block_loads() {
    let blocks: Vec<String> = fenced(DOC, "yaml")
        .into_iter()
        .filter(|b| !b.starts_with(HELM_MARKER))
        .collect();
    assert_eq!(blocks.len(), 1, "the guide has one gateway config block");
    let alice = format!("sha256:{}", "ab".repeat(32));
    let bob = format!("sha256:{}", "cd".repeat(32));
    let env = format!(
        "MCP_GATEWAY_TOKEN=team-guide-operator-token-0123456789abcdef\n\
         ALICE_KEY_SHA256={alice}\nBOB_KEY_SHA256={bob}\n"
    );
    let config = load(&blocks[0], &env)
        .unwrap_or_else(|e| panic!("docs/TEAM_DEPLOYMENT.md config block does not load: {e}"));
    assert_eq!(
        config.server.cleartext_http,
        CleartextHttp::TlsTerminatedUpstream
    );
    assert!(
        config.auth.enabled
            && config
                .security
                .transparency_log
                .is_enabled(config.auth.enabled)
    );
}

#[test]
fn prose_config_keys_are_read_by_the_gateway() {
    assert!(
        gateway_reads("auth.enabled"),
        "probe must accept a real key"
    );
    assert!(
        !gateway_reads("auth.enabeld"),
        "probe must refuse a misspelt key"
    );
    assert!(
        !gateway_reads("auth.bearer_token.typo"),
        "probe must refuse a key under a scalar"
    );
    assert!(
        !gateway_reads("security.caller_identity.modee.typo"),
        "probe must refuse a key under a misspelt ancestor"
    );
    assert!(
        !gateway_reads("security.caller_identity.modee"),
        "probe must refuse a misspelt key under a strict struct"
    );
    let roots = [
        "auth",
        "server",
        "security",
        "key_server",
        "mtls",
        "agent_auth",
    ];
    let values = values();
    let mut checked = 0;
    let mut missing = Vec::new();
    for (line, section) in prose(DOC) {
        for span in code_spans(&line) {
            if !is_dotted_key(&span) {
                continue;
            }
            let root = span.split('.').next().unwrap();
            let helm = section.starts_with("Kubernetes");
            let as_gateway = span.strip_prefix("config.").unwrap_or(&span);
            let ok = if helm {
                helm_value(&values, &span).is_some()
                    || (roots.contains(&as_gateway.split('.').next().unwrap())
                        && gateway_reads(as_gateway))
            } else if roots.contains(&root) {
                gateway_reads(&span)
            } else {
                continue;
            };
            checked += 1;
            if !ok {
                missing.push(format!("`{span}` ({section})"));
            }
        }
    }
    assert!(
        checked > 15,
        "found only {checked} keys; the scan no longer matches the guide"
    );
    assert!(missing.is_empty(), "keys nothing reads: {missing:?}");
}

#[test]
fn helm_values_block_names_real_chart_values() {
    let blocks: Vec<String> = fenced(DOC, "yaml")
        .into_iter()
        .filter(|b| b.starts_with(HELM_MARKER))
        .collect();
    assert!(!blocks.is_empty(), "the guide has no Helm values block");
    let chart = values();
    let mut with_config = 0;
    for block in &blocks {
        check_helm_block(&chart, block, &mut with_config);
    }
    assert!(with_config > 0, "no Helm block sets config");
}

/// Every leaf of one Helm values block is a chart value (inside the schema's
/// enum where it has one), and its `config` subtree loads as gateway config.
fn check_helm_block(chart: &serde_yaml::Value, block: &str, with_config: &mut usize) {
    let block: serde_yaml::Value = serde_yaml::from_str(block).expect("block parses");
    let mut leaves = Vec::new();
    collect_leaves(&block, String::new(), &mut leaves);
    assert!(leaves.len() >= 3, "the Helm block has only {leaves:?}");
    // The `config` subtree is gateway config the chart passes through; it
    // must load as written.
    if let Some(config) = block.get("config") {
        *with_config += 1;
        let config = serde_yaml::to_string(config).expect("serialize config");
        if let Err(e) = load(&config, "TEAM_GUIDE_UNUSED=1\n") {
            panic!("the Helm block's `config` does not load: {e}");
        }
    }
    for (path, value) in leaves {
        if let Some(gateway_key) = path.strip_prefix("config.") {
            assert!(
                gateway_reads(gateway_key),
                "`{path}`: the gateway reads no such key"
            );
            continue;
        }
        assert!(
            helm_value(chart, &path).is_some(),
            "`{path}` is not a chart value"
        );
        if let Some(allowed) = schema_enum(&path) {
            assert!(
                allowed.contains(&value),
                "`{path}: {value}` is outside {allowed:?}"
            );
        }
    }
}

fn collect_leaves(node: &serde_yaml::Value, prefix: String, out: &mut Vec<(String, String)>) {
    if let Some(map) = node.as_mapping() {
        for (k, v) in map {
            let k = k.as_str().expect("string key");
            let path = if prefix.is_empty() {
                k.to_string()
            } else {
                format!("{prefix}.{k}")
            };
            collect_leaves(v, path, out);
        }
        return;
    }
    let value = match node {
        serde_yaml::Value::String(s) => s.clone(),
        other => serde_yaml::to_string(other)
            .expect("serialize")
            .trim()
            .to_string(),
    };
    out.push((prefix, value));
}

/// The two Helm mode tables list exactly the schema's values, and the row
/// marked default is the chart's default.
#[test]
fn helm_mode_tables_match_the_chart() {
    let chart = values();
    for path in ["auth.mode", "server.cleartextHttp"] {
        let (rows, default) = table(DOC, &format!("`{path}`"));
        let listed: BTreeSet<String> = rows.into_iter().map(|(v, _)| v).collect();
        let allowed = schema_enum(path).expect("schema declares the enum");
        assert_eq!(
            listed, allowed,
            "`{path}` table rows differ from the chart schema"
        );
        let chart_default = helm_value(&chart, path)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(
            default, chart_default,
            "`{path}` default differs from values.yaml"
        );
    }
}

/// The `server.cleartext_http` table lists every variant, each spelled as
/// the config reads it.
#[test]
fn cleartext_table_lists_every_variant() {
    let (rows, _) = table(DOC, "`server.cleartext_http`");
    let mut seen = BTreeSet::new();
    for (value, _) in rows {
        let parsed: CleartextHttp = serde_yaml::from_str(&value)
            .unwrap_or_else(|e| panic!("`{value}` is not a server.cleartext_http value: {e}"));
        // A new variant fails to compile here until the guide is updated.
        match parsed {
            CleartextHttp::Refuse
            | CleartextHttp::TlsTerminatedUpstream
            | CleartextHttp::ClusterInternal
            | CleartextHttp::HostLocalPublish => {}
        }
        seen.insert(format!("{parsed:?}"));
    }
    assert_eq!(
        seen.len(),
        4,
        "the table must list all four values, got {seen:?}"
    );
}

/// How the defaults table spells an unset audit-log switch (MIK-8044 P2c2).
const UNSET_AUDIT_DEFAULT: &str = "on when `auth.enabled`, else `false`";

#[test]
fn defaults_table_matches_the_code() {
    let d = Config::default();
    let (rows, _) = table(DOC, "Key");
    assert!(rows.len() >= 5, "the defaults table was not found");
    for (key, stated) in rows {
        let actual = match key.as_str() {
            "auth.enabled" => d.auth.enabled.to_string(),
            "server.host" => d.server.host.clone(),
            "server.cleartext_http" => to_yaml(&d.server.cleartext_http),
            "server.replicas" => d.server.replicas.to_string(),
            "security.caller_identity.mode" => to_yaml(&d.security.caller_identity.mode),
            "security.transparency_log.enabled" => d
                .security
                .transparency_log
                .enabled
                .map_or_else(|| UNSET_AUDIT_DEFAULT.to_string(), |v| v.to_string()),
            "key_server.enabled" => d.key_server.enabled.to_string(),
            other => panic!("defaults table row `{other}` has no check; add one"),
        };
        assert_eq!(stated, actual, "default of `{key}`");
    }
}

/// The value as a config file spells it (JSON, so `off` is not quoted).
fn to_yaml<T: serde::Serialize>(value: &T) -> String {
    let json = serde_json::to_value(value).expect("serialize");
    json.as_str()
        .map_or_else(|| json.to_string(), str::to_string)
}

/// Every `mcp-gateway ...` command in the guide, in code spans and bash
/// blocks, parses with the real CLI.
#[test]
fn commands_parse() {
    let mut commands = Vec::new();
    for block in fenced(DOC, "bash") {
        for line in block.lines() {
            let line = line.split(" #").next().unwrap_or(line);
            for part in line.split('|') {
                if let Some(at) = part.find("mcp-gateway ") {
                    commands.push(part[at..].trim().to_string());
                }
            }
        }
    }
    for (line, _) in prose(DOC) {
        commands.extend(
            code_spans(&line)
                .into_iter()
                .filter(|s| s.starts_with("mcp-gateway ")),
        );
    }
    assert!(commands.len() >= 3, "found only {commands:?}");
    for command in commands {
        if let Err(e) = mcp_gateway::cli::Cli::try_parse_from(command.split_whitespace()) {
            panic!("`{command}` does not parse: {e}");
        }
    }
}

/// GitHub's heading anchor: lowercase, punctuation dropped, spaces to `-`.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

fn anchors(doc: &str) -> BTreeSet<String> {
    prose(doc)
        .into_iter()
        .filter_map(|(line, _)| {
            let hashes = line.chars().take_while(|c| *c == '#').count();
            (hashes > 0 && line[hashes..].starts_with(' ')).then(|| slug(&line[hashes..]))
        })
        .collect()
}

#[test]
fn relative_links_and_anchors_resolve() {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut checked = 0;
    let mut broken = Vec::new();
    for (line, _) in prose(DOC) {
        for piece in line.split("](").skip(1) {
            let target = piece.split(')').next().unwrap_or("");
            if target.starts_with("http") {
                continue;
            }
            let (file, anchor) = target.split_once('#').unwrap_or((target, ""));
            let text = if file.is_empty() {
                DOC.to_string()
            } else {
                let Ok(t) = std::fs::read_to_string(docs.join(file)) else {
                    broken.push(format!("{target}: no such file"));
                    continue;
                };
                t
            };
            if !anchor.is_empty() && !anchors(&text).contains(anchor) {
                broken.push(format!("{target}: no such heading"));
            }
            checked += 1;
        }
    }
    assert!(checked > 15, "found only {checked} links");
    assert!(
        broken.is_empty(),
        "broken links in docs/TEAM_DEPLOYMENT.md: {broken:?}"
    );
}
