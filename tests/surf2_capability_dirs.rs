// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2 (AUTO rows): the local capability commands read the
//! directories the gateway itself serves, `capabilities.directories` of the
//! loaded config, unless `-C` or `MCP_GATEWAY_CAPABILITIES` overrides them.
//!
//! Every run is the real binary with a cleared environment and an empty
//! working directory, so `./capabilities` never holds a fixture by accident.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

fn run(root: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = gateway_bin::command(root, gateway_bin::Inherit::Nothing);
    command
        .env("PATH", root.join("no-system-programs"))
        .current_dir(root)
        .stdin(Stdio::null())
        .args(args);
    for (k, v) in env {
        command.env(k, v);
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command.output().expect("run mcp-gateway")
}

fn both(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A capability named `name` in `dir`, described as `description`.
fn capability(dir: &Path, name: &str, description: &str, ext: &str) {
    std::fs::create_dir_all(dir).expect("caps dir");
    let yaml = format!(
        "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /{name}\n"
    );
    std::fs::write(dir.join(format!("{name}.{ext}")), yaml).expect("capability");
}

/// A gateway config at `path` naming `dirs` as capability directories.
fn config(path: &Path, dirs: &[&str], extra: &str) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("config dir");
    let list = dirs
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        path,
        format!("capabilities:\n  directories: [{list}]\n{extra}"),
    )
    .expect("config");
}

/// A root holding `conf/gateway.yaml` that names `<root>/dir_a` with `alpha`.
fn setup() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("root");
    let dir_a = root.path().join("dir_a");
    capability(&dir_a, "alpha", "Alpha one", "yaml");
    let cfg = root.path().join("conf").join("gateway.yaml");
    config(&cfg, &[dir_a.to_str().expect("utf-8")], "");
    (root, cfg)
}

fn with_config<'a>(cfg: &'a Path, rest: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["--config", cfg.to_str().expect("utf-8")];
    args.extend_from_slice(rest);
    args
}

/// E1a: `tool list` lists the configured directory's tools.
#[test]
fn tool_list_reads_the_configured_directories() {
    let (root, cfg) = setup();
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    assert!(out.status.success(), "{}", both(&out));
    assert!(both(&out).contains("alpha"), "{}", both(&out));
}

/// E1b: `tool inspect` finds a tool in the configured directory.
#[test]
fn tool_inspect_reads_the_configured_directories() {
    let (root, cfg) = setup();
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "inspect", "alpha"]),
    );
    assert!(out.status.success(), "{}", both(&out));
    assert!(both(&out).contains("Alpha one"), "{}", both(&out));
}

/// E1c: `tool invoke` loads the tool and reaches execution: its request to
/// the capability's own host (`api.invalid`) fails in transport, not the
/// catalogue load.
#[test]
fn tool_invoke_reads_the_configured_directories() {
    let (root, cfg) = setup();
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "invoke", "alpha"]),
    );
    let shown = both(&out);
    assert!(
        shown.contains("Transport error") && !shown.contains("Failed to load capabilities"),
        "{shown}"
    );
}

/// E1d: `tool completions` names the configured directory's tools.
#[test]
fn tool_completions_reads_the_configured_directories() {
    let (root, cfg) = setup();
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "completions", "bash"]),
    );
    assert!(out.status.success(), "{}", both(&out));
    assert!(both(&out).contains("alpha"), "{}", both(&out));
}

/// E1e: `skills generate` writes a skill for the configured directory's tools.
#[test]
fn skills_generate_reads_the_configured_directories() {
    let (root, cfg) = setup();
    let out_dir = root.path().join("skills_out");
    let out = run(
        root.path(),
        &[],
        &with_config(
            &cfg,
            &[
                "skills",
                "generate",
                "--out-dir",
                out_dir.to_str().expect("utf-8"),
            ],
        ),
    );
    assert!(out.status.success(), "{}", both(&out));
    let written = walk(&out_dir);
    assert!(written.iter().any(|f| f.contains("alpha")), "{written:?}");
}

fn walk(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path.display().to_string());
                if std::fs::read_to_string(&path).is_ok_and(|text| text.contains("alpha")) {
                    found.push("alpha (content)".to_owned());
                }
            }
        }
    }
    found
}

/// E2: `-C` beats the config, the env var beats the config, `-C` beats both.
#[test]
fn flag_and_env_override_the_config() {
    let (root, cfg) = setup();
    let dir_b = root.path().join("dir_b");
    capability(&dir_b, "beta", "Beta", "yaml");
    let b = dir_b.to_str().expect("utf-8");
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "list", "-C", b]),
    );
    assert!(
        both(&out).contains("beta") && !both(&out).contains("alpha"),
        "{}",
        both(&out)
    );
    let env = [("MCP_GATEWAY_CAPABILITIES", b)];
    let out = run(root.path(), &env, &with_config(&cfg, &["tool", "list"]));
    assert!(
        both(&out).contains("beta") && !both(&out).contains("alpha"),
        "{}",
        both(&out)
    );
    let dir_c = root.path().join("dir_c");
    capability(&dir_c, "gamma", "Gamma", "yaml");
    let c = dir_c.to_str().expect("utf-8");
    let out = run(
        root.path(),
        &env,
        &with_config(&cfg, &["tool", "list", "-C", c]),
    );
    assert!(
        both(&out).contains("gamma") && !both(&out).contains("beta"),
        "{}",
        both(&out)
    );
}

/// E3: no config and no overlay keep `./capabilities`.
#[test]
fn no_config_keeps_the_local_capabilities_directory() {
    let root = tempfile::tempdir().expect("root");
    capability(
        &root.path().join("capabilities"),
        "local_cap",
        "Local",
        "yaml",
    );
    let out = run(root.path(), &[], &["tool", "list"]);
    assert!(out.status.success(), "{}", both(&out));
    assert!(both(&out).contains("local_cap"), "{}", both(&out));
}

/// E4: a config that will not load stops the command, names the file and
/// `doctor`, and never prints the bad value.
#[test]
fn a_broken_config_stops_the_command_without_quoting_it() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &cfg,
        "server:\n  port: surf2-cap-sentinel\n",
    )
    .expect("config");
    // Positive control: while MIK-8375 is open the loader's own error quotes
    // the value, so the command has a leak to suppress.
    let leaks_today = mcp_gateway::config::Config::load(Some(&cfg))
        .err()
        .is_some_and(|e| e.to_string().contains("surf2-cap-sentinel"));
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    let shown = both(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(
        shown.contains(&format!("could not load {}", cfg.display())) && shown.contains("doctor"),
        "{shown}"
    );
    assert!(
        !shown.contains("surf2-cap-sentinel"),
        "leaks_today={leaks_today}: {shown}"
    );
}

/// E5: an explicit `--config` naming a missing file is an error.
#[test]
fn an_explicit_missing_config_is_an_error() {
    let root = tempfile::tempdir().expect("root");
    let missing = root.path().join("missing.yaml");
    let out = run(root.path(), &[], &with_config(&missing, &["tool", "list"]));
    assert_eq!(out.status.code(), Some(1), "{}", both(&out));
    assert!(
        both(&out).contains("Config file not found"),
        "{}",
        both(&out)
    );
}

/// E6: a later directory's definition of a name replaces an earlier one.
#[test]
fn a_later_directory_wins_a_name() {
    let root = tempfile::tempdir().expect("root");
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    capability(&a, "alpha", "First alpha", "yaml");
    capability(&b, "alpha", "Second alpha", "yaml");
    let cfg = root.path().join("gateway.yaml");
    config(
        &cfg,
        &[a.to_str().expect("utf-8"), b.to_str().expect("utf-8")],
        "",
    );
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "inspect", "alpha"]),
    );
    assert!(both(&out).contains("Second alpha"), "{}", both(&out));
}

/// E7: a missing directory is warned about; the others are still read.
#[test]
fn a_missing_directory_does_not_hide_the_others() {
    let (root, _) = setup();
    let dir_a = root.path().join("dir_a");
    let gone = root.path().join("gone_dir");
    let cfg = root.path().join("gateway2.yaml");
    config(
        &cfg,
        &[
            gone.to_str().expect("utf-8"),
            dir_a.to_str().expect("utf-8"),
        ],
        "",
    );
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    let shown = both(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("alpha") && shown.contains("gone_dir"),
        "{shown}"
    );
}

/// E8: an empty list of directories says so.
#[test]
fn no_directories_says_so() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    config(&cfg, &[], "");
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    assert!(out.status.success(), "{}", both(&out));
    assert!(
        both(&out).contains("No capability files found in the configured directories"),
        "{}",
        both(&out)
    );
}

/// E9: with no file, the environment overlay's directories are used.
#[test]
fn an_env_overlay_names_capability_dirs() {
    let root = tempfile::tempdir().expect("root");
    let dir = root.path().join("env_dir");
    capability(&dir, "env_cap", "From env", "yaml");
    let value = format!("[\"{}\"]", dir.display());
    let env = [("MCP_GATEWAY_CAPABILITIES__DIRECTORIES", value.as_str())];
    let out = run(root.path(), &env, &["tool", "list"]);
    assert!(both(&out).contains("env_cap"), "{}", both(&out));
}

/// E10: `tool completions` reads `.yml` files, as the gateway does.
#[test]
fn completions_read_yml_files() {
    let root = tempfile::tempdir().expect("root");
    let dir = root.path().join("yml_dir");
    capability(&dir, "yml_cap", "Yml", "yml");
    let cfg = root.path().join("gateway.yaml");
    config(&cfg, &[dir.to_str().expect("utf-8")], "");
    let out = run(
        root.path(),
        &[],
        &with_config(&cfg, &["tool", "completions", "bash"]),
    );
    assert!(both(&out).contains("yml_cap"), "{}", both(&out));
}

/// E11: a relative directory resolves against the working directory.
#[test]
fn a_relative_capability_dir_resolves_against_cwd() {
    let root = tempfile::tempdir().expect("root");
    capability(&root.path().join("rel_caps"), "rel_cap", "Relative", "yaml");
    let cfg = root.path().join("conf").join("gateway.yaml");
    config(&cfg, &["rel_caps"], "");
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    assert!(both(&out).contains("rel_cap"), "{}", both(&out));
}

/// E12: `capabilities.enabled: false` still names the directories to read.
#[test]
fn disabled_capabilities_still_name_capability_dirs() {
    let root = tempfile::tempdir().expect("root");
    let dir = root.path().join("dis_caps");
    capability(&dir, "dis_cap", "Disabled serving", "yaml");
    let cfg = root.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &cfg,
        format!(
            "capabilities:\n  enabled: false\n  directories: [\"{}\"]\n",
            dir.display()
        ),
    )
    .expect("config");
    let out = run(root.path(), &[], &with_config(&cfg, &["tool", "list"]));
    assert!(both(&out).contains("dis_cap"), "{}", both(&out));
}

/// E13: `./gateway.yaml` in the working directory is found without `--config`.
#[test]
fn the_fallback_search_finds_the_config() {
    let root = tempfile::tempdir().expect("root");
    let dir = root.path().join("found_caps");
    capability(&dir, "found_cap", "Found", "yaml");
    config(
        &root.path().join("gateway.yaml"),
        &[dir.to_str().expect("utf-8")],
        "",
    );
    let out = run(root.path(), &[], &["tool", "list"]);
    assert!(both(&out).contains("found_cap"), "{}", both(&out));
}

/// E15: a `${VAR}` entry expands as the gateway expands it.
#[test]
fn a_variable_entry_expands_as_the_gateway_does() {
    let root = tempfile::tempdir().expect("root");
    let dir = root.path().join("var_caps");
    capability(&dir, "var_cap", "From a variable", "yaml");
    let cfg = root.path().join("gateway.yaml");
    config(&cfg, &["${SURF2_CAPS_DIR}"], "");
    let env = [("SURF2_CAPS_DIR", dir.to_str().expect("utf-8"))];
    let out = run(root.path(), &env, &with_config(&cfg, &["tool", "list"]));
    assert!(both(&out).contains("var_cap"), "{}", both(&out));
}

/// E4b: every command stops on a config that will not load, naming `doctor`
/// and never the bad value; completions included.
#[test]
fn every_command_stops_on_a_broken_config() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &cfg,
        "server:\n  port: surf2-cap-sentinel\n",
    )
    .expect("config");
    let out_dir = root.path().join("skills_out");
    let out_dir = out_dir.to_str().expect("utf-8");
    for cmd in [
        vec!["tool", "inspect", "alpha"],
        vec!["tool", "invoke", "alpha"],
        vec!["tool", "completions", "bash"],
        vec!["skills", "generate", "--out-dir", out_dir],
    ] {
        let out = run(root.path(), &[], &with_config(&cfg, &cmd));
        let shown = both(&out);
        assert_eq!(out.status.code(), Some(1), "{cmd:?}: {shown}");
        assert!(shown.contains("doctor"), "{cmd:?}: {shown}");
        assert!(!shown.contains("surf2-cap-sentinel"), "{cmd:?}: {shown}");
    }
}

/// gpt impl: with no `--config`, the message names the config the loader
/// picked (here `./gateway.yaml`, found by the search).
#[test]
fn the_message_names_the_picked_config() {
    let root = tempfile::tempdir().expect("root");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        root.path().join("gateway.yaml"),
        "server:\n  port: surf2-cap-sentinel\n",
    )
    .expect("config");
    let out = run(root.path(), &[], &["tool", "list"]);
    let shown = both(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(shown.contains("could not load gateway.yaml"), "{shown}");
}

/// E9b: a config file and an env overlay both name directories; the overlay
/// wins, as `Config::load` orders them for the gateway.
#[test]
fn an_env_overlay_beats_the_config_file() {
    let root = tempfile::tempdir().expect("root");
    let (from_file, from_env) = (root.path().join("file_caps"), root.path().join("env_caps"));
    capability(&from_file, "file_cap", "From the file", "yaml");
    capability(&from_env, "env_cap", "From the env", "yaml");
    let cfg = root.path().join("gateway.yaml");
    config(&cfg, &[from_file.to_str().expect("utf-8")], "");
    let value = format!("[\"{}\"]", from_env.display());
    let env = [("MCP_GATEWAY_CAPABILITIES__DIRECTORIES", value.as_str())];
    let out = run(root.path(), &env, &with_config(&cfg, &["tool", "list"]));
    let shown = both(&out);
    assert!(
        shown.contains("env_cap") && !shown.contains("file_cap"),
        "{shown}"
    );
}
