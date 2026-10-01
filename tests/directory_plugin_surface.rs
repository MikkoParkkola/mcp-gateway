// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Directory-listing surface for the Claude plugin bundle.
//!
//! The catalogue assertion starts the published server the same way
//! `plugin/bin/launch.js` starts it, then reads `tools/list` and the
//! capability catalogue that process loaded. It does not keep a second list
//! of tool names as the source of truth.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use walkdir::WalkDir;

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/MikkoParkkola/mcp-gateway/releases/latest";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn plugin_manifests(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            entry.file_name() != "target"
                && entry.file_name() != ".git"
                && entry.file_name() != "node_modules"
        })
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.file_name().is_some_and(|name| name == "plugin.json")
                && path
                    .parent()
                    .and_then(|dir| dir.file_name())
                    .is_some_and(|name| name == ".claude-plugin")
        })
        .collect()
}

fn words_outside_fences(markdown: &str) -> usize {
    let mut in_fence = false;
    let mut count = 0usize;
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        count += line.split_whitespace().count();
    }
    count
}

fn example_headings(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("### Example")
                && trimmed
                    .chars()
                    .nth(11)
                    .is_none_or(|ch| ch.is_whitespace() || ch == ':')
        })
        .count()
}

/// True when `text` contains an email address. Package scopes such as
/// `@scope/name@1.2.3` are not addresses: the domain must contain a dot and a
/// letter-only suffix of at least two characters.
fn contains_email(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (index, _) in text.match_indices('@') {
        if index == 0 || index + 1 >= bytes.len() {
            continue;
        }
        let mut local_start = index;
        while local_start > 0 && is_email_local(bytes[local_start - 1]) {
            local_start -= 1;
        }
        if local_start == index {
            continue;
        }
        let mut domain_end = index + 1;
        while domain_end < bytes.len() && is_email_domain(bytes[domain_end]) {
            domain_end += 1;
        }
        let domain = &text[index + 1..domain_end];
        let Some((host, tld)) = domain.rsplit_once('.') else {
            continue;
        };
        if !host.is_empty() && tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return true;
        }
    }
    false
}

fn is_email_local(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn capabilities_dir_from_launcher(repo: &Path, launch_js: &str) -> PathBuf {
    let start = launch_js
        .find("path.resolve(")
        .expect("launch.js must resolve the capabilities directory with path.resolve");
    let rest = &launch_js[start + "path.resolve(".len()..];
    let end = rest.find(')').expect("path.resolve call must be closed");
    let parts: Vec<&str> = rest[..end]
        .split(',')
        .map(|part| part.trim().trim_matches('"').trim_matches('\''))
        .collect();
    assert!(
        parts.first().is_some_and(|part| *part == "__dirname"),
        "path.resolve must start from __dirname, got {parts:?}"
    );
    let mut path = repo.join("plugin").join("bin");
    for part in parts.iter().skip(1) {
        assert!(!part.is_empty(), "empty path.resolve argument");
        path = path.join(part);
    }
    path.canonicalize()
        .unwrap_or_else(|err| panic!("capabilities dir {}: {err}", path.display()))
}

#[test]
fn exactly_one_plugin_manifest() {
    let manifests = plugin_manifests(&repo_root());
    assert_eq!(
        manifests.len(),
        1,
        "expected exactly one .claude-plugin/plugin.json, found {manifests:?}"
    );
    assert!(
        manifests[0].ends_with("plugin/.claude-plugin/plugin.json"),
        "manifest is {}",
        manifests[0].display()
    );
}

#[tokio::test]
async fn plugin_version_equals_latest_github_release() {
    let manifest: Value = serde_json::from_str(&read(
        &repo_root().join("plugin/.claude-plugin/plugin.json"),
    ))
    .expect("plugin.json");
    let version = manifest["version"]
        .as_str()
        .expect("plugin.json version")
        .to_string();
    assert_eq!(manifest["name"].as_str(), Some("mcp-gateway"));
    assert_eq!(
        manifest["license"].as_str(),
        Some("PolyForm-Noncommercial-1.0.0")
    );

    let client = reqwest::Client::builder()
        .user_agent("mcp-gateway-directory-plugin-surface")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("http client");
    let mut request = client.get(LATEST_RELEASE_URL);
    if let Some(token) = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .filter(|token| !token.is_empty())
    {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("latest release request");
    let status = response.status();
    let body = response.text().await.expect("latest release body");
    assert!(
        status.is_success(),
        "latest release request failed: {status} {body}"
    );
    let release: Value = serde_json::from_str(&body).expect("latest release json");
    let tag = release["tag_name"]
        .as_str()
        .unwrap_or_else(|| panic!("tag_name missing in {body}"));
    let release_version = tag.strip_prefix('v').unwrap_or(tag);
    assert_eq!(
        version, release_version,
        "plugin version must equal latest release tag {tag}"
    );
}

#[test]
fn readme_has_three_examples_and_states_local_host() {
    let readme = read(&repo_root().join("plugin/README.md"));
    let words = words_outside_fences(&readme);
    assert!(
        words >= 40,
        "README has {words} words outside code fences, want at least 40"
    );
    assert!(
        example_headings(&readme) >= 3,
        "README needs at least three '### Example' headings"
    );
    assert!(
        readme.contains("listens on localhost"),
        "README must state that the server listens on localhost"
    );
    assert!(
        readme.contains("not a public hosted server"),
        "README must state that this is not a public hosted server"
    );
}

#[test]
fn plugin_license_matches_repo_noncommercial_text() {
    let root = repo_root();
    let plugin_license = fs::read(root.join("plugin/LICENSE")).expect("plugin/LICENSE");
    let repo_license = fs::read(root.join("LICENSE-NONCOMMERCIAL")).expect("LICENSE-NONCOMMERCIAL");
    assert_eq!(
        plugin_license, repo_license,
        "plugin/LICENSE must be byte-equal to LICENSE-NONCOMMERCIAL"
    );
    let text = String::from_utf8(plugin_license).expect("licence is utf-8");
    assert!(text.contains("PolyForm Noncommercial"));
    assert!(text.contains("1.0.0"));
}

#[test]
fn mcp_json_command_is_node_not_a_shell() {
    let mcp: Value =
        serde_json::from_str(&read(&repo_root().join("plugin/.mcp.json"))).expect(".mcp.json");
    let server = &mcp["mcpServers"]["mcp-gateway"];
    assert_eq!(server["command"].as_str(), Some("node"));
    assert!(
        server.get("shell").is_none(),
        "mcp server must not set a shell"
    );
    let args = server["args"]
        .as_array()
        .expect(".mcp.json args must be an array");
    assert_eq!(
        args.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
        vec!["${CLAUDE_PLUGIN_ROOT}/bin/launch.js"]
    );
}

#[test]
fn launch_js_pins_package_and_passes_a_config_file() {
    let root = repo_root();
    let manifest: Value =
        serde_json::from_str(&read(&root.join("plugin/.claude-plugin/plugin.json")))
            .expect("plugin.json");
    let version = manifest["version"].as_str().expect("version");
    let launch = read(&root.join("plugin/bin/launch.js"));
    let pin = format!("@mikkoparkkola/mcp-gateway@{version}");
    assert!(
        launch.contains(&pin),
        "launch.js must pin {pin}, got the published package line missing"
    );
    assert!(
        launch.contains("\"--config\""),
        "launch.js must pass a config file to the published binary"
    );
    assert!(launch.contains("\"serve\""));
    assert!(launch.contains("\"--stdio\""));
    assert!(
        launch.contains("delete env[key]"),
        "launch.js must drop an inherited MCP_GATEWAY_CAPABILITIES value"
    );
    assert!(
        !launch.contains("MCP_GATEWAY_CAPABILITIES:"),
        "launch.js must not assign MCP_GATEWAY_CAPABILITIES"
    );
    let capabilities = capabilities_dir_from_launcher(&root, &launch);
    assert!(
        capabilities.starts_with(root.join("plugin")),
        "the catalogue the launcher names must live inside the plugin folder, got {}",
        capabilities.display()
    );
    assert!(
        launch.contains("spawn("),
        "launcher must start the package with child_process.spawn"
    );
    assert!(
        !launch.contains("shell:"),
        "launcher must not opt into a shell"
    );
    assert!(
        !launch.contains("exec(") && !launch.contains("execSync"),
        "launcher must not use child_process exec"
    );
}

#[test]
fn privacy_states_local_facts_and_plugin_has_no_email() {
    let root = repo_root();
    let privacy = read(&root.join("plugin/PRIVACY.md"));
    assert!(privacy.contains("reads the user's local config"));
    assert!(privacy.contains("credentials that config names"));
    assert!(privacy.contains("stores config on the machine"));
    assert!(
        privacy.contains(
            "sends a request only to a backend the user configured when a tool is invoked"
        )
    );
    assert!(privacy.contains("does not add an author telemetry endpoint"));
    assert!(privacy.contains("Mikko Parkkola"));
    assert!(privacy.contains("https://github.com/MikkoParkkola/mcp-gateway/issues"));
    assert!(
        !privacy.contains('@'),
        "PRIVACY.md must not contain an email address"
    );

    // Capability schemas quote sample addresses for the APIs they call.
    // The disclosure the directory reviewer reads is the prose around them.
    for relative in [
        "plugin/README.md",
        "plugin/PRIVACY.md",
        "plugin/LICENSE",
        "plugin/.mcp.json",
        "plugin/.claude-plugin/plugin.json",
        "plugin/bin/launch.js",
    ] {
        let path = root.join(relative);
        assert!(
            !contains_email(&read(&path)),
            "email address in {}",
            path.display()
        );
    }
}

const REMOVED_TOOLS: [&str; 9] = [
    "stripe_charges",
    "stripe_create_payment_intent",
    "audio_tts",
    "video_create",
    "video_agent_create",
    "avatar_list",
    "voice_list",
    "video_get",
    "video_download",
];

const KEPT_TOOLS: [&str; 4] = [
    "stripe_list_charges",
    "audio_transcribe",
    "image_to_text",
    "screenshot_url",
];

/// Kills the launcher process group. `node` spawns `npx`, which spawns the
/// published binary; killing only the node pid leaves the server running.
struct KillGroup(u32);

impl Drop for KillGroup {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{}", self.0)])
            .output();
        let yaml = std::env::temp_dir().join(format!("mcp-gateway-plugin-{}.yaml", self.0));
        let _ = fs::remove_file(yaml);
    }
}

fn tool_names(tools: &Value) -> HashSet<String> {
    tools
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn message_by_id(lines: &[String], id: u64) -> Value {
    for line in lines {
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if value.get("id").and_then(Value::as_u64) == Some(id) {
            return value;
        }
    }
    panic!("JSON-RPC response id {id} was not in the server stdout");
}

fn stderr_tail(err: &str) -> String {
    let tail: String = err.chars().rev().take(800).collect();
    tail.chars().rev().collect()
}

fn assert_cut(label: &str, names: &HashSet<String>) {
    for removed in REMOVED_TOOLS {
        assert!(!names.contains(removed), "{label} still exposes {removed}");
    }
    for kept in KEPT_TOOLS {
        assert!(names.contains(kept), "{label} does not expose {kept}");
    }
}

#[test]
fn published_serve_tools_list_drops_payment_and_generative_media() {
    let root = repo_root();
    let mut command = Command::new("node");
    command
        .arg(root.join("plugin/bin/launch.js"))
        .current_dir(root.join("plugin"))
        // A parent value of this name crashes 3.5.1 serve unless the launcher
        // removes it. The nested form would retarget the catalogue.
        .env("MCP_GATEWAY_CAPABILITIES", "not-a-struct")
        .env(
            "MCP_GATEWAY_CAPABILITIES__DIRECTORIES",
            "/not-a-capability-directory",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("spawn node plugin/bin/launch.js");
    let guard = KillGroup(child.id());
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut lines = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            lines.push(std::mem::take(&mut line));
            if lines.iter().any(|item| item.contains("\"id\":3")) {
                break;
            }
        }
        let _ = tx.send(lines);
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });

    let mut stdin = child.stdin.take().expect("stdin");
    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"directory-plugin-surface","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gateway_list_tools","arguments":{"server":"gateway"}}}"#,
    ];
    for request in requests {
        writeln!(stdin, "{request}").expect("write JSON-RPC");
    }
    let _ = stdin.flush();

    let lines = match rx.recv_timeout(Duration::from_secs(45)) {
        Ok(lines) => lines,
        Err(_) => {
            drop(guard);
            let err = stderr_handle.join().unwrap_or_default();
            panic!(
                "published serve did not answer tools/list\n{}",
                stderr_tail(&err)
            );
        }
    };
    drop(stdin);
    drop(guard);
    let err = stderr_handle.join().unwrap_or_default();
    assert!(
        !err.contains("invalid type"),
        "published serve rejected its config: {}",
        stderr_tail(&err)
    );

    let listed = message_by_id(&lines, 2);
    let listed_names = tool_names(&listed["result"]["tools"]);
    assert_cut("tools/list", &listed_names);
    assert!(
        listed_names.len() > KEPT_TOOLS.len(),
        "tools/list returned only the surfaced names"
    );

    let called = message_by_id(&lines, 3);
    assert_ne!(called["result"]["isError"].as_bool(), Some(true));
    let text = called["result"]["content"][0]["text"]
        .as_str()
        .expect("gateway_list_tools text");
    let catalogue: Value = serde_json::from_str(text).expect("gateway_list_tools JSON");
    let catalogue_names = tool_names(&catalogue["tools"]);
    assert_cut("gateway_list_tools", &catalogue_names);
    assert!(
        catalogue_names.contains("weather"),
        "gateway_list_tools did not return the loaded catalogue"
    );
    let _ = child.wait();
}
