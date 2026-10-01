// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Directory-listing surface for the Claude plugin bundle.
//!
//! The catalogue assertions call [`ToolCatalogue::load`] on the capabilities
//! directory `plugin/bin/launch.js` points at. They do not keep a second list
//! of tool names as the source of truth.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use mcp_gateway::cli::invoke::ToolCatalogue;
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
fn launch_js_pins_package_and_names_capabilities_env() {
    let launch = read(&repo_root().join("plugin/bin/launch.js"));
    assert!(launch.contains("@mikkoparkkola/mcp-gateway@3.5.1"));
    assert!(launch.contains("MCP_GATEWAY_CAPABILITIES"));
    assert!(launch.contains("serve --stdio"));
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

    for entry in WalkDir::new(root.join("plugin"))
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        assert!(
            !contains_email(&text),
            "email address in {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn catalogue_loader_drops_payment_and_generative_media() {
    let root = repo_root();
    let launch = read(&root.join("plugin/bin/launch.js"));
    let capabilities = capabilities_dir_from_launcher(&root, &launch);
    let catalogue = ToolCatalogue::load(capabilities.to_str().expect("capabilities path is utf-8"))
        .await
        .unwrap_or_else(|err| panic!("ToolCatalogue::load failed: {err}"));
    let names: HashSet<&str> = catalogue
        .all()
        .iter()
        .map(|cap| cap.name.as_str())
        .collect();

    for removed in [
        "stripe_charges",
        "stripe_create_payment_intent",
        "audio_tts",
        "video_create",
        "video_agent_create",
        "avatar_list",
        "voice_list",
        "video_get",
        "video_download",
    ] {
        assert!(
            !names.contains(removed),
            "{removed} is still loaded from {}",
            capabilities.display()
        );
    }
    for kept in [
        "stripe_list_charges",
        "audio_transcribe",
        "image_to_text",
        "screenshot_url",
    ] {
        assert!(
            names.contains(kept),
            "{kept} was not loaded from {}",
            capabilities.display()
        );
    }
}
