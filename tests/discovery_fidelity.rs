// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1876: discovery keeps a client's env, headers and argument boundaries,
//! reads Zed's commented settings, and shows secret values only in the
//! owner-only config it writes.
//!
//! Every run uses the real binary in an isolated home with a cleared
//! environment. The sentinel stands for a credential.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use mcp_gateway::config::{Config, TransportConfig};

const SENTINEL: &str = "SENTINEL-1876-secret-value";

/// A Zed settings file with comments and trailing commas, one stdio server
/// with an env value and an argument containing a space, one HTTP server
/// with a header value. Both values are the sentinel.
fn zed_settings() -> String {
    format!(
        r#"// Zed settings
{{
  "theme": "One Dark", // a comment
  /* a block comment */
  "context_servers": {{
    "local": {{
      "command": "npx",
      "args": ["-y", "some-server", "--root", "/Users/a b/notes",],
      "env": {{ "DEMO_VAR": "{SENTINEL}", }},
    }},
    "remote": {{
      "url": "https://mcp.example.test/mcp",
      "headers": {{ "X-Demo": "{SENTINEL}" }},
    }},
  }},
}}
"#
    )
}

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
    xdg: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        let xdg = root.join("xdg");
        Self {
            _dir: dir,
            root,
            xdg,
        }
    }

    fn zed_settings_path(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.root.join(".config/zed/settings.json")
        } else if cfg!(windows) {
            // The debug-build seam follows XDG_CONFIG_HOME on Windows too.
            self.xdg.join("Zed/settings.json")
        } else {
            self.xdg.join("zed/settings.json")
        }
    }

    fn write_zed_settings(&self, body: &str) -> PathBuf {
        let path = self.zed_settings_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, body).unwrap();
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = gateway_bin::command(&self.root, gateway_bin::Inherit::Nothing);
        command
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("PATH", self.root.join("no-system-programs"))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .args(args);
        // A cleared environment loses the Windows system root the process needs to start.
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        command.output().expect("run mcp-gateway")
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_config(home: &Home) -> PathBuf {
    let out = home.root.join("discovered.yaml");
    let output = home.run(&[
        "cap",
        "discover",
        "--write-config",
        "--config-path",
        out.to_str().unwrap(),
    ]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(
        !shown.contains(SENTINEL),
        "--write-config output leaked: {shown}"
    );
    out
}

fn backend(config: &Path, name: &str) -> mcp_gateway::config::BackendConfig {
    let loaded = Config::load_literal(Some(config)).expect("discovered config loads");
    loaded
        .backends
        .get(name)
        .unwrap_or_else(|| panic!("no backend {name}"))
        .clone()
}

#[test]
fn commented_zed_settings_are_discovered_with_env_headers_and_args() {
    let home = Home::new();
    home.write_zed_settings(&zed_settings());
    let out = write_config(&home);

    let local = backend(&out, "local");
    assert_eq!(
        local.env.get("DEMO_VAR").map(String::as_str),
        Some(SENTINEL)
    );
    let TransportConfig::Stdio { command, .. } = &local.transport else {
        panic!("local is not stdio");
    };
    assert_eq!(
        mcp_gateway::transport::split_command(command),
        Some(
            ["npx", "-y", "some-server", "--root", "/Users/a b/notes"]
                .map(String::from)
                .to_vec()
        )
    );
    let remote = backend(&out, "remote");
    assert_eq!(
        remote.headers.get("X-Demo").map(String::as_str),
        Some(SENTINEL)
    );
    // Unix-only: asserts POSIX mode bits; Windows owner-only comes from DACLs (win_acl).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the config holding the values is owner-only");
    }
}

#[test]
fn discovery_output_never_shows_a_secret_value() {
    let home = Home::new();
    home.write_zed_settings(&zed_settings());
    for format in ["json", "yaml", "table"] {
        let output = home.run(&["cap", "discover", "--format", format]);
        let shown = text(&output);
        assert!(output.status.success(), "{shown}");
        assert!(
            shown.contains("local"),
            "discovery lost the server: {shown}"
        );
        assert!(
            !shown.contains(SENTINEL),
            "--format {format} leaked: {shown}"
        );
    }
    let output = home.run(&["cap", "discover", "--shadow", "--format", "json"]);
    let shown = text(&output);
    assert!(!shown.contains(SENTINEL), "--shadow leaked: {shown}");
}

#[test]
fn an_unset_variable_in_an_imported_value_is_refused_at_load() {
    let home = Home::new();
    home.write_zed_settings(
        r#"{ "context_servers": { "local": { "command": "srv", "env": { "DEMO_VAR": "${DISCOVERY_1876_UNSET}" } } } }"#,
    );
    let out = write_config(&home);
    let error = Config::load(Some(&out)).expect_err("an unset reference must refuse the load");
    assert!(
        error.to_string().contains("backends.local.env.DEMO_VAR"),
        "the refusal names the field: {error}"
    );

    // With the variable set (through the config's own env file), it expands.
    let env_file = home.root.join("gateway.env");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &env_file,
        "DISCOVERY_1876_UNSET=expanded-value\n",
    )
    .unwrap();
    let written = std::fs::read_to_string(&out).unwrap();
    let env_line = format!("env_files: ['{}']", env_file.display());
    let with_env = if written.contains("env_files: []") {
        written.replacen("env_files: []", &env_line, 1)
    } else {
        format!("{env_line}\n{written}")
    };
    mcp_gateway::gateway::test_helpers::write_owner_only(&out, with_env).unwrap();
    let loaded = Config::load(Some(&out)).expect("a set reference loads");
    assert_eq!(
        loaded.backends["local"]
            .env
            .get("DEMO_VAR")
            .map(String::as_str),
        Some("expanded-value")
    );
}

#[test]
fn export_into_a_commented_zed_file_refuses_and_leaves_it_untouched() {
    let home = Home::new();
    let body = zed_settings();
    let settings = home.write_zed_settings(&body);
    let gateway = home.root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &gateway,
        "server:\n  host: 127.0.0.1\n  port: 39482\n",
    )
    .unwrap();
    let output = home.run(&[
        "setup",
        "export",
        "--target",
        "zed",
        "--mode",
        "stdio",
        "-c",
        gateway.to_str().unwrap(),
    ]);
    let shown = text(&output);
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        body,
        "the commented file must not be rewritten"
    );
    assert!(
        shown.contains("comments"),
        "the refusal explains why: {shown}"
    );
    assert!(
        shown.contains("\"context_servers\"") && shown.contains("\"mcp-gateway\""),
        "the refusal prints the entry to paste: {shown}"
    );
}
