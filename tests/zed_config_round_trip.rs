// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1811: what `setup export --target zed` writes is what Zed reads, and what
//! the gateway's own Zed discovery imports back.
//!
//! Zed's settings format and location, from Zed's source
//! (zed-industries/zed @ 1a28cff4b409169bac058bca40dfbfeb7621d19b):
//! - `crates/settings_content/src/project.rs:517-533, 607-615`: a
//!   `context_servers` entry is flat, `{"command": "<path>", "args": [...]}`
//!   for stdio or `{"url": "..."}` for HTTP;
//! - `crates/paths/src/paths.rs:133-152, 289-292`: `settings.json` lives in
//!   `~/.config/zed` on macOS and in the OS config dir (`$XDG_CONFIG_HOME/zed`,
//!   `%APPDATA%\Zed`) elsewhere.
//!
//! Both runs use the real binary in an isolated home with a cleared
//! environment, so no other discovery source can supply the entry.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use mcp_gateway::config::{Config, TransportConfig};
use serde_json::Value;

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
    xdg: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        // Deliberately not `$HOME/.config`: a Linux build must follow
        // `$XDG_CONFIG_HOME` the way Zed does.
        let xdg = root.join("xdg");
        Self {
            _dir: dir,
            root,
            xdg,
        }
    }

    /// The directory Zed reads `settings.json` from in this home.
    fn zed_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.root.join(".config/zed")
        } else if cfg!(windows) {
            // The debug-build seam follows XDG_CONFIG_HOME on Windows too.
            self.xdg.join("Zed")
        } else {
            self.xdg.join("zed")
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = gateway_bin::command(&self.root, gateway_bin::Inherit::Nothing);
        command
            .env("XDG_CONFIG_HOME", &self.xdg)
            // Process discovery calls `ps` by name; an empty PATH keeps host
            // processes out of the discovered set.
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

fn write(path: &Path, body: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(path, body).expect("write file");
}

fn ok(output: &Output, what: &str) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{what} failed: {}\nstdout: {stdout}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// Export the gateway entry for Zed in `mode`, then return the entry as it
/// sits in the settings file Zed reads.
fn export(home: &Home, mode: &str) -> (PathBuf, Value) {
    std::fs::create_dir_all(home.zed_dir()).expect("zed config dir");
    let gateway = home.root.join("gateway.yaml");
    write(&gateway, "server:\n  host: 127.0.0.1\n  port: 39481\n");
    let gateway_arg = gateway.to_str().unwrap();
    ok(
        &home.run(&[
            "setup",
            "export",
            "--target",
            "zed",
            "--mode",
            mode,
            "--name",
            "gateway",
            "-c",
            gateway_arg,
        ]),
        "setup export",
    );
    let settings = home.zed_dir().join("settings.json");
    let text = std::fs::read_to_string(&settings).unwrap_or_else(|_| {
        panic!(
            "export did not write the file Zed reads, {}",
            settings.display()
        )
    });
    let doc: Value = serde_json::from_str(&text).expect("settings.json is JSON");
    let entry = doc["context_servers"]["gateway"].clone();
    assert!(
        entry.is_object(),
        "no context_servers.gateway entry in {text}"
    );
    (gateway, entry)
}

/// Discover servers in this home: the JSON listing and the backend written
/// by `--write-config` for `gateway`.
fn import(home: &Home) -> (Value, TransportConfig) {
    let listing = ok(
        &home.run(&["cap", "discover", "--format", "json"]),
        "cap discover",
    );
    // In json mode stdout is the listing alone (#1909).
    let listing: Value = serde_json::from_str(&listing)
        .unwrap_or_else(|e| panic!("discover stdout is not one JSON value ({e}): {listing}"));
    let found = listing
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["name"] == "gateway")
        .cloned()
        .unwrap_or_else(|| panic!("discover did not import the exported entry: {listing}"));
    let out = home.root.join("discovered.yaml");
    let out_arg = out.to_str().unwrap();
    ok(
        &home.run(&[
            "cap",
            "discover",
            "--write-config",
            "--config-path",
            out_arg,
        ]),
        "cap discover --write-config",
    );
    let config = Config::load(Some(&out)).expect("discovered config loads");
    let backend = config
        .backends
        .get("gateway")
        .expect("discovered config has the gateway backend");
    (found, backend.transport.clone())
}

#[test]
fn zed_stdio_entry_round_trips() {
    let home = Home::new();
    let (gateway, entry) = export(&home, "stdio");
    assert_eq!(
        entry["command"], "mcp-gateway",
        "Zed reads `command` as a string"
    );
    let args: Vec<&str> = entry["args"]
        .as_array()
        .expect("args array")
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    assert_eq!(args, ["serve", "--stdio", "-c", gateway.to_str().unwrap()]);

    let (found, transport) = import(&home);
    assert_eq!(
        found["source"], "Zed",
        "imported from another source: {found}"
    );
    let expected = format!("mcp-gateway serve --stdio -c {}", gateway.display());
    match transport {
        TransportConfig::Stdio { command, .. } => assert_eq!(command, expected),
        other => panic!("expected a stdio backend, got {other:?}"),
    }
}

#[test]
fn zed_http_entry_round_trips() {
    let home = Home::new();
    let (_, entry) = export(&home, "proxy");
    assert_eq!(entry["url"], "http://127.0.0.1:39481/mcp");

    let (found, transport) = import(&home);
    assert_eq!(
        found["source"], "Zed",
        "imported from another source: {found}"
    );
    match transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "http://127.0.0.1:39481/mcp");
        }
        other => panic!("expected an HTTP backend, got {other:?}"),
    }
}
