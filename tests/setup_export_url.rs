// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `setup export` writes a URL a client can use, and says on stderr what that
//! URL cannot tell the client. Every row runs the real binary in a private home.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/required.rs"]
mod required;

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

const PORT: u16 = 39481;
/// Distinct pieces of each note's line, as the product prints them.
const WILDCARD: &str = "listens on every address";
const TLS: &str = "the gateway serves TLS";
const CLIENT_CERT: &str = "asks every client for a certificate";

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        Self { _dir: dir, root }
    }

    /// Where the zed target writes, under the helper's `XDG_CONFIG_HOME`.
    fn zed_settings(&self) -> PathBuf {
        let leaf = if cfg!(windows) { "Zed" } else { "zed" };
        self.root.join(".config").join(leaf).join("settings.json")
    }

    fn config(&self, body: &str) {
        mcp_gateway::gateway::test_helpers::write_owner_only(self.root.join("gateway.yaml"), body)
            .expect("write gateway.yaml");
    }

    /// An empty directory, or one holding an empty `mcp-gateway` file, as PATH.
    fn path_dir(&self, with_gateway: bool) -> PathBuf {
        let dir = self.root.join(if with_gateway {
            "path-with-gateway"
        } else {
            "path-empty"
        });
        std::fs::create_dir_all(&dir).expect("path dir");
        if with_gateway {
            std::fs::write(dir.join("mcp-gateway"), b"").expect("stand-in binary");
        }
        dir
    }

    fn command(&self, path: &Path, args: &[&str]) -> std::process::Command {
        let mut command = gateway_bin::command(&self.root, gateway_bin::Inherit::Nothing);
        command
            .env("PATH", path)
            .env("LC_ALL", "C")
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        let path = self.path_dir(false);
        self.command(&path, args).output().expect("run mcp-gateway")
    }

    /// A CA and a server certificate in `tls/`, and the `mtls` block naming
    /// them, with `require_client_cert` left out (so it is true).
    fn mtls_block(&self) -> String {
        let tls = self.root.join("tls");
        let out = tls.to_str().expect("utf-8 path");
        let init = self.run(&["tls", "init-ca", "--cn", "Test CA", "--out", out]);
        assert!(init.status.success(), "init-ca: {}", text(&init.stderr));
        let ca_crt = tls.join("ca.crt");
        let ca_key = tls.join("ca.key");
        let issue = self.run(&[
            "tls",
            "issue-server",
            "--ca-cert",
            ca_crt.to_str().unwrap(),
            "--ca-key",
            ca_key.to_str().unwrap(),
            "--cn",
            "localhost",
            "--san-dns",
            "localhost",
            "--out",
            out,
        ]);
        assert!(
            issue.status.success(),
            "issue-server: {}",
            text(&issue.stderr)
        );
        format!(
            "mtls:\n  enabled: true\n  server_cert: {out}/server.crt\n  server_key: {out}/server.key\n  ca_cert: {out}/ca.crt\n"
        )
    }

    fn zed_url(&self) -> String {
        let body = std::fs::read_to_string(self.zed_settings()).expect("zed settings");
        let json: Value = serde_json::from_str(&body).expect("zed settings JSON");
        json["context_servers"]["gateway"]["url"]
            .as_str()
            .expect("the gateway entry's url")
            .to_string()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

/// `setup export --mode proxy --target generic`: the JSON's url, and stderr.
fn generic(home: &Home) -> (String, String) {
    let out = home.run(&["setup", "export", "--mode", "proxy", "--target", "generic"]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "export failed: {stderr}");
    let stdout = text(&out.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("stdout is one JSON document");
    assert!(!stdout.contains("Note:"), "a note reached stdout: {stdout}");
    let url = json["mcpServers"]["gateway"]["url"]
        .as_str()
        .expect("url")
        .to_string();
    (url, stderr)
}

#[test]
fn u3_an_ipv4_wildcard_bind_exports_loopback_with_one_note() {
    let home = Home::new();
    home.config(&format!("server:\n  host: 0.0.0.0\n  port: {PORT}\n"));
    let (url, stderr) = generic(&home);
    assert_eq!(url, format!("http://127.0.0.1:{PORT}/mcp"));
    assert_eq!(count(&stderr, WILDCARD), 1, "{stderr}");
}

#[test]
fn u3_an_ipv6_wildcard_bind_exports_bracketed_loopback() {
    let home = Home::new();
    home.config(&format!("server:\n  host: \"::\"\n  port: {PORT}\n"));
    let (url, stderr) = generic(&home);
    assert_eq!(url, format!("http://[::1]:{PORT}/mcp"));
    assert_eq!(count(&stderr, WILDCARD), 1, "{stderr}");
}

#[test]
fn u3_a_tls_listener_exports_https_and_its_two_notes() {
    let home = Home::new();
    let mtls = home.mtls_block();
    home.config(&format!(
        "server:\n  host: 127.0.0.1\n  port: {PORT}\n{mtls}"
    ));
    let (url, stderr) = generic(&home);
    assert_eq!(url, format!("https://127.0.0.1:{PORT}/mcp"));
    assert_eq!(count(&stderr, TLS), 1, "{stderr}");
    assert_eq!(count(&stderr, CLIENT_CERT), 1, "{stderr}");
}

fn last_line(output: &Output) -> String {
    text(&output.stdout)
        .lines()
        .last()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn u3b_the_closing_line_names_what_was_written() {
    let home = Home::new();
    std::fs::create_dir_all(home.zed_settings().parent().unwrap()).expect("zed dir");
    home.config("server:\n  host: 0.0.0.0\n  port: 8080\n");
    let proxy = home.run(&["setup", "export", "--mode", "proxy", "--target", "zed"]);
    assert!(proxy.status.success(), "{}", text(&proxy.stderr));
    assert_eq!(
        last_line(&proxy),
        "Gateway endpoint: http://127.0.0.1:8080/mcp"
    );
    let stdio = home.run(&["setup", "export", "--mode", "stdio", "--target", "zed"]);
    assert!(stdio.status.success(), "{}", text(&stdio.stderr));
    assert_eq!(last_line(&stdio), "Gateway endpoint: none (stdio entry)");
    assert!(
        !text(&stdio.stderr).contains("Note:"),
        "{}",
        text(&stdio.stderr)
    );
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn u4_an_unusable_public_url_stops_before_any_file_is_touched() {
    let home = Home::new();
    let settings = home.zed_settings();
    std::fs::create_dir_all(settings.parent().unwrap()).expect("zed dir");
    std::fs::write(&settings, b"{\"theme\": \"One Dark\"}\n").expect("zed settings");
    let before = listing(settings.parent().unwrap());
    home.config("server:\n  public_url: not a url\n");
    let out = home.run(&["setup", "export", "--mode", "proxy", "--target", "all"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("server.public_url is not a URL a client can use"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");
    assert_eq!(
        std::fs::read(&settings).unwrap(),
        b"{\"theme\": \"One Dark\"}\n"
    );
    assert_eq!(listing(settings.parent().unwrap()), before);
}

/// Auto mode with an empty `mcp-gateway` file on PATH: a reachable gateway
/// gives a proxy entry, none gives stdio.
fn auto_entry(home: &Home) -> Value {
    let path = home.path_dir(true);
    let out = home
        .command(&path, &["setup", "export", "--target", "generic"])
        .output()
        .expect("run mcp-gateway");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let json: Value = serde_json::from_str(&text(&out.stdout)).expect("JSON");
    json["mcpServers"]["gateway"].clone()
}

#[test]
fn u6b_no_gateway_here_gives_a_stdio_entry() {
    let home = Home::new();
    // Port 0 cannot be connected to, so the probe finds nothing.
    home.config("server:\n  host: 127.0.0.1\n  port: 0\n");
    assert!(auto_entry(&home).get("command").is_some());
}

#[test]
fn u6b_a_gateway_listening_here_gives_a_proxy_entry() {
    let home = Home::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    home.config(&format!("server:\n  host: 127.0.0.1\n  port: {port}\n"));
    assert!(auto_entry(&home).get("url").is_some());
    drop(listener);
}

#[test]
fn u6b_an_ipv6_loopback_gateway_is_probed_in_a_form_that_parses() {
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        required::skip_or_fail("u6b: this host has no IPv6 loopback to listen on");
        return;
    };
    let home = Home::new();
    let port = listener.local_addr().unwrap().port();
    home.config(&format!("server:\n  host: \"::1\"\n  port: {port}\n"));
    assert!(auto_entry(&home).get("url").is_some());
    drop(listener);
}

/// The watch child, killed and reaped however the row ends. Declared after
/// the home, so it is dropped (and the child gone) before the home's folder.
struct Watched {
    child: Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
}

impl Drop for Watched {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Watched {
    fn collect(pipe: impl std::io::Read + Send + 'static) -> Arc<Mutex<String>> {
        let buffer = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&buffer);
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut held = sink.lock().unwrap();
                held.push_str(&line);
                held.push('\n');
            }
        });
        buffer
    }

    /// Wait at most 30 s for `needle` on stdout (`on_stdout`) or stderr.
    fn wait_for(&self, on_stdout: bool, needle: &str) {
        let started = Instant::now();
        loop {
            let seen = if on_stdout { &self.out } else { &self.err };
            if seen.lock().unwrap().contains(needle) {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "no {needle:?} within 30 s\nstdout: {}\nstderr: {}",
                self.out.lock().unwrap(),
                self.err.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn u7_the_watch_loop_keeps_the_url_right_across_edits() {
    let home = Home::new();
    std::fs::create_dir_all(home.zed_settings().parent().unwrap()).expect("zed dir");
    let mtls = home.mtls_block();
    let config = home.root.join("gateway.yaml");
    home.config(&format!("server:\n  host: 127.0.0.1\n  port: {PORT}\n"));
    let path = home.path_dir(false);
    let mut child = home
        .command(
            &path,
            &[
                "setup", "export", "--watch", "--mode", "proxy", "--target", "zed",
            ],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn() // spawn-check: waits for exit: Watched kills and reaps it on drop
        .expect("start the watch");
    let out = Watched::collect(child.stdout.take().expect("stdout"));
    let err = Watched::collect(child.stderr.take().expect("stderr"));
    let watched = Watched { child, out, err };
    // Edits rewrite the file in place: the watch follows the file, and a
    // rename would leave it watching the old one.
    let rewrite = |body: String| std::fs::write(&config, body).expect("rewrite gateway.yaml");

    watched.wait_for(true, "Watching");
    rewrite(format!(
        "server:\n  host: 127.0.0.1\n  port: {PORT}\n{mtls}"
    ));
    watched.wait_for(false, CLIENT_CERT);
    assert!(home.zed_url().starts_with("https://"), "{}", home.zed_url());
    let after_tls = std::fs::read(home.zed_settings()).expect("zed settings");
    let zed_dir = home.zed_settings().parent().unwrap().to_path_buf();
    let names_after_tls = listing(&zed_dir);
    let modified = || {
        std::fs::metadata(home.zed_settings())
            .and_then(|meta| meta.modified())
            .expect("zed settings mtime")
    };
    let modified_after_tls = modified();

    rewrite(format!(
        "server:\n  host: 127.0.0.1\n  port: {PORT}\n  public_url: not a url\n"
    ));
    watched.wait_for(false, "Cannot regenerate");
    // Nothing is touched: same bytes, no rewrite of them, no backup beside them.
    assert_eq!(
        std::fs::read(home.zed_settings()).expect("zed settings"),
        after_tls
    );
    assert_eq!(
        modified(),
        modified_after_tls,
        "the settings were rewritten"
    );
    assert_eq!(listing(&zed_dir), names_after_tls, "a file appeared");

    rewrite(format!("server:\n  host: 0.0.0.0\n  port: {PORT}\n"));
    watched.wait_for(false, WILDCARD);
    assert_eq!(home.zed_url(), format!("http://127.0.0.1:{PORT}/mcp"));
    drop(watched);
}
