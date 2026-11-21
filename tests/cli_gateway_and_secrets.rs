// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where the remote commands send their request, and what `cap import
//! --auth-key` accepts. The destination resolves in a fixed order: the
//! `--gateway` flag, then `MCP_GATEWAY_URL`, then the default (the `--config`
//! file's server address). Each order row runs the real binary against
//! listeners that count connections, so a request reaching the wrong place is
//! seen, not inferred.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;

/// A loopback listener that only counts the connections it accepts; each is
/// dropped at once, so the client fails fast after reaching it.
struct Counting {
    url: String,
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Counting {
    fn start() -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = socket.local_addr().expect("local address");
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counter, stopping) = (Arc::clone(&hits), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while let Ok((conn, _)) = socket.accept() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                drop(conn);
            }
        });
        Self {
            url: format!("http://{addr}"),
            addr,
            hits,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Stops the listener and returns how many connections it took.
    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        let _wake = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.hits.load(Ordering::SeqCst)
    }
}

/// A gateway config whose server address is `port` on loopback.
fn config_pointing_at(dir: &Path, port: u16) -> PathBuf {
    let path = dir.join("gateway.yaml");
    let yaml = format!("server:\n  host: 127.0.0.1\n  port: {port}\n");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write the config");
    path
}

/// Runs one command through the shared runner, with a placeholder token and,
/// when given, `MCP_GATEWAY_URL`.
fn invoke(args: &[&str], gateway_env: Option<&str>, stdin: &str) -> Output {
    let mut env = vec![("MCP_GATEWAY_TOKEN", "placeholder")];
    env.extend(gateway_env.map(|url| ("MCP_GATEWAY_URL", url)));
    let input = (!stdin.is_empty()).then_some(stdin.as_bytes());
    gateway_bin::run_cli(args, &env, input)
}

/// All five commands that reach a gateway, each with what it reads from
/// stdin (only the email lookup reads anything).
const ALL: &[(&[&str], &str)] = &[
    (&["stats"], ""),
    (&["dashboard-link"], ""),
    (&["api", "GET", "/ui/api/status"], ""),
    (&["events", "dead-letters", "list"], ""),
    (
        &["audit", "lookup-email", "--email-stdin"],
        "someone@example.test\n",
    ),
];

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn the_flag_beats_the_environment() {
    for (command, stdin) in ALL {
        let (flag, env) = (Counting::start(), Counting::start());
        let mut args = command.to_vec();
        args.extend(["--gateway", flag.url.as_str()]);
        let out = invoke(&args, Some(env.url.as_str()), stdin);
        let (flag_hits, env_hits) = (flag.finish(), env.finish());
        assert!(
            flag_hits >= 1,
            "{command:?}: the flag's listener saw nothing: {}",
            stderr(&out)
        );
        assert_eq!(
            env_hits, 0,
            "{command:?}: MCP_GATEWAY_URL won over the flag"
        );
    }
}

#[test]
fn the_environment_beats_the_default() {
    for (command, stdin) in ALL {
        let (env, default) = (Counting::start(), Counting::start());
        let dir = tempfile::tempdir().expect("config dir");
        let config = config_pointing_at(dir.path(), default.port());
        let mut args = command.to_vec();
        args.extend(["--config", config.to_str().expect("utf-8 path")]);
        let out = invoke(&args, Some(env.url.as_str()), stdin);
        let (env_hits, default_hits) = (env.finish(), default.finish());
        assert!(
            env_hits >= 1,
            "{command:?}: the variable's listener saw nothing: {}",
            stderr(&out)
        );
        assert_eq!(
            default_hits, 0,
            "{command:?}: the config's address won over the variable"
        );
    }
}

/// Green at the tip on purpose: it guards the default against the rename,
/// and it proves the config fixture is read (else the rows above would be
/// failing for a broken fixture, not for the rule).
#[test]
fn without_flag_or_variable_the_config_address_is_used() {
    for (command, stdin) in ALL {
        let default = Counting::start();
        let dir = tempfile::tempdir().expect("config dir");
        let config = config_pointing_at(dir.path(), default.port());
        let mut args = command.to_vec();
        args.extend(["--config", config.to_str().expect("utf-8 path")]);
        let out = invoke(&args, None, stdin);
        assert!(
            default.finish() >= 1,
            "{command:?}: the config's address saw nothing: {}",
            stderr(&out)
        );
    }
}

/// One operation, enough for the importer to write a capability.
const SPEC: &str = "openapi: 3.0.0\ninfo:\n  title: probe\n  version: \"1\"\npaths:\n  /ping:\n    get:\n      operationId: ping\n      responses:\n        \"200\":\n          description: ok\n";

/// Imports `SPEC` with `auth_key`; returns the run and the text of every file
/// it wrote.
fn import_with_auth_key(auth_key: &str) -> (Output, Vec<String>) {
    let work = tempfile::tempdir().expect("work dir");
    let spec = work.path().join("spec.yaml");
    std::fs::write(&spec, SPEC).expect("write spec");
    let caps = work.path().join("caps");
    let spec_arg = spec.to_str().expect("utf-8 path");
    let caps_arg = caps.to_str().expect("utf-8 path");
    let out = invoke(
        &[
            "cap",
            "import",
            spec_arg,
            "--output",
            caps_arg,
            "--auth-key",
            auth_key,
        ],
        None,
        "",
    );
    let mut written = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&caps) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                written.push(text);
            }
        }
    }
    (out, written)
}

#[test]
fn auth_key_takes_each_reference_form() {
    // The six forms the credential resolver reads, the last two included.
    for reference in [
        "env:API_TOKEN",
        "keychain:probe",
        "oauth:github",
        "file:/run/probe.key",
        "{env.API_TOKEN}",
        "API_TOKEN",
    ] {
        let (out, written) = import_with_auth_key(reference);
        assert_eq!(out.status.code(), Some(0), "{reference}: {}", stderr(&out));
        assert!(
            written.iter().any(|text| text.contains(reference)),
            "{reference} is not in what was written: {written:?}"
        );
    }
}

#[test]
fn auth_key_refuses_a_value_that_is_not_a_reference() {
    // A plain value, an unrecognised scheme, a recognised scheme that is not
    // at the start, and nothing at all.
    for value in [
        "plain-text-not-a-reference",
        "vault:probe",
        "x-env:NAME",
        "",
    ] {
        let (out, written) = import_with_auth_key(value);
        assert_eq!(out.status.code(), Some(2), "{value:?} was accepted");
        let said = stderr(&out);
        assert!(
            said.contains(AUTH_KEY_REFUSAL),
            "not the one refusal sentence: {said}"
        );
        // The value, and the 20-character prefix a format error would quote.
        let prefix: String = value.chars().take(20).collect();
        for (stream, text) in [("stderr", &said), ("stdout", &stdout(&out))] {
            for shown in [value, prefix.as_str()] {
                assert!(
                    shown.is_empty() || !text.contains(shown),
                    "the refusal repeats {shown:?} on {stream}: {text}"
                );
            }
        }
        assert!(
            written.is_empty(),
            "{value:?}: files were written: {written:?}"
        );
    }
}

/// What --auth-key says when given anything but a reference: every form the
/// resolver reads, and never the value.
const AUTH_KEY_REFUSAL: &str = "--auth-key takes a credential reference: env:NAME, keychain:NAME, \
oauth:PROVIDER, file:PATH, {env.NAME} or a variable NAME";

/// When no destination is given and the config cannot be read, the remedy
/// names the one destination flag, not the old spelling.
#[test]
fn the_config_refusal_names_the_destination_flag() {
    let dir = tempfile::tempdir().expect("config dir");
    let broken = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [not, valid\n")
        .expect("write the config");
    let broken = broken.to_str().expect("utf-8 path");
    let out = invoke(&["dashboard-link", "--config", broken], None, "");
    let said = stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{said}");
    assert!(
        said.contains("--gateway"),
        "the remedy does not name --gateway: {said}"
    );
    assert!(
        !said.contains("--url"),
        "the remedy still names --url: {said}"
    );
}
