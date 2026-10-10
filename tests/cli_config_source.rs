// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which config file `add`, `list`, `get` and `remove` read and write
//! (MIK-8044 SURF.3).
//!
//! The four commands follow the global `--config` / `MCP_GATEWAY_CONFIG`: a
//! flag wins over the variable, the variable over `./gateway.yaml`, and the
//! flag works before or after the subcommand. Each source file holds one
//! backend named after it, so a command's output or its write shows which file
//! it used.

#![cfg(all(unix, feature = "webui"))]

use std::path::Path;
use std::process::{Command, Output, Stdio};

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

/// Where the command is told to find its config.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// Nothing named: `./gateway.yaml`.
    Default,
    /// `MCP_GATEWAY_CONFIG` only.
    Env,
    /// `-c <file>` before the subcommand.
    FlagBefore,
    /// `--config <file>` after the subcommand.
    FlagAfter,
    /// `--config <file>` with `MCP_GATEWAY_CONFIG` naming a different file.
    FlagOverEnv,
}

impl Source {
    /// The file the command must use.
    fn expected(self) -> &'static str {
        match self {
            Self::Default => "gateway.yaml",
            Self::Env => "env.yaml",
            Self::FlagBefore | Self::FlagAfter | Self::FlagOverEnv => "flag.yaml",
        }
    }
}

const SOURCES: [Source; 5] = [
    Source::Default,
    Source::Env,
    Source::FlagBefore,
    Source::FlagAfter,
    Source::FlagOverEnv,
];

/// The backend each file holds, named after the file so output says which one was read.
fn marker(file: &str) -> &'static str {
    match file {
        "gateway.yaml" => "fromdefault",
        "env.yaml" => "fromenv",
        "flag.yaml" => "fromflag",
        other => panic!("no marker for {other}"),
    }
}

fn write_config(path: &Path, backend: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(
        path,
        format!("backends:\n  {backend}:\n    command: \"echo {backend}\"\n"),
    )
    .expect("write config");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

/// A home with all three files, each holding its own marker backend.
fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("home");
    for file in ["gateway.yaml", "env.yaml", "flag.yaml"] {
        write_config(&home.path().join(file), marker(file));
    }
    home
}

fn run(home: &Path, source: Source, subcommand: &[&str]) -> Output {
    let mut command: Command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    command
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", home.join("no-system-programs"))
        .current_dir(home)
        .stdin(Stdio::null());
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let flag = home.join("flag.yaml");
    let flag = flag.to_str().expect("utf-8 path");
    let env = home.join("env.yaml");
    match source {
        Source::Default => {
            command.args(subcommand);
        }
        Source::Env => {
            command.env("MCP_GATEWAY_CONFIG", &env).args(subcommand);
        }
        Source::FlagBefore => {
            command.args(["-c", flag]).args(subcommand);
        }
        Source::FlagAfter => {
            command.args(subcommand).args(["--config", flag]);
        }
        Source::FlagOverEnv => {
            command
                .env("MCP_GATEWAY_CONFIG", &env)
                .args(subcommand)
                .args(["--config", flag]);
        }
    }
    command.output().expect("run mcp-gateway")
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout {}\nstderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn list_reads_the_file_its_source_names() {
    for source in SOURCES {
        let home = home();
        let out = run(home.path(), source, &["list", "--json"]);
        assert!(out.status.success(), "{source:?}: {}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        for file in ["gateway.yaml", "env.yaml", "flag.yaml"] {
            let listed = stdout.contains(marker(file));
            assert_eq!(
                listed,
                file == source.expected(),
                "{source:?}: `list` must read {} (listed {file}'s backend: {listed}): {}",
                source.expected(),
                text(&out)
            );
        }
    }
}

#[test]
fn get_finds_only_the_backend_of_the_file_its_source_names() {
    for source in SOURCES {
        let home = home();
        let out = run(home.path(), source, &["get", marker(source.expected())]);
        assert!(
            out.status.success(),
            "{source:?}: `get` must read {}: {}",
            source.expected(),
            text(&out)
        );
        for file in ["gateway.yaml", "env.yaml", "flag.yaml"] {
            if file != source.expected() {
                let other = run(home.path(), source, &["get", marker(file)]);
                let stderr = String::from_utf8_lossy(&other.stderr);
                assert!(
                    !other.status.success()
                        && stderr.contains(&format!("Backend '{}' not found", marker(file))),
                    "{source:?}: `get` must answer {file}'s backend as not found, \
                     so it did not read {file}: {}",
                    text(&other)
                );
            }
        }
    }
}

#[test]
fn add_writes_the_file_its_source_names() {
    for source in SOURCES {
        let home = home();
        let out = run(
            home.path(),
            source,
            &["add", "--command", "echo added", "addedbackend"],
        );
        assert!(out.status.success(), "{source:?}: {}", text(&out));
        for file in ["gateway.yaml", "env.yaml", "flag.yaml"] {
            let body = std::fs::read_to_string(home.path().join(file)).expect("read config");
            assert_eq!(
                body.contains("addedbackend"),
                file == source.expected(),
                "{source:?}: `add` must write {}, not {file}: {}",
                source.expected(),
                text(&out)
            );
        }
    }
}

#[test]
fn remove_edits_the_file_its_source_names() {
    for source in SOURCES {
        let home = home();
        let target = marker(source.expected());
        let out = run(home.path(), source, &["remove", target]);
        assert!(out.status.success(), "{source:?}: {}", text(&out));
        let body = std::fs::read_to_string(home.path().join(source.expected())).expect("read");
        assert!(
            !body.contains(target),
            "{source:?}: `remove` must edit {}: {}",
            source.expected(),
            text(&out)
        );
        for file in ["gateway.yaml", "env.yaml", "flag.yaml"] {
            if file != source.expected() {
                let other = std::fs::read_to_string(home.path().join(file)).expect("read");
                assert!(
                    other.contains(marker(file)),
                    "{source:?}: {file} changed: {}",
                    text(&out)
                );
            }
        }
    }
}
