// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one way a test starts the gateway binary (MIK-7637).
//!
//! A spawned gateway is not built with `cfg(test)`, so the in-crate guard that
//! refuses the real task store (`src/gateway/server/task_runtime.rs`) is not
//! in it: only its environment keeps it off the developer's home. Every spawn
//! goes through [`command`], which gives the child an isolated home on every
//! OS, and `scripts/ci/check-gateway-spawns.py` fails a test that names the
//! binary, clears an environment or touches an isolation variable anywhere
//! else.
//!
//! Isolation is set last, after any clearing, so no caller order can undo it:
//! `HOME` and `USERPROFILE`; `MCP_GATEWAY_TEST_HOME_DIR`, the debug build's
//! override that Windows needs because `dirs::home_dir()` there reads the
//! Known Folder API and ignores both (#2368); `APPDATA` and `LOCALAPPDATA`;
//! and the XDG config, data and state directories. Inherited `MCP_GATEWAY_*`
//! variables are removed, so an operator's own overrides never reach a test, and
//! an inherited `RUST_LOG` keeps the port banner visible.
//!
//! Every product home lookup goes through `crate::home_dir`, so the override
//! reaches all of them; `clippy.toml` refuses a direct `dirs` call (MIK-8001).
#![allow(dead_code, reason = "each test crate uses part of this helper")]

use std::path::Path;
use std::process::Command;

/// What the child inherits from the test process besides its isolated home.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inherit {
    /// The test's environment, minus every `MCP_GATEWAY_*` variable.
    Environment,
    /// Nothing but what a process needs to start (`SystemRoot` on Windows)
    /// and a coverage run's profile path.
    Nothing,
}

/// The gateway binary's path, for a config that runs it as a child of a
/// gateway this module started (that child inherits the isolated home).
pub fn path() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-gateway")
}

/// A command for the gateway binary with `home` as its only home.
pub fn command(home: &Path, inherit: Inherit) -> Command {
    isolated(Command::new(path()), home, inherit)
}

/// The binary run through `wrapper` (for example `sh -c '...; exec "$0" "$@"'`),
/// isolated the same way: the wrapper's child inherits it.
pub fn wrapped(wrapper: &[&str], home: &Path, inherit: Inherit) -> Command {
    let (program, args) = wrapper.split_first().expect("a wrapper program");
    let mut command = Command::new(program);
    command.args(args).arg(path());
    isolated(command, home, inherit)
}

fn isolated(mut command: Command, home: &Path, inherit: Inherit) -> Command {
    match inherit {
        Inherit::Environment => {
            for (name, _) in std::env::vars_os() {
                // Case-blind: Windows looks variables up that way.
                if name
                    .to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("MCP_GATEWAY_")
                {
                    command.env_remove(name);
                }
            }
            // The bound port is read from an info-level banner, so an
            // inherited filter keeps its own directives but may not hide it.
            if let Ok(filter) = std::env::var("RUST_LOG") {
                command.env("RUST_LOG", format!("{filter},{BANNER_TARGET}=info"));
            }
        }
        Inherit::Nothing => {
            command.env_clear();
            for name in ["SystemRoot", "LLVM_PROFILE_FILE"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
    }
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("MCP_GATEWAY_TEST_HOME_DIR", home)
        .env("APPDATA", home.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.join("AppData").join("Local"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local").join("share"))
        .env("XDG_STATE_HOME", home.join(".local").join("state"));
    command
}

/// The variables [`command`] fixes; a caller must not set them again.
const ISOLATION: [&str; 5] = [
    "HOME",
    "USERPROFILE",
    "MCP_GATEWAY_TEST_HOME_DIR",
    "APPDATA",
    "LOCALAPPDATA",
];

/// Caller-chosen variables for a gateway command, refusing any isolation
/// variable, which would undo [`command`]'s home. The spawn check requires a
/// variable list passed to `.envs(...)` to come through here.
pub fn checked_env<I, K, V>(vars: I) -> impl Iterator<Item = (K, V)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
{
    vars.into_iter().inspect(|(name, _)| {
        let name: &std::ffi::OsStr = name.as_ref();
        let name = name.to_string_lossy().to_ascii_uppercase();
        assert!(
            !ISOLATION.contains(&name.as_str()),
            "{name} would undo the gateway's isolated home"
        );
    })
}

/// The module that logs the `Listening` banner [`logged_port`] reads.
const BANNER_TARGET: &str = "mcp_gateway::gateway::server::support";

/// `server.port: 0` (or `-p 0`): the child binds an OS-chosen port and logs
/// the one it got, so no port is picked here and dropped before the child
/// binds it (MIK-7634, MIK-7984). Read it back with [`logged_port`].
pub const ANY_PORT: u16 = 0;

/// The port a child started on [`ANY_PORT`] reports in `log`, once its
/// `Listening` line is complete.
pub fn logged_port(log: &Path) -> Option<u16> {
    reported_port(&std::fs::read_to_string(log).ok()?)
}

/// The port in the gateway's `Listening` banner line, with terminal colour
/// codes stripped (their digits are not part of the port). The last `port`
/// on the line is the field; the module path before it can contain the word.
pub fn reported_port(log: &str) -> Option<u16> {
    // Only a line already ended by a newline: the child may be mid-write, and
    // a prefix such as `port=39` would parse as a wrong port.
    let line = log
        .split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .find(|line| line.contains("Listening") && line.contains("port"))?;
    let mut plain = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for skipped in chars.by_ref() {
                if skipped.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    let rest = &plain[plain.rfind("port")? + "port".len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Whether a gateway on `port` answers `GET /livez` with 200.
pub fn answers_livez(port: u16) -> bool {
    use std::io::{Read as _, Write as _};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let request =
        format!("GET /livez HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut answer = String::new();
    stream.write_all(request.as_bytes()).is_ok()
        && stream.read_to_string(&mut answer).is_ok()
        && answer.starts_with("HTTP/1.1 200")
}
