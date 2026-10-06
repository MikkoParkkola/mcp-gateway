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
//! variables are removed, so an operator's own overrides never reach a test.
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
                if name.to_string_lossy().starts_with("MCP_GATEWAY_") {
                    command.env_remove(name);
                }
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
