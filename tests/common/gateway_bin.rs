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

/// As [`command`], but `HOME` and `USERPROFILE` name a second temporary
/// directory, `env_home`, while the debug override still names `home`. A test
/// that the gateway resolves its home through the override, never through
/// `HOME`, needs the two to differ; neither is the real home (MIK-8001).
pub fn command_with_env_home(home: &Path, env_home: &Path, inherit: Inherit) -> Command {
    let mut command = command(home, inherit);
    command.env("HOME", env_home).env("USERPROFILE", env_home);
    command
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
    // A mutant proof switches one site on through this variable, and the
    // site may sit in the binary: pass it through in both
    // modes. A normal build reads no switch, so there it changes nothing.
    if let Some(value) = std::env::var_os("MCP_GATEWAY_MUTANT") {
        command.env("MCP_GATEWAY_MUTANT", value);
    }
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("MCP_GATEWAY_TEST_HOME_DIR", home)
        // init and the setup wizard store the admin token through the secret
        // store: pin the files store so no spawned gateway writes to a runner's
        // real keychain. A test that wants another setting passes it through
        // `checked_env`, which is applied after this.
        .env("MCP_GATEWAY_SECRETS__STORE", "files")
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

/// A spawned gateway together with every folder it, or a backend it started,
/// writes into. Folders are removed only after the gateway drained on a
/// SIGTERM and exited by itself: then its own shutdown has ended its
/// backends' process trees. After a kill, a signal death, a panic or a stop
/// that never finished, the folders are kept on disk and named on stderr,
/// since a backend may still be writing; the CI temp-folder guard then fails
/// on them instead of on a half-removed folder.
pub struct Reaped {
    child: tokio::process::Child,
    folders: Vec<tempfile::TempDir>,
    /// Set by a reap that saw the gateway exit by itself after its SIGTERM.
    drained: bool,
    /// The first reap's exit status; a later reap returns it unchanged.
    first_exit: Option<std::process::ExitStatus>,
}

/// How long a gateway may drain after SIGTERM: above its own serial
/// shutdown phases, as the helpers this replaces allowed.
const EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(90);
/// How long a killed child may take to be reaped.
const KILL_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

impl Reaped {
    pub fn new(child: tokio::process::Child) -> Self {
        Self {
            child,
            folders: Vec::new(),
            drained: false,
            first_exit: None,
        }
    }

    /// Hands `folder` to the gateway's owner, so it is removed after the
    /// gateway, never before.
    pub fn owning(&mut self, folder: tempfile::TempDir) -> &Path {
        self.folders.push(folder);
        self.folders.last().expect("just pushed").path()
    }

    /// The child, for a row that kills it on purpose or reads its pipes.
    pub fn child_mut(&mut self) -> &mut tokio::process::Child {
        &mut self.child
    }

    /// Ends the gateway the way an operator does and waits for it; the
    /// folders stay. Fails the test if it does not exit within the bound.
    pub async fn reap(&mut self) -> std::process::ExitStatus {
        self.reap_within(EXIT_BOUND).await
    }

    /// [`Self::reap`] with its own bound, for a row that tests the bound.
    pub async fn reap_within(&mut self, bound: std::time::Duration) -> std::process::ExitStatus {
        if let Some(status) = self.first_exit {
            return status;
        }
        let started = std::time::Instant::now();
        let pid = self.child.id();
        // A child that already exited is not drained by this stop: whatever
        // it started was never told to stop. Its zombie still takes a signal,
        // so the check comes first. `id()` is None once the child was reaped:
        // a pid a reap released is never signalled, since the OS may have
        // handed it to another process.
        let running = matches!(self.child.try_wait(), Ok(None));
        let signalled = running && self.terminate();
        let Ok(waited) = tokio::time::timeout(bound, self.child.wait()).await else {
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(KILL_BOUND, self.child.wait()).await;
            self.drained = false;
            panic!(
                "the gateway (pid {pid:?}) did not exit within {bound:?} of its stop; \
                 killed it and kept {}",
                self.kept()
            );
        };
        let status = waited.expect("the gateway's exit status");
        self.drained = signalled && exited_by_itself(status);
        self.first_exit = Some(status);
        let elapsed = started.elapsed();
        if elapsed > std::time::Duration::from_secs(1) {
            eprintln!("gateway_bin: the gateway (pid {pid:?}) took {elapsed:?} to stop ({status})");
        }
        status
    }

    /// Reaps the gateway, then removes its folders if it drained.
    pub async fn stop(mut self) -> std::process::ExitStatus {
        let status = self.reap().await;
        if self.drained {
            self.folders.clear();
        }
        status
    }

    /// Asks the gateway to drain; whether the request was delivered.
    #[cfg(unix)]
    fn terminate(&mut self) -> bool {
        let Some(pid) = self
            .child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
        else {
            return false;
        };
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).is_ok()
    }

    /// Windows has no SIGTERM; ending the gateway ends the Job object that
    /// holds its backends.
    #[cfg(not(unix))]
    fn terminate(&mut self) -> bool {
        self.child.start_kill().is_ok()
    }

    /// Keeps every folder on disk and lists them.
    fn kept(&mut self) -> String {
        let kept: Vec<String> = self
            .folders
            .drain(..)
            .map(|folder| folder.keep().display().to_string())
            .collect();
        kept.join(", ")
    }
}

#[cfg(unix)]
fn exited_by_itself(status: std::process::ExitStatus) -> bool {
    status.code().is_some()
}

#[cfg(not(unix))]
fn exited_by_itself(_status: std::process::ExitStatus) -> bool {
    true
}

impl Drop for Reaped {
    fn drop(&mut self) {
        if self.child.id().is_some() {
            // A coverage build writes its profile only on a clean exit, so it
            // gets the drain first; the kill below is the backstop.
            if std::env::var_os("LLVM_PROFILE_FILE").is_some() && self.terminate() {
                wait_blocking(&mut self.child, std::time::Duration::from_secs(10));
            }
            let _ = self.child.start_kill();
            wait_blocking(&mut self.child, KILL_BOUND);
        }
        if !self.drained && !self.folders.is_empty() {
            eprintln!(
                "gateway_bin: a gateway ended without a drained stop; kept {}",
                self.kept()
            );
        }
    }
}

/// Polls `child` until it is reaped or `bound` passes, without a runtime.
fn wait_blocking(child: &mut tokio::process::Child, bound: std::time::Duration) {
    let deadline = std::time::Instant::now() + bound;
    while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
