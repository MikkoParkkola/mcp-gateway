// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Linux keychain: the Secret Service, through `gdbus` and `secret-tool`
//! (ADR-028 rule 7).
//!
//! Every read asks `SearchItems` first, by the `service` attribute, which
//! returns the matching items split into unlocked and locked. Nothing is
//! spawned that could unlock: a locked item is refused, and `secret-tool
//! lookup` runs only for an unlocked one. Each child is bounded at 2 s and is
//! killed and reaped on this thread before the call returns.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::keychain::{KeychainError, KeychainRead, WipedBytes};

/// How long one child may take (ADR-028 rule 7).
const BOUND: Duration = Duration::from_secs(2);

/// The Secret Service through its command-line tools.
pub(crate) struct LinuxKeychain {
    gdbus: Option<PathBuf>,
    secret_tool: Option<PathBuf>,
    bound: Duration,
}

impl LinuxKeychain {
    /// The tools found on `PATH`; a missing one makes every read unavailable.
    pub(crate) fn from_path() -> Self {
        Self {
            gdbus: on_path("gdbus"),
            secret_tool: on_path("secret-tool"),
            bound: BOUND,
        }
    }

    /// The tools at these paths, for tests that stand in stubs.
    #[cfg(test)]
    pub(crate) fn with_programs(gdbus: PathBuf, secret_tool: PathBuf, bound: Duration) -> Self {
        Self {
            gdbus: Some(gdbus),
            secret_tool: Some(secret_tool),
            bound,
        }
    }

    /// `(unlocked, locked)` item counts for `name`, from `SearchItems`.
    fn search(&self, name: &str) -> Result<(usize, usize), KeychainError> {
        let gdbus = self.gdbus.as_deref().ok_or_else(|| {
            KeychainError::Unavailable("gdbus is not installed (package libglib2.0-bin)".into())
        })?;
        // The name is ADR-028's grammar, so it needs no quoting beyond the
        // GVariant string's own quotes.
        // `SearchItems` takes `a{ss}`: a plain string value, not a variant.
        let attributes = format!("{{'service': '{name}'}}");
        let output = run(
            gdbus,
            &[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                "/org/freedesktop/secrets",
                "--method",
                "org.freedesktop.Secret.Service.SearchItems",
                &attributes,
            ],
            self.bound,
        )?;
        if !output.success {
            return Err(KeychainError::Unavailable(
                "the Secret Service did not answer on the session bus".into(),
            ));
        }
        parse_search(&String::from_utf8_lossy(output.stdout.as_bytes())).ok_or_else(|| {
            KeychainError::Unavailable("the Secret Service gave an unreadable answer".into())
        })
    }
}

impl KeychainRead for LinuxKeychain {
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError> {
        match self.search(name)? {
            (0, 0) => return Err(KeychainError::Missing),
            (0, _) => return Err(KeychainError::Locked),
            _ => {}
        }
        let secret_tool = self.secret_tool.as_deref().ok_or_else(|| {
            KeychainError::Unavailable(
                "secret-tool is not installed (package libsecret-tools)".into(),
            )
        })?;
        let output = run(secret_tool, &["lookup", "service", name], self.bound)?;
        // An exit status cannot tell "not found" from a bus failure, and the
        // search already said the item exists, so a failure here is the store's.
        if !output.success {
            return Err(KeychainError::Unavailable(
                "secret-tool lookup failed".into(),
            ));
        }
        // Piped output is the stored bytes exactly: secret-tool adds a newline
        // only when stdout is a terminal.
        Ok(output.stdout)
    }
}

/// Counts the object paths in `SearchItems`' `(ao, ao)` reply, as `gdbus`
/// prints it: `([objectpath '/a'], @ao [])`.
fn parse_search(reply: &str) -> Option<(usize, usize)> {
    let inner = reply.trim().strip_prefix('(')?.strip_suffix(')')?;
    let (unlocked, locked) = inner.split_once("], ")?;
    let count = |list: &str| list.matches("objectpath").count();
    Some((count(unlocked), count(locked)))
}

/// What a finished child produced; stdout is wiped on drop.
struct Finished {
    success: bool,
    stdout: WipedBytes,
}

/// Runs `program` with `args` and no stdin, waiting at most `bound`. A child
/// past the bound is killed and reaped before this returns. Stderr is drained
/// and dropped: it can carry nothing an operator needs that the reason lacks.
fn run(program: &Path, args: &[&str], bound: Duration) -> Result<Finished, KeychainError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| KeychainError::Unavailable(format!("{} could not start", display(program))))?;
    let deadline = Instant::now() + bound;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(KeychainError::Timeout);
            }
        }
    };
    // ponytail: stdout is read after exit, so a child that writes more than
    // the pipe buffer (64 KiB) blocks until the bound. Replies here are a few
    // hundred bytes and secrets at most 8 KiB; read on a thread if that changes.
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut stdout);
    }
    Ok(Finished {
        success: status.success(),
        stdout: WipedBytes::new(stdout),
    })
}

fn display(program: &Path) -> String {
    program.file_name().map_or_else(
        || program.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// The first `PATH` entry holding `name`.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
}
