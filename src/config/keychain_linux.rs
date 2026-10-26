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
//!
//! The writer is the same client. Before each spawn, `gdbus` confirms the
//! default collection exists and is unlocked, and `SearchItems` that the
//! name is free. Then `secret-tool store` takes the value on stdin, never in
//! argv.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::keychain::{KeychainError, KeychainRead, WipedBytes};
use crate::secret_store::{SecretStore, StoreError, StoreKind};

/// How long one child may take (ADR-028 rule 7).
const BOUND: Duration = Duration::from_secs(2);

/// The largest value the Secret Service store takes (ADR-028 rule 2).
const LIMIT: usize = 8_192;

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
        let gdbus = self.gdbus()?;
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
            None,
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
    fn gdbus(&self) -> Result<&Path, KeychainError> {
        self.gdbus.as_deref().ok_or_else(|| {
            KeychainError::Unavailable("gdbus is not installed (package libglib2.0-bin)".into())
        })
    }

    fn secret_tool(&self) -> Result<&Path, KeychainError> {
        self.secret_tool.as_deref().ok_or_else(|| {
            KeychainError::Unavailable(
                "secret-tool is not installed (package libsecret-tools)".into(),
            )
        })
    }

    /// The write gate: the default collection exists and its `Locked`
    /// property reads false. Reading a property never prompts to unlock.
    fn default_unlocked(&self) -> Result<(), KeychainError> {
        let output = run(
            self.gdbus()?,
            &[
                "call",
                "--session",
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                "/org/freedesktop/secrets/aliases/default",
                "--method",
                "org.freedesktop.DBus.Properties.Get",
                "org.freedesktop.Secret.Collection",
                "Locked",
            ],
            None,
            self.bound,
        )?;
        let reply = String::from_utf8_lossy(output.stdout.as_bytes()).into_owned();
        match (output.success, reply.trim()) {
            (true, "(<false>,)") => Ok(()),
            (true, "(<true>,)") => Err(KeychainError::Locked),
            _ => Err(KeychainError::Unavailable(
                "the Secret Service has no default collection on the session bus".into(),
            )),
        }
    }
}

impl SecretStore for LinuxKeychain {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn limit(&self) -> usize {
        LIMIT
    }

    fn probe(&self) -> Result<(), StoreError> {
        self.secret_tool().map_err(store_error)?;
        self.default_unlocked().map_err(store_error)
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        let (unlocked, locked) = self.search(name).map_err(store_error)?;
        Ok(unlocked + locked > 0)
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        let secret_tool = self.secret_tool().map_err(store_error)?;
        self.default_unlocked().map_err(store_error)?;
        // `secret-tool store` replaces an item with the same attributes, so
        // create-only is this check plus the vault lock around it.
        if self.exists(name)? {
            return Err(StoreError::Exists);
        }
        let label = format!("--label={name}");
        let output = run(
            secret_tool,
            &["store", &label, "service", name],
            Some(value),
            self.bound,
        )
        .map_err(store_error)?;
        if !output.success {
            return Err(StoreError::Failed("secret-tool store failed".into()));
        }
        Ok(format!("keychain:{name}"))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        match self.search(name).map_err(store_error)? {
            (0, 0) => return Ok(()),
            (0, _) => {
                return Err(StoreError::Unavailable(
                    "the entry is in a locked collection".into(),
                ));
            }
            _ => {}
        }
        let secret_tool = self.secret_tool().map_err(store_error)?;
        let output =
            run(secret_tool, &["clear", "service", name], None, self.bound).map_err(store_error)?;
        // Durable means gone: the search, not the exit status, decides.
        match (output.success, self.search(name).map_err(store_error)?) {
            (true, (0, 0)) => Ok(()),
            _ => Err(StoreError::Failed(
                "secret-tool clear left the entry in place".into(),
            )),
        }
    }
}

/// A reader error as a writer error. A timeout stays a timeout: a killed
/// `secret-tool store` may already have asked the service to create.
fn store_error(error: KeychainError) -> StoreError {
    match error {
        KeychainError::Timeout => StoreError::TimedOut,
        KeychainError::Locked => StoreError::Unavailable("the keychain is locked".into()),
        KeychainError::Unavailable(why) => StoreError::Unavailable(why),
        KeychainError::Missing => StoreError::Failed("the entry vanished mid-call".into()),
    }
}

impl KeychainRead for LinuxKeychain {
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError> {
        match self.search(name)? {
            (0, 0) => return Err(KeychainError::Missing),
            (0, _) => return Err(KeychainError::Locked),
            _ => {}
        }
        let secret_tool = self.secret_tool()?;
        let output = run(secret_tool, &["lookup", "service", name], None, self.bound)?;
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

/// Runs `program` with `args`, writing `stdin` to it if given, waiting at
/// most `bound` for the write and the exit together. A child past the bound
/// is killed and reaped before this returns. Stderr is dropped: it can carry
/// nothing an operator needs that the reason lacks.
fn run(
    program: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    bound: Duration,
) -> Result<Finished, KeychainError> {
    let deadline = Instant::now() + bound;
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| KeychainError::Unavailable(format!("{} could not start", display(program))))?;
    // The value is written on its own thread, so a child that never reads
    // cannot stall past the bound; killing it breaks the pipe and ends the
    // write. The thread owns a wiped copy, and closes stdin when done.
    let writer = match (stdin, child.stdin.take()) {
        (Some(value), Some(mut pipe)) => {
            let value = WipedBytes::new(value.to_vec());
            let spawned = std::thread::Builder::new()
                .name("keychain-stdin".into())
                .spawn(move || {
                    let _ = pipe.write_all(value.as_bytes());
                });
            let Ok(handle) = spawned else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(KeychainError::Unavailable(
                    "no thread to write the keychain value".into(),
                ));
            };
            Some(handle)
        }
        _ => None,
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(writer) = writer {
                    let _ = writer.join();
                }
                return Err(KeychainError::Timeout);
            }
        }
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
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
