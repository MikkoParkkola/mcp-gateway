// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Run a built CLI invocation (MIK-7782).
//!
//! No shell is involved anywhere: the resolved program is spawned with the
//! built argv. The child gets a private empty directory as cwd, HOME and temp
//! space (so it cannot fall back to the operator's own logins or dotfiles), an
//! environment of only the allowlisted names, capped output, a timeout, and a
//! process group (Unix) or Job object (Windows) so the whole tree dies with the
//! call, also when the call is cancelled.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::cli_argv::CliInvocation;
use crate::{Error, Result};

/// Longest a CLI capability may run, whatever its file asks for.
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// A private, empty directory that is the child's cwd, HOME and temp area,
/// removed when the call ends.
pub(crate) struct Workdir(PathBuf);

impl Workdir {
    pub(crate) fn create() -> std::io::Result<Self> {
        let root =
            std::env::temp_dir().join(format!("mcp-gateway-cap-{}", uuid::Uuid::new_v4().simple()));
        // A fresh random name, created (not opened): an entry planted at that
        // path makes this fail instead of being used.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        }
        #[cfg(windows)]
        crate::private_fs::create_dir_private(&root)?;
        #[cfg(not(any(unix, windows)))]
        std::fs::create_dir(&root)?;
        let dir = Self(root);
        for sub in SUBDIRS {
            std::fs::create_dir_all(dir.0.join(sub))?;
        }
        Ok(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        // Owned scratch made for this call alone; nothing else lives here.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SUBDIRS: [&str; 4] = [".config", ".cache", ".local/share", "tmp"];

/// The child's whole environment: PATH, the private directories, the
/// platform variables a program needs to start, and then only `allowed`.
///
/// `lookup` resolves a name against the gateway's environment (the `LiveEnv`
/// overlay in production). Values are never logged.
pub(crate) fn child_env(
    workdir: &Path,
    allowed: &[String],
    lookup: &dyn Fn(&str) -> Option<OsString>,
    token: Option<(&str, &str)>,
) -> Vec<(OsString, OsString)> {
    let dir = |sub: &str| workdir.join(sub).into_os_string();
    let mut env: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), workdir.as_os_str().to_owned()),
        ("XDG_CONFIG_HOME".into(), dir(".config")),
        ("XDG_CACHE_HOME".into(), dir(".cache")),
        ("XDG_DATA_HOME".into(), dir(".local/share")),
        ("TMPDIR".into(), dir("tmp")),
    ];
    if let Some(path) = lookup("PATH") {
        env.push(("PATH".into(), path));
    }
    if cfg!(windows) {
        env.push(("USERPROFILE".into(), workdir.as_os_str().to_owned()));
        env.push(("APPDATA".into(), dir(".config")));
        env.push(("LOCALAPPDATA".into(), dir(".local/share")));
        env.push(("TEMP".into(), dir("tmp")));
        env.push(("TMP".into(), dir("tmp")));
        for name in ["SYSTEMROOT", "COMSPEC", "PATHEXT"] {
            if let Some(value) = lookup(name) {
                env.push((name.into(), value));
            }
        }
    }
    for name in allowed {
        if !is_reserved(name)
            && let Some(value) = lookup(name)
        {
            env.push((name.into(), value));
        }
    }
    if let Some((name, value)) = token
        && !is_reserved(name)
    {
        env.push((name.into(), value.into()));
    }
    env
}

/// Names the gateway sets for the child itself. An allowlist entry,
/// `token_env` or `root_env` naming one is ignored: it would point the child
/// back at the operator's home, profile or temp space, or (SYSTEMROOT,
/// COMSPEC) replace the Windows bootstrap values `child_env` sets.
/// Case-insensitive, as on Windows.
pub(crate) fn is_reserved(name: &str) -> bool {
    const RESERVED: [&str; 14] = [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "TMPDIR",
        "PATH",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "PATHEXT",
        "SYSTEMROOT",
        "COMSPEC",
    ];
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
}

/// Resolve `command` to the absolute path that is spawned.
///
/// An absolute path is taken as written; a bare name is looked up on `path`
/// (on Windows with each `PATHEXT` extension, so an npm `.cmd` shim is found
/// and std's batch-argument escaping applies to it). Anything else, such as
/// `./tool` or `bin/tool`, is refused.
pub(crate) fn resolve_command(
    command: &str,
    path: Option<&OsStr>,
    pathext: Option<&OsStr>,
) -> Result<PathBuf> {
    let as_path = Path::new(command);
    if as_path.is_absolute() {
        return if as_path.is_file() {
            Ok(as_path.to_path_buf())
        } else {
            Err(Error::Config(format!("command '{command}' does not exist")))
        };
    }
    if command.is_empty() || command.contains(['/', '\\']) {
        return Err(Error::Config(format!(
            "command '{command}' must be a bare name or an absolute path"
        )));
    }
    // On Windows a name without an extension is tried only with PATHEXT's:
    // npm puts an extensionless shell script next to its `.cmd` shim, and
    // that script is not something Windows can start.
    let has_extension = Path::new(command).extension().is_some();
    let extensions: Vec<String> = if cfg!(windows) && !has_extension {
        let list = pathext.map_or_else(
            || ".COM;.EXE;.BAT;.CMD".to_owned(),
            |p| p.to_string_lossy().into_owned(),
        );
        list.split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(path.unwrap_or_default()) {
        for ext in &extensions {
            let candidate = dir.join(format!("{command}{ext}"));
            if candidate.is_file() && candidate.is_absolute() {
                return Ok(candidate);
            }
        }
    }
    Err(Error::Config(format!(
        "command '{command}' was not found on PATH"
    )))
}

/// What a finished child produced.
#[derive(Debug)]
pub(crate) struct CliOutcome {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Owns the spawned tree. Dropping it, on any path (success, error, timeout
/// or a cancelled call), kills the whole group or Job, then reaps off-thread.
struct TreeGuard(Option<Box<dyn ChildWrapper>>);

impl TreeGuard {
    fn child(&mut self) -> &mut Box<dyn ChildWrapper> {
        self.0.as_mut().expect("child present until drop")
    }
}

impl Drop for TreeGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        // On Unix this signals the whole process group (killpg), not only the
        // leader; on Windows it terminates the Job. A group already gone is
        // fine.
        let _ = child.start_kill();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

/// Spawn `program` with `invocation`'s argv in `workdir`, feed stdin, collect
/// capped output, and wait at most `timeout`.
pub(crate) async fn run(
    program: &Path,
    invocation: &CliInvocation,
    workdir: &Workdir,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    max_output: usize,
) -> Result<CliOutcome> {
    let timeout = timeout.min(MAX_TIMEOUT);
    let mut wrap = CommandWrap::with_new(program, |cmd| {
        cmd.args(&invocation.args)
            .env_clear()
            .envs(env)
            .current_dir(workdir.path())
            .stdin(if invocation.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    #[cfg(unix)]
    wrap.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    wrap.wrap(JobObject);
    wrap.wrap(KillOnDrop);
    // From just before spawn: the fork and exec are part of what it cost.
    let started = Instant::now();
    let child = wrap.spawn().map_err(|e| {
        Error::Protocol(format!(
            "could not start '{}': {}",
            invocation.command,
            e.kind()
        ))
    })?;
    let mut guard = TreeGuard(Some(child));

    if let Some(bytes) = invocation.stdin.clone()
        && let Some(mut stdin) = guard.child().stdin().take()
    {
        // Written off the read path and then closed, so a child that never
        // reads stdin cannot stall the call.
        tokio::spawn(async move {
            let _ = stdin.write_all(bytes.as_bytes()).await;
        });
    }
    let stdout = guard.child().stdout().take();
    let stderr = guard.child().stderr().take();

    let collected = tokio::time::timeout(timeout, async {
        // try_join: an overflow on one stream ends the call at once rather
        // than waiting on the other until the timeout.
        let (out, err) = tokio::try_join!(
            read_capped(stdout, max_output),
            read_capped(stderr, max_output)
        )?;
        let status =
            guard.child().wait().await.map_err(|e| {
                Failure::Observe(format!("waiting for the child failed: {}", e.kind()))
            })?;
        Ok::<_, Failure>(CliOutcome {
            status,
            stdout: out,
            stderr: err,
        })
    })
    .await;
    // `guard` drops here on every path and takes the tree with it.
    let (ended, result) = match collected {
        Ok(Ok(outcome)) => (ProcessEnd::of(outcome.status), Ok(outcome)),
        Ok(Err(Failure::Overflow(max))) => (
            ProcessEnd::OutputOverflow,
            Err(Error::Protocol(format!(
                "child output passed the {max}-byte limit"
            ))),
        ),
        Ok(Err(Failure::Observe(message))) => {
            (ProcessEnd::ObservationFailed, Err(Error::Protocol(message)))
        }
        Err(_) => (
            ProcessEnd::TimedOut,
            Err(Error::BackendTimeout(format!(
                "'{}' did not finish within {}s",
                invocation.command,
                timeout.as_secs()
            ))),
        ),
    };
    let bytes = result
        .as_ref()
        .ok()
        .map(|o| (o.stdout.len(), o.stderr.len()));
    crate::gateway::note_process(ProcessNote {
        ended,
        duration: started.elapsed(),
        bytes,
    });
    result
}

/// How a started child ended, as the invocation record states it
/// (MIK-7926.FIX.2). Counts and codes only, never output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessEnd {
    /// It exited with this code.
    Exited(i32),
    /// It was ended by a signal (no exit code).
    Signalled,
    /// It outlived the capability's timeout and was killed.
    TimedOut,
    /// It wrote more than `max_output_bytes` and was killed.
    OutputOverflow,
    /// Reading its output or waiting for it failed.
    ObservationFailed,
}

impl ProcessEnd {
    fn of(status: ExitStatus) -> Self {
        status.code().map_or(Self::Signalled, Self::Exited)
    }
}

/// One started child, for the invocation record of the call that ran it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessNote {
    pub(crate) ended: ProcessEnd,
    /// From spawn to the end of collection, the wait included.
    pub(crate) duration: Duration,
    /// Stdout and stderr byte counts; `None` when the output was not kept.
    pub(crate) bytes: Option<(usize, usize)>,
}

impl ProcessNote {
    /// The record's form: `ended` in `snake_case`, `exit_code` for an exit,
    /// byte counts `null` when the output was not kept.
    pub(crate) fn to_json(self) -> serde_json::Value {
        let (ended, code) = match self.ended {
            ProcessEnd::Exited(code) => ("exited", Some(code)),
            ProcessEnd::Signalled => ("signalled", None),
            ProcessEnd::TimedOut => ("timed_out", None),
            ProcessEnd::OutputOverflow => ("output_overflow", None),
            ProcessEnd::ObservationFailed => ("observation_failed", None),
        };
        let mut json = serde_json::json!({
            "ended": ended,
            "duration_ms": u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX),
            "stdout_bytes": self.bytes.map(|b| b.0),
            "stderr_bytes": self.bytes.map(|b| b.1),
        });
        if let Some(code) = code {
            json["exit_code"] = code.into();
        }
        json
    }
}

/// Why collection stopped short, kept apart so `run` names the outcome
/// without reading error text.
enum Failure {
    Overflow(usize),
    Observe(String),
}

/// Read a stream to its end, failing once it passes `max` bytes.
async fn read_capped<R: AsyncRead + Unpin>(
    stream: Option<R>,
    max: usize,
) -> std::result::Result<Vec<u8>, Failure> {
    let Some(stream) = stream else {
        return Ok(Vec::new());
    };
    let mut buf = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    stream
        .take(limit)
        .read_to_end(&mut buf)
        .await
        .map_err(|e| Failure::Observe(format!("reading child output failed: {}", e.kind())))?;
    if buf.len() > max {
        return Err(Failure::Overflow(max));
    }
    Ok(buf)
}

#[cfg(test)]
#[path = "cli_run_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cli_audit_tests.rs"]
mod audit_tests;
