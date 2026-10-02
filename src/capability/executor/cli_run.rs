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
use std::process::ExitStatus;
use std::time::Duration;

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

/// Names the gateway sets for the child itself. An allowlist entry or
/// `token_env` naming one is ignored: it would point the child back at the
/// operator's home, profile or temp space. Case-insensitive, as on Windows.
pub(crate) fn is_reserved(name: &str) -> bool {
    const RESERVED: [&str; 12] = [
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
    let _ = (program, workdir, env, timeout, max_output);
    Err(Error::Protocol(format!(
        "running '{}' is not implemented yet",
        invocation.command
    )))
}

#[cfg(test)]
#[path = "cli_run_tests.rs"]
mod tests;
