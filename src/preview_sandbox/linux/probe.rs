// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The launcher's probe for an npm fetch (D7): npm and node beside the `npx`
//! the target names (a system install or an NVM-only node alike), npm's
//! version floor, and `ip` for bringing `lo` up, each inside a bound tree.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::preview_sandbox::Refusal;

/// Where `ip` may live; the first that exists inside a bound tree is used.
pub(super) const IP_CANDIDATES: [&str; 4] = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

/// npm older than this refuses the fetch.
const NPM_FLOOR: u32 = 9;
/// How long `npm --version` may take.
const VERSION_BOUND: Duration = Duration::from_secs(10);

/// npm and node's directory beside `npx` (the path it was found at, before
/// symlinks are followed), as npm and node install them together.
pub(super) fn npm_beside(npx: &Path) -> Result<(PathBuf, PathBuf), Refusal> {
    let dir = npx
        .parent()
        .ok_or_else(|| Refusal::Step("finding npm beside npx (npx has no directory)".into()))?;
    let (npm, node) = (dir.join("npm"), dir.join("node"));
    for (what, file) in [("npm", &npm), ("node", &node)] {
        if !file.exists() {
            return Err(Refusal::Step(format!(
                "finding {what} beside {} (not there)",
                npx.display()
            )));
        }
    }
    Ok((npm, dir.to_path_buf()))
}

/// Refuse an npm older than 9: `npm --version` (within `VERSION_BOUND`, environment cleared but
/// PATH = `node_dir`, since npm starts through `/usr/bin/env node`).
pub(super) fn check_npm(npm: &Path, node_dir: &Path) -> Result<(), Refusal> {
    let out = answer(
        npm,
        &["--version"],
        Some(node_dir.as_os_str()),
        "npm --version",
    )?;
    let version = out.trim();
    match version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
    {
        Some(major) if major >= NPM_FLOOR => Ok(()),
        Some(_) => Err(Refusal::Step(format!(
            "npm {version} is older than {NPM_FLOOR}"
        ))),
        None => Err(Refusal::Step(format!(
            "reading npm's version ({version:?})"
        ))),
    }
}

/// The first 256 bytes `program` prints on stdout, run with `args`, its
/// environment cleared (PATH = `path` when given), within `VERSION_BOUND`;
/// `label` names it when it does not answer in time.
pub(super) fn answer(
    program: &Path,
    args: &[&str],
    path: Option<&std::ffi::OsStr>,
    label: &str,
) -> Result<String, Refusal> {
    use std::os::unix::process::CommandExt as _;
    let mut command = Command::new(program);
    // Its own process group, so the call and anything it started end with it.
    command.args(args).env_clear().process_group(0);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            Refusal::Step(format!(
                "starting {} {} ({e})",
                program.display(),
                args.join(" ")
            ))
        })?;
    let deadline = Instant::now() + VERSION_BOUND;
    let late = || {
        Refusal::Step(format!(
            "{label} did not answer within {} s",
            VERSION_BOUND.as_secs()
        ))
    };
    // The answer is one line, read on its own thread: a descendant that keeps
    // the pipe open after the line cannot hold the call past the bound.
    // ponytail: the reader thread outlives a call refused at the bound until
    // the pipe closes; bounded by the caller's own descendants.
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufRead::read_line(
                &mut std::io::BufReader::new(stdout.take(256)),
                &mut line,
            );
            let _ = line_tx.send(line);
        });
    }
    // The group's id is the child's pid; the kernel does not reuse it while
    // any member, the descendants included, is alive.
    let group = rustix::process::Pid::from_child(&child);
    let end_group = || {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    };
    while child.try_wait().ok().flatten().is_none() {
        if Instant::now() >= deadline {
            end_group();
            let _ = child.wait();
            return Err(late());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let answered = line_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| late());
    // Whatever the call started is ended with it: nothing it left holds the
    // pipe or runs on after the answer.
    end_group();
    answered
}

/// The first of `candidates` that exists, followed to its real file, and is
/// `shown` inside the root.
pub(super) fn find_ip(
    candidates: &[&str],
    shown: &dyn Fn(&Path) -> bool,
) -> Result<String, Refusal> {
    for candidate in candidates {
        let Ok(real) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if let Some(real) = real.to_str()
            && shown(Path::new(real))
        {
            return Ok(real.to_owned());
        }
    }
    Err(Refusal::Step(
        "finding ip inside the bound trees (none there)".into(),
    ))
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
