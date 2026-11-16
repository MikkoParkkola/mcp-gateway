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
    let mut child = Command::new(npm)
        .arg("--version")
        .env_clear()
        .env("PATH", node_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Refusal::Step(format!("starting {} --version ({e})", npm.display())))?;
    let deadline = Instant::now() + VERSION_BOUND;
    while child.try_wait().ok().flatten().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Refusal::Step(format!(
                "npm --version did not answer within {} s",
                VERSION_BOUND.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut out = String::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(256).read_to_string(&mut out);
    }
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
