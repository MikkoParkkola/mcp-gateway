// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The launcher's probe for a uv fetch (its design, 1 and 2): uv beside
//! the canonical `uvx` the target names, and the host's `python3` placed by
//! narrow binds, never its whole tree, with every globally installed package
//! directory masked.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the uv fetch's plan calls these (the uv fetch part)"
    )
)]

use std::fs;
use std::path::{Path, PathBuf};

use super::utf8;
use crate::preview_sandbox::Refusal;

/// uv beside the real file of `uvx` (both come from one install).
pub(super) fn uv_beside(uvx: &Path) -> Result<PathBuf, Refusal> {
    Ok(uvx.parent().unwrap_or_else(|| Path::new("/")).join("uv"))
}

/// The real file of the `python3` found on the gateway's PATH.
pub(super) fn python_real(python: &Path) -> Result<PathBuf, Refusal> {
    Ok(fs::canonicalize(python).unwrap_or_else(|_| python.to_owned()))
}

/// What the root must show of the interpreter in both phases, and what it
/// covers with an empty directory after every bind and bind-back.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PythonPlace {
    /// Bound read-only at their own paths.
    pub(super) read_only: Vec<String>,
    /// Bound back under the masked `/usr/local`.
    pub(super) bound_back: Vec<String>,
    /// Package directories hidden from both phases.
    pub(super) masks: Vec<String>,
}

/// The binds and masks for the interpreter whose real file is `real` and
/// whose version is `xy`; `system` lists the roots the sandbox shows anyway.
pub(super) fn place_python(
    real: &Path,
    xy: (u32, u32),
    system: &[String],
) -> Result<PythonPlace, Refusal> {
    let _ = (xy, system);
    let prefix = real
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));
    Ok(PythonPlace {
        read_only: vec![utf8(prefix)?],
        ..PythonPlace::default()
    })
}

#[cfg(test)]
#[path = "uv_probe_tests.rs"]
mod tests;
