// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Install checks for the fetch phase (ADR-027): the npm lock holds nothing
//! from outside the registry, and the run's argv comes from the installed
//! package's own metadata, never from a listing of a bin directory.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls these")
)]

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::Refusal;

/// Refuse unless `lock` (a `package-lock.json`) holds only registry tarballs.
pub(crate) fn check_lock(_lock: &Value) -> Result<(), Refusal> {
    Ok(())
}

/// The bin file of npm package `name` installed under `root`.
pub(crate) fn npm_bin(_root: &Path, _name: &str) -> Result<PathBuf, Refusal> {
    Err(Refusal::Command("stub".into()))
}

/// The console script of PyPI package `name` in the uv tool environment `env`.
pub(crate) fn uv_entry_point(_env: &Path, _name: &str) -> Result<PathBuf, Refusal> {
    Err(Refusal::Command("stub".into()))
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
