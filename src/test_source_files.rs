// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one walk over source files for the tests that scan the tree. Standard library only, so the library's tests
//! use it as a module and the integration tests include it through `#[path]` without pulling in anything else.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Appends every `.rs` file under `dir`, at any depth, to `out`, after whatever `out` already holds. The order is
/// the file system's; a caller that needs one sorts.
///
/// # Panics
///
/// When `dir` or a directory under it cannot be listed, or one of its entries cannot be read. The message names the
/// path: a scan that silently read a missing directory as empty would pass over nothing.
pub(crate) fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let listing =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
    for item in listing {
        let found = item
            .unwrap_or_else(|e| panic!("cannot read an entry of {}: {e}", dir.display()))
            .path();
        if found.is_dir() {
            rust_files(&found, out);
            continue;
        }
        // Exactly `rs`: a `.RS` or `.rs.bak` file is not Rust source to these scans.
        if found.extension() == Some(OsStr::new("rs")) {
            out.push(found);
        }
    }
}
