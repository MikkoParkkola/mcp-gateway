// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Executable stubs for tests. Std only and naming no `crate::` item, so the
//! library's tests use it as a module and the integration tests through
//! `#[path]`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

/// Write `contents` to `path` as a program anyone may run (mode 0755).
pub(crate) fn write_executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write stub");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod stub");
}
