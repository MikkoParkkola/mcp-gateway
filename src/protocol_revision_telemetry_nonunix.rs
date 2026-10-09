// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Off unix, directory fsync and owner-only permissions are no-ops; each keeps
//! the unix signature so the callers stay platform-free (MIK-8223).

use std::io;
use std::path::Path;

pub(super) fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "a no-op off unix that keeps the unix signature"
)]
pub(super) fn force_directory_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}
