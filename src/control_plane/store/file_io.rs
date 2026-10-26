// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The control-plane records of a reverse audit-log scan, and the atomic
//! whole-file write (split from `store.rs`). The paging itself is the shared
//! `transparency_log::pager`.

use super::{AUDIT_KIND, StoreError, StoreResult, audit_event_from_entry};
use crate::control_plane::ControlPlaneAuditEvent;
use std::path::Path;

/// Point at which [`write_atomic`] simulates a crash, for the phase-fault test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FaultPoint {
    /// Complete the write normally.
    None,
    /// Crash after writing the temp file, before its `fsync`.
    AfterTempWrite,
    /// Crash after the temp file's `fsync`, before the `rename`.
    AfterTempFsync,
    /// Crash after the `rename`, before the directory `fsync`.
    AfterRename,
    /// Crash after the directory `fsync` (i.e. fully durable).
    AfterDirFsync,
}

/// Yield the control-plane audit records in `body` newest-first, each paired with
/// the absolute byte offset of its line. `body` must begin on a line boundary at
/// `body_start`.
///
/// A line tagged as a control-plane audit event MUST reconstruct; a malformed one
/// fails closed rather than silently vanishing from the view. Lines of any other
/// kind share the log but are not ours, and are skipped.
pub(super) fn reverse_audit_lines(
    body: &[u8],
    body_start: u64,
) -> impl Iterator<Item = StoreResult<(u64, ControlPlaneAuditEvent)>> + '_ {
    crate::security::transparency_log::pager::lines_newest_first(body, body_start)
        .into_iter()
        .filter_map(|(at, raw)| {
            let trimmed = raw.trim_ascii();
            if trimmed.is_empty() {
                return None;
            }
            let entry: serde_json::Value = match serde_json::from_slice(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    return Some(Err(StoreError::Corrupt(format!(
                        "audit line at byte {at}: {e}"
                    ))));
                }
            };
            if entry.get("kind").and_then(serde_json::Value::as_str) != Some(AUDIT_KIND) {
                return None;
            }
            Some(
                audit_event_from_entry(&entry)
                    .map(|event| (at, event))
                    .ok_or_else(|| {
                        StoreError::Corrupt(format!(
                            "audit line at byte {at}: malformed control-plane audit entry"
                        ))
                    }),
            )
        })
}

// ── Atomic whole-file write ─────────────────────────────────────────────────────

/// Write `bytes` to `target` atomically: temp file in the same dir → `fsync` →
/// `rename` → dir `fsync`. A crash at any phase leaves either the complete old
/// file or the complete new file. `fault` injects an early return for the
/// phase-fault crash-safety test.
// Not `config_persistence::write_atomic`: its FaultPoint crash seam and directory fsync.
pub(super) fn write_atomic(target: &Path, bytes: &[u8], fault: FaultPoint) -> std::io::Result<()> {
    use std::io::Write;

    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent dir")
    })?;
    #[cfg(not(unix))]
    let _ = dir; // dir is only used for the unix directory fsync below
    // ponytail: fixed temp name per collection. A temp orphaned by a crash is
    // ignored by the loader (it reads only the real file) and overwritten by
    // the next write.
    let tmp = target.with_extension("json.tmp");

    {
        // A stale temp would keep its old mode or DACL through the rename, so
        // the helper replaces it: the final collection is always owner-only.
        let mut f = crate::config_persistence::create_private_replacing(&tmp)?;
        f.write_all(bytes)?;
        if fault == FaultPoint::AfterTempWrite {
            return Err(injected_fault());
        }
        f.sync_all()?;
        if fault == FaultPoint::AfterTempFsync {
            return Err(injected_fault());
        }
    }

    std::fs::rename(&tmp, target)?;
    if fault == FaultPoint::AfterRename {
        return Err(injected_fault());
    }

    // Directory fsync makes the rename durable across power loss. Unix only:
    // opening a directory as a file is not portable (Windows rejects it), and
    // the file backend's durability target is Linux. The rename itself is still
    // atomic elsewhere.
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    if fault == FaultPoint::AfterDirFsync {
        return Err(injected_fault());
    }

    Ok(())
}

pub(super) fn injected_fault() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "injected write-phase fault",
    )
}
