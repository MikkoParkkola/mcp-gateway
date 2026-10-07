// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process-tree ownership and frame reading for the stdio transport.

use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
use tokio::process::Command;

use super::StdioTransport;
use crate::{Error, Result};

impl Drop for StdioTransport {
    /// A dropped transport ends the whole tree. `KillOnDrop` only kills the
    /// group leader, so `npx`/`uvx` descendants would outlive it.
    fn drop(&mut self) {
        if let Some(child) = self.child.get_mut().as_mut() {
            let _ = child.start_kill();
        }
    }
}

/// Start `cmd` as the leader of its own process group (Unix) or Job object
/// (Windows), so stopping the backend ends every process it started:
/// `npx`/`uvx`-style launchers otherwise leave the real server behind.
pub(super) fn spawn_in_own_tree(cmd: Command) -> Result<Box<dyn ChildWrapper>> {
    let mut wrap = CommandWrap::from(cmd);
    wrap.wrap(KillOnDrop);
    #[cfg(unix)]
    wrap.wrap(process_wrap::tokio::ProcessGroup::leader());
    #[cfg(windows)]
    wrap.wrap(process_wrap::tokio::JobObject);
    wrap.spawn().map_err(|e| match e.kind() {
        // A command path that does not exist, or a file that is not
        // executable. No amount of waiting fixes either, and warm-start
        // retries transport failures indefinitely -- so before this, a
        // typo in a backend command was respawned once a minute for the
        // life of the process with no indication the config was wrong.
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            Error::TransportPermanent(format!("Failed to spawn: {e}"))
        }
        _ => Error::Transport(format!("Failed to spawn: {e}")),
    })
}

/// Whether the backend's leader has exited, WITHOUT reaping it (MIK-8080).
///
/// The leader's pid is its process-group id. Reaping it here would free that id
/// while `close()`, `Drop` and the read-error path still signal the stored
/// group, so after a pid wraparound they could kill an unrelated group. Left a
/// zombie, the leader keeps the id reserved until teardown kills and reaps the
/// whole group.
#[cfg(unix)]
pub(super) fn leader_exited(child: &mut dyn ChildWrapper) -> bool {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
    let Some(pid) = child
        .id()
        .and_then(|id| Pid::from_raw(i32::try_from(id).ok()?))
    else {
        return true; // already reaped: nothing is left to signal
    };
    let peek = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    !matches!(waitid(WaitId::Pid(pid), peek), Ok(None))
}

/// A Job object, not a reusable group id, owns the tree here.
#[cfg(not(unix))]
pub(super) fn leader_exited(child: &mut dyn ChildWrapper) -> bool {
    matches!(child.try_wait(), Ok(Some(_)))
}

/// Default longest JSON-RPC frame a stdio peer may send (16 MiB). Without a
/// bound, a peer that never sends a newline grows the gateway's buffer without
/// limit. A backend raises or lowers it with `max_frame_bytes`.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Smallest `max_frame_bytes` a backend may ask for (64 KiB).
pub const MIN_MAX_FRAME_BYTES: usize = 64 * 1024;
/// Largest `max_frame_bytes` a backend may ask for (1 GiB).
pub const CEILING_MAX_FRAME_BYTES: usize = 1024 * 1024 * 1024;

/// Read one newline-terminated frame (without its `\n` or `\r\n`).
/// `Ok(None)` at end of stream; an error for a frame over
/// `max` bytes or one that is not UTF-8.
pub(super) async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<String>> {
    frame.clear();
    // Room for the longest allowed frame plus its `\r\n`; a longer line is cut
    // here and refused below once the terminator is trimmed.
    let limit = u64::try_from(max).unwrap_or(u64::MAX) + 2;
    let read = reader.take(limit).read_until(b'\n', frame).await?;
    if read == 0 {
        return Ok(None);
    }
    if frame.last() == Some(&b'\n') {
        frame.pop();
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
    }
    if frame.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "stdio frame over {max} bytes; raise this backend's max_frame_bytes if the response is legitimate"
            ),
        ));
    }
    String::from_utf8(std::mem::take(frame))
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
