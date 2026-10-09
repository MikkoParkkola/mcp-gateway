// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Process-tree ownership and frame reading for the stdio transport.

use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use super::StdioTransport;
use crate::protocol::{JsonRpcRequest, RequestId};
use crate::transport::write_claim::WriteClaim;
use crate::{Error, Result};

impl Drop for StdioTransport {
    /// A dropped transport ends the whole tree. `KillOnDrop` only kills the
    /// group leader, so `npx`/`uvx` descendants would outlive it. It also
    /// cancels `shutdown`, as `close()` does, so a write stuck on a reader
    /// outside the group ends and gives up stdin (MIK-8079).
    fn drop(&mut self) {
        // The tree itself (`ChildTree`'s Drop) sends the one group signal.
        self.shutdown.get_mut().cancel();
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

/// Write one frame (`message` and a newline) to stdin (MIK-8079).
///
/// The caller takes stdin first, so a caller cancelled while waiting sends
/// nothing. The write itself runs in a task the caller only awaits, so an
/// admitted write is never cut off mid-frame by its caller being dropped.
/// `close()` cancels `shutdown` after ending the tree: a write stuck on a reader
/// outside the group is then dropped, giving up stdin and its buffer.
pub(super) async fn write_frame(
    writer: &std::sync::Arc<tokio::sync::Mutex<Option<tokio::process::ChildStdin>>>,
    shutdown: &parking_lot::Mutex<tokio_util::sync::CancellationToken>,
    message: String,
    began: &std::sync::atomic::AtomicBool,
    claim: Option<&WriteClaim>,
) -> Result<()> {
    // Built in place: a queued write holds one copy of the message.
    let mut frame = message.into_bytes();
    frame.push(b'\n');
    let mut writer = std::sync::Arc::clone(writer).lock_owned().await;
    // Admitted: from here the frame goes out whole, so a caller dropped
    // after this point has a written request to cancel (`MIK-7642.PR.B`).
    if let Some(claim) = claim {
        claim.claim_write();
    }
    // Taken under the stdin lock: the token belongs to the stdin it guards.
    let shutdown = shutdown.lock().clone();
    // From here the frame goes out whole even if the caller is dropped, so the
    // call is no longer pre-send (MIK-7979).
    began.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::spawn(async move {
        let Some(stdin) = writer.as_mut() else {
            return Err(Error::TransportConnect("Not connected".to_string()));
        };
        let write = async {
            stdin.write_all(&frame).await?;
            stdin.flush().await
        };
        tokio::select! {
            written = write => written.map_err(|e| Error::Transport(e.to_string())),
            () = shutdown.cancelled() => {
                Err(Error::Transport("stdio transport closed mid-write".to_string()))
            }
        }
    })
    .await
    .map_err(|e| Error::Transport(e.to_string()))?
}

/// `MIK-7642.PR.B`: a request dropped before its answer cancels the backend's
/// call, if its frame was written, by the id the backend received. The cancel
/// goes through [`write_frame`], so it waits for the request frame's stdin
/// lock and can never land ahead of it or inside it.
pub(super) struct CancelUnanswered<'a> {
    transport: &'a StdioTransport,
    key: String,
    id: RequestId,
    claim: std::sync::Arc<WriteClaim>,
    armed: bool,
}

impl<'a> CancelUnanswered<'a> {
    /// Never armed for `initialize`, which the protocol forbids cancelling.
    pub(super) fn arm(
        transport: &'a StdioTransport,
        request: &JsonRpcRequest,
        claim: &std::sync::Arc<WriteClaim>,
    ) -> Self {
        Self {
            transport,
            key: request.id.to_string(),
            id: request.id.clone(),
            claim: std::sync::Arc::clone(claim),
            armed: request.method != "initialize",
        }
    }

    /// Finished, answered or failed: a transport timeout is not a cancel.
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelUnanswered<'_> {
    fn drop(&mut self) {
        // Removing the entry is the arbitration with the reader, which removes
        // it before delivering: exactly one of {answer, cancel} wins.
        if !self.armed
            || self.transport.pending.remove(&self.key).is_none()
            || !self.claim.abandon()
        {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("stdio: cancel not sent; the backend finishes the call");
            return;
        };
        let writer = std::sync::Arc::clone(&self.transport.writer);
        let shutdown = parking_lot::Mutex::new(self.transport.shutdown.lock().clone());
        let message = serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": crate::transport::write_claim::cancelled_params(&self.id),
        })
        .to_string();
        runtime.spawn(async move {
            let began = std::sync::atomic::AtomicBool::new(false);
            drop(write_frame(&writer, &shutdown, message, &began, None).await);
        });
    }
}

/// How long `close()` waits for a write it could not stop to give up stdin.
const CLOSE_WRITER_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Clear stdin at the end of `close()`, after the tree was killed and
/// `shutdown` cancelled, which drops any stuck write. The wait stays bounded as
/// a backstop, so `close()` can never hang on stdin (MIK-8079).
pub(super) async fn clear_writer(writer: &tokio::sync::Mutex<Option<tokio::process::ChildStdin>>) {
    if let Ok(mut writer) = tokio::time::timeout(CLOSE_WRITER_WAIT, writer.lock()).await {
        *writer = None;
    }
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
