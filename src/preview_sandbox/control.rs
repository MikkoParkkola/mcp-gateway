// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The control socket between the gateway and a preview's sandbox helper
//! (ADR-027 step 6): one connection from the helper, one JSON object per
//! line. The helper asks for a fetch, the gateway answers with the fetch's
//! proxy credential, the helper reports the fetch done, and the gateway
//! answers `expired` only once every tunnel of that credential is shut.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the helper's fetch step, a later part, drives the session"
    )
)]

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use super::Refusal;
use super::proxy::AllowlistProxy;

/// The longest control line, its newline included.
pub(crate) const MAX_LINE: usize = 1024;

/// The bounds a session runs under; rows shorten them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlBounds {
    /// The helper's one connection.
    pub(crate) accept: Duration,
    /// The handshake, and the rest of any frame once its first byte came.
    pub(crate) frame: Duration,
}

/// The design's bounds.
pub(crate) const CONTROL_BOUNDS: ControlBounds = ControlBounds {
    accept: Duration::from_secs(5),
    frame: Duration::from_secs(5),
};

/// The connecting process is the helper: its parent is the `unshare` the
/// launcher spawned, and it runs as the gateway's own uid. `status` is the
/// text of `/proc/<pid>/status`; anything unreadable refuses.
pub(crate) fn peer_is_helper(status: &str, unshare_pid: u32, uid: u32) -> Result<(), Refusal> {
    // Red step: no check yet.
    let _ = (status, unshare_pid, uid);
    Ok(())
}

/// Accept the helper's one connection within the bound and check its peer.
/// The listener is consumed, so no second connection is ever taken.
pub(crate) async fn accept_helper(
    listener: UnixListener,
    unshare_pid: u32,
    uid: u32,
    bounds: ControlBounds,
) -> Result<UnixStream, Refusal> {
    // Red step: no bound, no peer check.
    let _ = (unshare_pid, uid, bounds);
    let (stream, _) = listener
        .accept()
        .await
        .map_err(|e| Refusal::Step(format!("accepting the sandbox's control connection ({e})")))?;
    Ok(stream)
}

/// One control line, without its newline: the first byte may take until
/// `first`, the rest of the line `bounds.frame`; over [`MAX_LINE`] refuses.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    first: Duration,
    bounds: ControlBounds,
) -> Result<String, Refusal> {
    // Red step: no cap, no bound.
    let _ = (first, bounds);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| Refusal::Step(format!("reading the control socket ({e})")))?;
    Ok(line.trim_end_matches('\n').to_owned())
}

/// Write one control line.
async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

/// The helper's request for a fetch: `{"fetch_start": true}`.
#[derive(serde::Deserialize)]
struct FetchStart {
    fetch_start: bool,
}

/// The helper's report that the fetch ended: `{"fetch_done": true}`.
#[derive(serde::Deserialize)]
struct FetchDone {
    fetch_done: bool,
}

/// The gateway's answer to `fetch_start`.
#[derive(serde::Serialize)]
struct Issued<'a> {
    credential: &'a str,
    deadline_ms: u128,
}

fn parse<T: serde::de::DeserializeOwned>(line: &str, what: &str) -> Result<T, Refusal> {
    serde_json::from_str(line)
        .map_err(|_| Refusal::Step(format!("the sandbox sent something other than {what}")))
}

/// Run one helper's session on `stream`: `fetch_start`, then the fetch's
/// credential, then `fetch_done`, then `expired` once the credential's
/// tunnels are shut. Any other line, a closed socket or a missed bound ends
/// the session with the credential revoked.
pub(crate) async fn serve_session(
    stream: UnixStream,
    proxy: &AllowlistProxy,
    deadline: tokio::time::Instant,
    bounds: ControlBounds,
) -> Result<(), Refusal> {
    let (read, mut write) = stream.into_split();
    let mut read = tokio::io::BufReader::new(read);
    // Red step: no order check, no revoke on an early exit, `expired` sent
    // before the revoke.
    let start: FetchStart = parse(
        &read_line(&mut read, bounds.frame, bounds).await?,
        "fetch_start",
    )?;
    let _ = start.fetch_start;
    let credential = proxy.begin_fetch(deadline)?;
    let deadline_ms = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .as_millis();
    let issued = serde_json::to_string(&Issued {
        credential: credential.secret(),
        deadline_ms,
    })
    .map_err(|e| Refusal::Step(format!("encoding the credential line ({e})")))?;
    let lost = |e: io::Error| Refusal::Step(format!("writing the control socket ({e})"));
    write_line(&mut write, &issued).await.map_err(lost)?;
    let first = deadline.saturating_duration_since(tokio::time::Instant::now());
    let done: FetchDone = parse(&read_line(&mut read, first, bounds).await?, "fetch_done")?;
    let _ = done.fetch_done;
    write_line(&mut write, r#"{"expired":true}"#)
        .await
        .map_err(lost)?;
    proxy.revoke(&credential);
    Ok(())
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
