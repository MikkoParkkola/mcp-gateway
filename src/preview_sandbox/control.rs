// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The control socket between the gateway and a preview's sandbox helper
//! (ADR-027 step 6): one connection from the helper, one JSON object per
//! line. The helper asks for a fetch, the gateway answers with the fetch's
//! proxy credential, the helper reports the fetch done, and the gateway
//! answers `expired` only once every tunnel of that credential is shut.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the fetch step, a later part, drives it")
)]

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use super::Refusal;
use super::proxy::{AllowlistProxy, Credential};

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
    let refuse = |why: &str| Refusal::Step(format!("the sandbox's control peer {why}"));
    // Each field exactly once: a second copy (smuggled through the process
    // name, say) refuses instead of racing the real line.
    let field = |name: &str| {
        let mut found = status.lines().filter_map(|line| line.strip_prefix(name));
        match (found.next(), found.next()) {
            (Some(value), None) => Ok(value),
            _ => Err(refuse("has no readable parentage")),
        }
    };
    let parent: u32 = field("PPid:")?
        .trim()
        .parse()
        .map_err(|_| refuse("has no readable parentage"))?;
    // Real, effective, saved and filesystem uid: all four are the gateway's.
    let uids = field("Uid:")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refuse("has no readable uid"))?;
    if uids.len() != 4 {
        return Err(refuse("has no readable uid"));
    }
    if parent != unshare_pid {
        return Err(refuse("is not the sandbox's helper"));
    }
    if uids.iter().any(|u| *u != uid) {
        return Err(refuse("runs as another user"));
    }
    Ok(())
}

/// The connecting process started no later than its connection was taken:
/// `stat` is the text of `/proc/<pid>/stat`, `accepted` the boot clock in
/// clock ticks read just after the accept. A later start means the pid
/// names a newer process than the one that connected.
pub(crate) fn started_by(stat: &str, accepted: u64) -> Result<(), Refusal> {
    let refuse = |why: &str| Refusal::Step(format!("the sandbox's control peer {why}"));
    // The fields after the LAST ')': the process name before it is the
    // process's own choice and may hold spaces and parentheses.
    let (_, fields) = stat
        .rsplit_once(')')
        .ok_or_else(|| refuse("has no readable start time"))?;
    // Field 22 of the line; field 3 is the first after the name.
    let start: u64 = fields
        .split_whitespace()
        .nth(22 - 3)
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| refuse("has no readable start time"))?;
    if start > accepted {
        return Err(refuse("started after its connection was taken"));
    }
    Ok(())
}

/// The boot clock now, in the clock ticks `/proc/<pid>/stat` counts in.
#[cfg(target_os = "linux")]
fn boot_ticks() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let hz = rustix::param::clock_ticks_per_second();
    let secs = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    secs.saturating_mul(hz)
        .saturating_add(nanos.saturating_mul(hz) / 1_000_000_000)
}

/// The peer's `/proc/<pid>` directory, opened once. Every later read goes
/// through it, and it stays bound to the process it named when it opened:
/// once that process is gone its reads fail, even if the pid is reused.
#[cfg(target_os = "linux")]
fn open_peer(pid: i32) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    Ok(rustix::fs::open(
        format!("/proc/{pid}"),
        flags,
        Mode::empty(),
    )?)
}

/// One file of the peer's `/proc` directory, read through `dir`.
#[cfg(target_os = "linux")]
fn read_peer(dir: &rustix::fd::OwnedFd, name: &str) -> io::Result<String> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read as _;
    let file = rustix::fs::openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut text = String::new();
    std::fs::File::from(file).read_to_string(&mut text)?;
    Ok(text)
}

/// Judge the peer behind `dir`: it started by `accepted`, its parent is the
/// spawned `unshare` and it runs as `uid`. Any unreadable file refuses.
#[cfg(target_os = "linux")]
fn judge_dir(
    dir: &rustix::fd::OwnedFd,
    accepted: u64,
    unshare_pid: u32,
    uid: u32,
) -> Result<(), Refusal> {
    let read = |name: &str| {
        read_peer(dir, name).map_err(|e| {
            Refusal::Step(format!(
                "the sandbox's control peer has no readable {name} ({e})"
            ))
        })
    };
    started_by(&read("stat")?, accepted)?;
    peer_is_helper(&read("status")?, unshare_pid, uid)
}

/// Without `/proc` the peer cannot be judged, so it is refused.
#[cfg(not(target_os = "linux"))]
fn judge_peer(_pid: i32, _unshare_pid: u32, _uid: u32) -> Result<(), Refusal> {
    Err(Refusal::Step(
        "the sandbox's control peer cannot be checked without /proc".into(),
    ))
}

/// Accept the helper's one connection within the bound and check its peer.
/// The listener is consumed, so no second connection is ever taken.
pub(crate) async fn accept_helper(
    listener: UnixListener,
    unshare_pid: u32,
    uid: u32,
    bounds: ControlBounds,
) -> Result<UnixStream, Refusal> {
    let accepted = tokio::time::timeout(bounds.accept, listener.accept())
        .await
        .map_err(|_| Refusal::Step("the sandbox never opened its control connection".into()))?;
    let (stream, _) = accepted
        .map_err(|e| Refusal::Step(format!("accepting the sandbox's control connection ({e})")))?;
    // The boot clock as the connection is taken: a process that started
    // later is not the one that connected, whatever pid it holds.
    #[cfg(target_os = "linux")]
    let accepted_at = boot_ticks();
    let cred = stream
        .peer_cred()
        .map_err(|e| Refusal::Step(format!("reading the control peer's credentials ({e})")))?;
    let pid = cred
        .pid()
        .ok_or_else(|| Refusal::Step("the control peer has no process id".into()))?;
    if cred.uid() != uid {
        return Err(Refusal::Step(
            "the sandbox's control peer runs as another user".into(),
        ));
    }
    // One /proc/<pid> directory for every read, opened now: a process that
    // took the pid after the accept refuses on its start time, and one that
    // exits after the open fails the reads. A pid taken before the accept
    // names no child of the spawned unshare, whose only child is the helper.
    #[cfg(target_os = "linux")]
    judge_dir(
        &open_peer(pid).map_err(|e| {
            Refusal::Step(format!(
                "the sandbox's control peer has no /proc entry ({e})"
            ))
        })?,
        accepted_at,
        unshare_pid,
        uid,
    )?;
    #[cfg(not(target_os = "linux"))]
    judge_peer(pid, unshare_pid, uid)?;
    Ok(stream)
}

/// One control line, without its newline: the first byte may take until
/// `first`, the rest of the line `bounds.frame`; over [`MAX_LINE`] refuses.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    first: Duration,
    bounds: ControlBounds,
) -> Result<String, Refusal> {
    let refuse = |why: &str| Refusal::Step(format!("the sandbox's control line {why}"));
    let io_err = |e: io::Error| Refusal::Step(format!("reading the control socket ({e})"));
    match tokio::time::timeout(first, reader.fill_buf()).await {
        Err(_) => return Err(refuse("never came")),
        Ok(Err(e)) => return Err(io_err(e)),
        Ok(Ok([])) => return Err(refuse("ended with the connection")),
        Ok(Ok(_)) => {}
    }
    let rest = async {
        let mut line = Vec::new();
        loop {
            let buf = reader.fill_buf().await.map_err(io_err)?;
            if buf.is_empty() {
                return Err(refuse("was cut off by a close"));
            }
            // The cap is checked before the buffer grows; the newline counts.
            if let Some(end) = buf.iter().position(|b| *b == b'\n') {
                if line.len() + end >= MAX_LINE {
                    return Err(refuse("is over 1 KiB"));
                }
                line.extend_from_slice(&buf[..end]);
                reader.consume(end + 1);
                return Ok(line);
            }
            let taken = buf.len();
            if line.len() + taken >= MAX_LINE {
                return Err(refuse("is over 1 KiB"));
            }
            line.extend_from_slice(buf);
            reader.consume(taken);
        }
    };
    let line = tokio::time::timeout(bounds.frame, rest)
        .await
        .map_err(|_| refuse("stalled before its end"))??;
    String::from_utf8(line).map_err(|_| refuse("is not UTF-8"))
}

/// Write one control line within the frame bound: a helper that stops
/// reading cannot hold the session open.
async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
    _bounds: ControlBounds,
) -> Result<(), Refusal> {
    let write = async {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    };
    write
        .await
        .map_err(|e| Refusal::Step(format!("writing the control socket ({e})")))
}

/// The helper's request for a fetch: `{"fetch_start": true}`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchStart {
    fetch_start: bool,
}

/// The helper's report that the fetch ended: `{"fetch_done": true}`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    let start: FetchStart = parse(
        &read_line(&mut read, bounds.frame, bounds).await?,
        "fetch_start",
    )?;
    if !start.fetch_start {
        return Err(Refusal::Step("the sandbox sent fetch_start false".into()));
    }
    let credential = proxy.begin_fetch(deadline)?;
    // Revokes on every way out of here, an error or a dropped future
    // included, so a helper that dies mid-fetch leaves no live credential.
    let fetch = Revoking {
        proxy,
        credential: credential.clone(),
    };
    let deadline_ms = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .as_millis();
    let issued = serde_json::to_string(&Issued {
        credential: credential.secret(),
        deadline_ms,
    })
    .map_err(|e| Refusal::Step(format!("encoding the credential line ({e})")))?;
    write_line(&mut write, &issued, bounds).await?;
    let first = deadline.saturating_duration_since(tokio::time::Instant::now());
    let done: FetchDone = parse(&read_line(&mut read, first, bounds).await?, "fetch_done")?;
    if !done.fetch_done {
        return Err(Refusal::Step("the sandbox sent fetch_done false".into()));
    }
    // The revoke returns only once every tunnel of the credential is shut.
    drop(fetch);
    write_line(&mut write, r#"{"expired":true}"#, bounds).await?;
    Ok(())
}

/// The fetch's credential, revoked when this drops.
struct Revoking<'a> {
    proxy: &'a AllowlistProxy,
    credential: Credential,
}

impl Drop for Revoking<'_> {
    fn drop(&mut self) {
        self.proxy.revoke(&self.credential);
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
