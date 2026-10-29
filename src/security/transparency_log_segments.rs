// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: segment files beside the active log, the `.hwm` high-water mark and
//! the disk-full reserve. Pure file helpers; the chain logic stays in the
//! parent module.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::{HmacSha256, MAX_TAIL_SCAN_BYTES, sha256_raw, sig_message};
use hmac::{KeyInit, Mac};

/// Digits in a sealed segment's suffix; lexical order is numeric order.
const SEQ_DIGITS: usize = 20;
/// Written length of `<path>.hwm`; any other length is a torn file.
pub(crate) const HWM_LEN: usize = 200;
/// Size of `<path>.reserve`, written (never sparse).
pub(crate) const RESERVE_BYTES: usize = 1024 * 1024;

/// A sealed segment: `<path>.<20 digits>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The number in the file name.
    pub seq: u64,
    /// Where the file is.
    pub path: PathBuf,
}

/// `<path>.<seq>` with the zero-padded 20-digit suffix.
#[must_use]
pub fn sealed_path(path: &Path, seq: u64) -> PathBuf {
    sibling(path, &format!("{seq:0SEQ_DIGITS$}"))
}

/// An I/O error from the log, named: the operation, the path, the cause.
#[derive(Debug)]
struct Named {
    text: String,
    source: io::Error,
}

impl std::fmt::Display for Named {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Named {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Name `op` and `path` in an I/O error the log returns, keeping its kind
/// (callers and the degraded-cause mapping read the kind). Already-named
/// errors pass through unchanged.
pub(crate) fn ctx<'a>(op: &'a str, path: &'a Path) -> impl FnOnce(io::Error) -> io::Error + 'a {
    move |e| {
        if e.get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<Named>)
        {
            return e;
        }
        let text = format!("audit log: {op} {}: {e}", path.display());
        io::Error::new(e.kind(), Named { text, source: e })
    }
}

/// `<path>.<suffix>`.
pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// The number the next segment takes: one past the newest sealed one, or 0.
/// A sealed segment at the last number is refused rather than wrapped or
/// saturated onto, either of which would seal over a segment (MIK-7949).
///
/// # Errors
///
/// `InvalidData` when the newest sealed segment holds `u64::MAX`.
pub(crate) fn next_seq(sealed: &[Segment]) -> io::Result<u64> {
    sealed.last().map_or(Ok(0), |newest| {
        newest.seq.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "audit log: sealed segment {} is the last number, so no segment can follow it; \
                     a renamed or planted segment file is for the operator to resolve",
                    newest.seq
                ),
            )
        })
    })
}

/// Every sealed segment of the log at `path`, oldest first. Matches exactly
/// `<file name>.` plus 20 ASCII digits, so `.lock`, `.hwm`, `.reserve` and
/// operator copies (`.bak`, `.7`) are never read as segments. The one
/// discovery rule for the logger, verify, the exporter and the readers.
///
/// # Errors
///
/// The directory cannot be listed (a missing directory is an empty list).
pub fn list_segments(path: &Path) -> io::Result<Vec<Segment>> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Some(base) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(Vec::new());
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ctx("list", &dir)(e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(ctx("list", &dir))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(base).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        if rest.len() == SEQ_DIGITS
            && rest.bytes().all(|b| b.is_ascii_digit())
            && let Ok(seq) = rest.parse::<u64>()
        {
            out.push(Segment {
                seq,
                path: dir.join(name),
            });
        }
    }
    out.sort_by_key(|s| s.seq);
    Ok(out)
}

/// `fsync` the directory holding `path`, so a rename, create or unlink is
/// durable. Unix only; elsewhere a no-op.
#[cfg_attr(
    not(unix),
    expect(
        clippy::unnecessary_wraps,
        reason = "a no-op off unix that keeps the unix signature"
    )
)]
pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let dir = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(ctx("sync", dir))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The first non-empty line of `path`, read through a 4 MiB window.
pub(crate) fn read_first_line(path: &Path) -> io::Result<Option<String>> {
    read_first_line_raw(path).map_err(ctx("read", path))
}

fn read_first_line_raw(path: &Path) -> io::Result<Option<String>> {
    first_line_in(&File::open(path)?)
}

/// The first non-empty line of an open `file`, read from its start through
/// the same 4 MiB window as [`read_first_line`].
fn first_line_in(mut file: &File) -> io::Result<Option<String>> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.take(MAX_TAIL_SCAN_BYTES).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(str::to_string))
}

/// The segment number the active file at `path` holds: the one its open
/// record names, or, for a pre-D6 log with no open record, `after` (the
/// newest sealed + 1, or 0). The open record decides because retention or
/// the disk-full path can leave no sealed sibling to count from.
pub(crate) fn active_segment_seq(path: &Path, after: u64) -> u64 {
    read_first_line(path)
        .ok()
        .flatten()
        .and_then(|l| opened_seq(&l))
        .unwrap_or(after)
}

/// [`active_segment_seq`] for a file already open, read through that
/// descriptor: a reader checking which segment it opened by the active name.
pub(crate) fn segment_seq_in(file: &File, after: u64) -> io::Result<u64> {
    Ok(first_line_in(file)?
        .and_then(|l| opened_seq(&l))
        .unwrap_or(after))
}

/// One snapshot of a log's files for a reader resolving where to read.
pub(crate) struct Listing {
    /// The sealed segments, oldest first.
    pub(crate) sealed: Vec<Segment>,
    /// The active file's segment, `None` when there is no active file.
    pub(crate) active: Option<u64>,
    /// The number after the newest sealed segment: the active file's number
    /// when it has no open record, and the newest when it is absent.
    next: u64,
}

impl Listing {
    /// The newest segment: the active file's, or with none, the number the
    /// next file takes, whose page is empty and steps to the sealed ones.
    pub(crate) fn newest(&self) -> u64 {
        self.active.unwrap_or(self.next)
    }

    /// Whether the log had any file when listed. A log never written has
    /// none; one whose files went later must not read as never written.
    pub(crate) fn seen(&self) -> bool {
        self.active.is_some() || !self.sealed.is_empty()
    }

    /// Whether `seq` lies in the kept range, from the oldest sealed segment
    /// (or the newest, with none sealed) up to the newest.
    pub(crate) fn kept(&self, seq: u64) -> bool {
        let oldest = self.sealed.first().map_or(self.newest(), |s| s.seq);
        (oldest..=self.newest()).contains(&seq)
    }
}

/// List `path`'s files: the sealed segments first, then the active file.
/// That order means a rotation between the two reads shows the new active
/// file under a number above every listed segment, never a sealed segment
/// as the newest; a sealed list that changed meanwhile is listed again.
///
/// # Errors
///
/// The directory or the active file cannot be read, the newest sealed
/// segment holds the last number ([`next_seq`]), or the log rotated during
/// three listings in a row (`Interrupted`).
pub(crate) fn listing(path: &Path) -> io::Result<Listing> {
    // A rotation between the two reads (the live file renamed to its sealed
    // name, the next not yet created) would leave the just-sealed segment in
    // neither: listing the sealed segments again shows whether one moved.
    for _ in 0..3 {
        let sealed = list_segments(path)?;
        let next = next_seq(&sealed)?;
        #[cfg(test)]
        super::pager::seam::fire_sealed_listed();
        let active = match File::open(path) {
            Ok(file) => Some(segment_seq_in(&file, next)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let moved = list_segments(path)?
            .iter()
            .map(|s| s.seq)
            .ne(sealed.iter().map(|s| s.seq));
        if !moved {
            return Ok(Listing {
                sealed,
                active,
                next,
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "log rotated during listing three times in a row; retry",
    ))
}

/// The segment number an open record line names.
fn opened_seq(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .filter(|v| {
            v.get("event").and_then(serde_json::Value::as_str) == Some("audit_segment_opened")
        })
        .and_then(|v| v.get("segment_seq").and_then(serde_json::Value::as_u64))
}

/// High-water mark: how far the log got, kept outside the active file so a
/// deleted or truncated active segment is detected (D6 2.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighWater {
    /// Counter of the last appended record.
    pub counter: u64,
    /// Its `entry_hash`.
    pub entry_hash: String,
    /// The segment it went into.
    pub segment_seq: u64,
}

fn hwm_mac(hw: &HighWater, secret: &[u8], key_id: &str) -> String {
    let digest =
        sha256_raw(format!("hwm|{}|{}|{}", hw.counter, hw.entry_hash, hw.segment_seq).as_bytes());
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&sig_message(&digest, key_id));
    hex::encode(mac.finalize().into_bytes())
}

/// Serialise `hw` to its fixed-length form; the MAC is empty without a secret.
///
/// # Errors
///
/// `InvalidData` naming the length when the mark does not fit the fixed
/// width (an over-long `entry_hash` from a corrupt tail), rather than writing
/// a file every reader would then treat as missing.
pub(crate) fn encode_hwm(hw: &HighWater, secret: &[u8], key_id: &str) -> io::Result<Vec<u8>> {
    let mac = if secret.is_empty() {
        String::new()
    } else {
        hwm_mac(hw, secret, key_id)
    };
    let body = format!(
        "{}\t{}\t{}\t{mac}",
        hw.counter, hw.entry_hash, hw.segment_seq
    );
    let mut out = body.into_bytes();
    if out.len() > HWM_LEN - 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "audit high-water mark is {} bytes, over its {}-byte width: the log tail's \
                 entry_hash is malformed",
                out.len(),
                HWM_LEN - 1
            ),
        ));
    }
    out.resize(HWM_LEN - 1, b' ');
    out.push(b'\n');
    Ok(out)
}

/// Write `hw` over `<path>.hwm` at offset 0 (one write, fixed length).
pub(crate) fn write_hwm(path: &Path, bytes: &[u8], sync: bool) -> io::Result<()> {
    let hwm = sibling(path, "hwm");
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&hwm)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            if sync { f.sync_all() } else { Ok(()) }
        })
        .map_err(ctx("write", &hwm))
}

/// Read `<path>.hwm`. `None` when it is missing, torn (wrong length),
/// unparseable, or (with a secret) fails its MAC: all count as missing.
#[must_use]
pub fn read_hwm(path: &Path, secret: &[u8], key_id: &str) -> Option<HighWater> {
    let raw = std::fs::read(sibling(path, "hwm")).ok()?;
    parse_hwm(&raw, secret, key_id).map(|(hw, _)| hw)
}

/// Parse one `.hwm` image, and whether it carries a MAC. `None` when torn,
/// unparseable, or (with a secret) failing its MAC.
pub(crate) fn parse_hwm(raw: &[u8], secret: &[u8], key_id: &str) -> Option<(HighWater, bool)> {
    if raw.len() != HWM_LEN {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.trim_end().split('\t');
    let hw = HighWater {
        counter: parts.next()?.parse().ok()?,
        entry_hash: parts.next()?.to_string(),
        segment_seq: parts.next()?.parse().ok()?,
    };
    let mac = parts.next().unwrap_or("");
    if !secret.is_empty() {
        let want = hwm_mac(&hw, secret, key_id);
        let ok: bool = bool::from(subtle::ConstantTimeEq::ct_eq(
            want.as_bytes(),
            mac.as_bytes(),
        ));
        if !ok {
            return None;
        }
    }
    Some((hw, !mac.is_empty()))
}

/// Create `<path>.reserve` as 1 MiB of written bytes (a sparse file would
/// reserve nothing), unless it is already whole.
pub(crate) fn ensure_reserve(path: &Path) -> io::Result<()> {
    let reserve = sibling(path, "reserve");
    if std::fs::metadata(&reserve).is_ok_and(|m| m.len() == RESERVE_BYTES as u64) {
        return Ok(());
    }
    let mut f = File::create(&reserve)?;
    f.write_all(&vec![0u8; RESERVE_BYTES])?;
    f.sync_all()
}

/// Unlink `<path>.reserve`, freeing its space; `false` if it was absent.
pub(crate) fn release_reserve(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(sibling(path, "reserve")) {
        Ok(()) => {
            sync_dir(path)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod hwm_mac_tests {
    use super::*;

    #[test]
    fn the_right_mac_parses() {
        let secret = b"synthetic-hwm-secret-not-real";
        let hw = HighWater {
            counter: 7,
            entry_hash: "ab".repeat(32),
            segment_seq: 2,
        };
        let image = encode_hwm(&hw, secret, "k1").expect("encodes");
        let parsed = parse_hwm(&image, secret, "k1");
        assert!(
            matches!(&parsed, Some((got, true)) if got.counter == 7),
            "the right mac parses: {parsed:?}"
        );
    }

    #[test]
    fn a_wrong_mac_is_refused() {
        let secret = b"synthetic-hwm-secret-not-real";
        let hw = HighWater {
            counter: 7,
            entry_hash: "ab".repeat(32),
            segment_seq: 2,
        };
        let image = encode_hwm(&hw, secret, "k1").expect("encodes");
        let mut bad = image.clone();
        let tabs: Vec<usize> = image
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\t')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(tabs.len(), 3, "the hwm image has three tabs");
        let mac_start = tabs[2] + 1;
        let orig = bad[mac_start];
        bad[mac_start] = if orig == b'a' { b'b' } else { b'a' };
        assert_eq!(bad.len(), HWM_LEN, "flipping keeps the length");
        assert!(
            parse_hwm(&bad, secret, "k1").is_none(),
            "a flipped mac is refused"
        );
    }

    #[test]
    fn a_short_mac_is_refused() {
        let secret = b"synthetic-hwm-secret-not-real";
        let hw = HighWater {
            counter: 7,
            entry_hash: "ab".repeat(32),
            segment_seq: 2,
        };
        let image = encode_hwm(&hw, secret, "k1").expect("encodes");
        assert_eq!(image.len(), HWM_LEN);
        let full_mac = hwm_mac(&hw, secret, "k1");
        let short = full_mac[..10].to_owned();
        let body = format!(
            "{}\t{}\t{}\t{short}",
            hw.counter, hw.entry_hash, hw.segment_seq
        );
        let mut image2 = body.into_bytes();
        image2.resize(HWM_LEN - 1, b' ');
        image2.push(b'\n');
        assert_eq!(image2.len(), HWM_LEN);
        assert!(
            parse_hwm(&image2, secret, "k1").is_none(),
            "a short mac is refused"
        );
    }
}
