// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7713: `audit verify --anchor`. Nothing on the host proves a log once
//! existed after its files are cut back and `.hwm` is rewritten to match, so
//! the operator keeps a copy of `.hwm` off the host and the log must still
//! hold the record it names. Also the checked `+ 1` every record-supplied
//! counter goes through (MIK-7944 finding 5).

use std::io::{self, Read};
use std::path::Path;

use super::TransparencyLogConfig;
use super::segments::{self, HWM_LEN, HighWater};
use super::verify::{VerifyMode, VerifyResult, verify_pinned};

/// The one library entry point for `audit verify`: the whole log at `path`,
/// across its sealed segments, in `mode`, with the per-entry HMAC checked
/// when `config` carries a secret (D6 2.5), and against `anchor`, an
/// off-host copy of `<path>.hwm`, when given (MIK-7713).
///
/// # Errors
///
/// `InvalidData` when the anchor is unreadable, torn, fails its MAC, or is
/// signed while no secret is configured; `NotFound` when neither the log nor
/// any sealed segment exists and no anchor is given; `Interrupted` when the
/// log rotated under the reader twice in a row (retry); any read error.
pub fn verify_audit_log(
    path: &Path,
    config: &TransparencyLogConfig,
    mode: VerifyMode,
    anchor: Option<&Path>,
) -> io::Result<VerifyResult> {
    let pin = anchor.map(|a| read_anchor(a, config)).transpose()?;
    match (verify_pinned(path, config, mode, pin.as_ref()), &pin) {
        // A wiped log is the anchor's first case, not a missing input.
        (Err(e), Some(pin)) if e.kind() == io::ErrorKind::NotFound => Ok(VerifyResult {
            error_at_counter: Some(pin.counter),
            error_message: Some(behind(pin.counter)),
            ..VerifyResult::default()
        }),
        (verdict, _) => verdict,
    }
}

/// Read an anchor through the `.hwm` parser and its MAC check; every
/// failure refuses the verification, never skips the anchor.
fn read_anchor(anchor: &Path, config: &TransparencyLogConfig) -> io::Result<HighWater> {
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("anchor {} {why}", anchor.display()),
        )
    };
    let mut raw = Vec::with_capacity(HWM_LEN + 1);
    std::fs::File::open(anchor)
        .and_then(|f| f.take(HWM_LEN as u64 + 1).read_to_end(&mut raw))
        .map_err(|e| refuse(&format!("is unreadable: {e}")))?;
    let secret = config.shared_secret.as_bytes();
    let (hw, signed) = segments::parse_hwm(&raw, secret, &config.key_id)
        .ok_or_else(|| refuse("is unreadable or fails its MAC"))?;
    // Without a secret the MAC is not checked, so a signed log stripped of
    // its signatures would pass hash-only against its signed anchor.
    if signed && secret.is_empty() {
        return Err(refuse("is signed: verify with the log's secret"));
    }
    Ok(hw)
}

fn behind(counter: u64) -> String {
    format!(
        "log behind its anchor: counter {counter} not found; the log was wiped, rolled back or \
         replaced"
    )
}

/// The record the stream walked at the anchor's counter, and the expired
/// boundary (`last_counter`, `final_hash`) the oldest survivor verifiably
/// links to.
pub(super) struct Walked<'a> {
    pub(super) last: Option<u64>,
    pub(super) at_pin: Option<&'a str>,
    pub(super) boundary: Option<(u64, &'a str)>,
    /// Every record's HMAC was checked, so the expiry record naming the
    /// boundary is authenticated.
    pub(super) signed: bool,
}

/// The anchor rule, both modes. An anchor inside an expired range is
/// refused rather than passed with a warning. The expired boundary stands in
/// for the anchored record only in a signed log: without HMAC an attacker
/// who wiped the log can forge an open record and an expiry record naming
/// the anchored counter and hash.
pub(super) fn check_anchor(
    pin: &HighWater,
    walked: &Walked<'_>,
) -> Result<(), (Option<u64>, String)> {
    let n = pin.counter;
    let at_boundary = walked.boundary.filter(|(c, _)| *c == n).map(|(_, h)| h);
    if walked.at_pin.is_none() && at_boundary.is_some() && !walked.signed {
        return Err((
            Some(n),
            format!(
                "the anchored record at counter {n} has expired, and an unsigned log cannot \
                 prove its expiry: verify with a newer anchor"
            ),
        ));
    }
    match walked.at_pin.or(at_boundary) {
        Some(h) if h == pin.entry_hash => Ok(()),
        Some(_) => Err((
            Some(n),
            format!(
                "record at the anchor's counter {n} is not the anchored one: the log was replaced"
            ),
        )),
        None if walked.last.is_none_or(|l| n > l) => Err((Some(n), behind(n))),
        None => Err((
            Some(n),
            format!(
                "the anchor at counter {n} predates the retained range; verify with a newer anchor"
            ),
        )),
    }
}

/// `n + 1` for a counter or segment number a record or file name supplies:
/// `u64::MAX` is a failed verdict located at `at`, never a panic or a wrap.
pub(super) fn succ(n: u64, at: Option<u64>) -> Result<u64, (Option<u64>, String)> {
    n.checked_add(1).ok_or_else(|| {
        (
            at,
            format!("counter overflow past {n}: a record names u64::MAX"),
        )
    })
}
