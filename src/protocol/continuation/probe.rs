// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Finds a gateway-held continuation envelope inside a value bound for a
//! backend (MIK-8323).
//!
//! An envelope is a secret between the gateway and the client it was minted
//! for. A playbook step whose arguments would carry one to another backend is
//! refused; this is the check that says whether they would.
//!
//! Only an envelope THIS gateway can open counts: a foreign, expired or merely
//! envelope-shaped string is ordinary data. Opening costs an AEAD attempt, so
//! two bounds keep a hostile value from turning the check into work:
//! - a framing gate (length, then the version and a held kid decoded from the
//!   first four characters, without allocating) rejects almost everything
//!   before any open;
//! - a per-step budget caps the opens; the candidate after the last one is
//!   refused rather than let through (fail closed).

use serde_json::Value;

use super::{Keyring, MAX_ENVELOPE_LEN, NONCE_LEN, VERSION};

/// The opens one playbook step may spend before its arguments are refused.
pub(crate) const PROBE_OPENS_PER_STEP: usize = 16;

/// The shortest string that could be an envelope: the base64url length of a
/// header, nonce, tag and one byte of plaintext. Conservative: a real payload
/// is far longer, and a shorter bound only costs a gate comparison.
const MIN_ENVELOPE_LEN: usize = ((2 + NONCE_LEN + 16 + 1) * 4).div_ceil(3);

/// The opens left for one step's arguments.
#[derive(Debug)]
pub struct ProbeBudget {
    left: usize,
    spent: usize,
}

impl ProbeBudget {
    /// A budget of `opens` envelope opens.
    #[must_use]
    pub const fn new(opens: usize) -> Self {
        Self {
            left: opens,
            spent: 0,
        }
    }

    /// The opens spent so far.
    #[must_use]
    pub const fn spent(&self) -> usize {
        self.spent
    }
}

/// Why the probe could not answer, so the value is refused (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRefusal {
    /// The value framed more envelope candidates than the budget could open.
    TooManyCandidates,
    /// The clock could not be read, so a candidate could not be judged. Read
    /// as "not ours" it would let a live envelope through while the clock is
    /// wrong.
    ClockUnreadable,
}

/// Whether `value` carries an envelope `keyring` opens, anywhere: a whole
/// string, any maximal base64url run inside one, an object key, at any depth.
///
/// # Errors
///
/// [`ProbeRefusal`] when a framed candidate is found with no opens left, or
/// the clock cannot be read to judge one.
pub fn sealed_state_in(
    keyring: &Keyring,
    value: &Value,
    budget: &mut ProbeBudget,
) -> Result<bool, ProbeRefusal> {
    scan(keyring, value, budget, &|| crate::clock::unix_secs().ok())
}

/// [`sealed_state_in`] against `clock`, read only for a framed candidate.
fn scan(
    keyring: &Keyring,
    value: &Value,
    budget: &mut ProbeBudget,
    clock: &dyn Fn() -> Option<u64>,
) -> Result<bool, ProbeRefusal> {
    match value {
        Value::String(text) => text_carries(keyring, text, budget, clock),
        Value::Array(items) => {
            for item in items {
                if scan(keyring, item, budget, clock)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Object(map) => {
            for (key, item) in map {
                if text_carries(keyring, key, budget, clock)? || scan(keyring, item, budget, clock)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(false),
    }
}

/// The candidates are the maximal base64url runs of `text`; a string that is
/// all base64url is its own single run, so it is opened once, not twice.
fn text_carries(
    keyring: &Keyring,
    text: &str,
    budget: &mut ProbeBudget,
    clock: &dyn Fn() -> Option<u64>,
) -> Result<bool, ProbeRefusal> {
    for run in text.split(|c: char| !is_base64url(c)) {
        if !framed(keyring, run) {
            continue;
        }
        if budget.left == 0 {
            return Err(ProbeRefusal::TooManyCandidates);
        }
        budget.left -= 1;
        budget.spent += 1;
        let now = clock().ok_or(ProbeRefusal::ClockUnreadable)?;
        if keyring.open(run, now).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

const fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// The gate: a plausible length, then the version byte and a held kid. Four
/// characters decode to exactly three bytes; three characters would leave two
/// nonce bits in the second byte, so the kid would compare wrong.
fn framed(keyring: &Keyring, run: &str) -> bool {
    if !(MIN_ENVELOPE_LEN..=MAX_ENVELOPE_LEN).contains(&run.len()) {
        return false;
    }
    let Some(head) = run.as_bytes().get(..4) else {
        return false;
    };
    let mut bits: u32 = 0;
    for &c in head {
        let Some(sextet) = sextet(c) else {
            return false;
        };
        bits = (bits << 6) | u32::from(sextet);
    }
    let [_, version, kid, _] = bits.to_be_bytes();
    version == VERSION && keyring.holds_kid(kid)
}

/// The base64url (RFC 4648 §5) value of one character.
const fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
