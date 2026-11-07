// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` pairs settle records (MIK-9318 step 3): each intent with
//! its terminal record, by token and role, over the records the chain check
//! already verified. Findings name a token, a role, a rule and counters,
//! never a payload value; tokens stay raw here, and the CLI escapes them.

use serde_json::Value;

/// What pairing found over one verified stream.
#[derive(Debug, Default)]
pub(super) struct Findings {
    /// The first pairing failure: the deciding record's counter, and a
    /// message naming the rule and the token.
    pub(super) failure: Option<(u64, String)>,
    /// Findings that do not fail the verdict.
    pub(super) warnings: Vec<String>,
    /// Information lines: expired intents, legacy intents.
    pub(super) notes: Vec<String>,
}

/// Pairing state over the records of one stream, fed in order.
#[derive(Debug, Default)]
pub(super) struct Pairing {}

impl Pairing {
    /// Take one verified record at `counter`.
    #[expect(clippy::unused_self, reason = "the typed stub pairs nothing yet")]
    pub(super) fn observe(&mut self, entry: &Value, counter: u64) {
        let _ = (entry, counter);
    }

    /// The findings, given the retention `boundary`: the counter of the
    /// first record of the oldest file streamed.
    #[expect(clippy::unused_self, reason = "the typed stub pairs nothing yet")]
    pub(super) fn finish(self, boundary: Option<u64>) -> Findings {
        let _ = boundary;
        Findings::default()
    }
}
