// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7939 test support: a backend failure whose gateway hint is long enough
//! to fingerprint, and that hint's own text, shared by the unit and route
//! tests; and (MIK-7994) prose no part of which matches another.

use serde_json::Value;

/// A backend's tool-level failure around `prose`. The status in it makes
/// the gateway's hint a `BackendError` one, whose advice is long enough
/// for [`own_hint_text`].
pub(crate) fn backend_failure(prose: &str) -> String {
    format!("{prose} The press answered 503 Service Unavailable.")
}

/// The longest text of the `recovery` hint in `answer` (its tool value,
/// read decoded when wrapped) that is none of `backend` and long enough
/// that a receipt holding it would be found: a shared run of
/// `K + 2W - 1` = 79 chars meets the default `min_matches` of 2, so a
/// "not receipted" assertion on it cannot pass for being too short.
pub(crate) fn own_hint_text(answer: &Value, backend: &str) -> String {
    let value = answer["content"][0]["text"]
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(|decoded| decoded.get("recovery").is_some())
        .unwrap_or_else(|| answer.clone());
    let hint = value["recovery"].to_string();
    hint.split('"')
        .filter(|piece| {
            piece.chars().count() >= 79
                && !backend.contains(*piece)
                && !piece.contains(&backend[..40])
        })
        .max_by_key(|piece| piece.len())
        .unwrap_or_else(|| panic!("base: the gateway attached a hint of its own: {answer}"))
        .to_owned()
}

/// `len` bytes of words that never repeat, so no 48-char fingerprint window
/// of one part of the text matches another part.
pub(crate) fn distinct_prose(len: usize) -> String {
    let mut text = String::new();
    let mut n: u64 = 1;
    while text.len() < len {
        n = n.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        // The high bits: an LCG's low bits cycle within 256 steps.
        let mut bits = n >> 34;
        let word: String = (0..6)
            .map(|_| {
                let letter = b'a' + u8::try_from(bits % 26).unwrap_or(0);
                bits /= 26;
                char::from(letter)
            })
            .collect();
        text.push_str(&word);
        text.push(' ');
    }
    text.truncate(len);
    text
}
