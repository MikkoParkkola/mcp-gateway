// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7939 test support: a backend failure whose gateway hint is long enough
//! to fingerprint, and that hint's own text, shared by the unit and route
//! tests; and (MIK-7994) prose no part of which matches another.

use serde_json::{Value, json};

/// A backend's tool-level failure around `prose`. The status in it makes
/// the gateway's hint a `BackendError` one, whose advice is long enough
/// for [`own_hint_text`].
pub(crate) fn backend_failure(prose: &str) -> String {
    format!("{prose} The press answered 503 Service Unavailable.")
}

/// The longest text of the `recovery` hint in `answer` (its tool value,
/// read decoded when wrapped) that is none of `backend` and long enough
/// that a receipt holding it would be found: a relay of it is reported under
/// this process's hash key (see [`detectable`]), so a "not receipted"
/// assertion on it never passes for being too short (MIK-8083).
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
                && detectable(piece)
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

/// Whether a relay of `text` is found under this process's hash key: one
/// caller holds it as a delivered result, another forwards it. Fingerprints
/// are a keyed sample of k-grams (MIK-8083), so a short text can keep fewer
/// than `min_matches` under some keys; such a text proves nothing as a probe.
fn detectable(text: &str) -> bool {
    use crate::security::firewall::{
        CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller, ScanType,
    };
    let fw = Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["probe:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    );
    fw.record_delivery(
        RelayCaller::Keyed("holder"),
        "probe",
        "read",
        &json!({ "text": text }),
    );
    let params = json!({ "name": "send", "arguments": { "text": text } });
    fw.check_relay(
        RelayCaller::Keyed("other"),
        "probe",
        "send",
        &params,
        ("s", "other"),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}
