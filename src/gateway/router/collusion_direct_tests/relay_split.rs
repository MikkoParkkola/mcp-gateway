// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 copies split mid-word over short fields (A3c), and the
//! same-source excuse for a caller delivered such a copy (MIK-7773).

use super::*;

/// `text` cut into pieces of about 20 chars, every cut inside a word, so
/// every k-gram of the pieces joined by a separator crosses that separator.
pub(super) fn split_mid_word(text: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut prev = ' ';
    for c in text.chars() {
        let len = fields.last().map_or(0, |f| f.chars().count());
        if len >= 20 && !c.is_whitespace() && !prev.is_whitespace() {
            fields.push(String::new());
        }
        fields.last_mut().expect("one field").push(c);
        prev = c;
    }
    fields
}

/// `pieces` as one object, under keys that sort in piece order.
pub(super) fn fields(pieces: &[String]) -> Value {
    let fields = pieces.iter().enumerate();
    Value::Object(
        fields
            .map(|(i, f)| (format!("p{i:03}"), Value::String(f.clone())))
            .collect(),
    )
}

/// MIK-7773 `RELAY-SPLIT-FP.1`: B was delivered the copy already split
/// mid-word over short fields, from the same source A read it flat from.
/// B forwarding those pieces sends its own copy, so it is not refused
/// under `block`. Refused without B's read: A3c.
#[tokio::test]
async fn a_callers_own_split_copy_excuses_it() {
    let fx = fixture(Setup::default()).await;
    fx.read(Some("a")).await;
    let pieces = split_mid_word(PROSE);
    fx.answer_read(Read::Pieces(pieces.clone()));
    fx.read(Some("b")).await;
    let forward = call("send", &fields(&pieces), None, None);
    assert_sent(&fx, &fx.call(Some("b"), &forward).await, 1);
}
