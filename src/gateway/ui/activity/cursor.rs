// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The page token: both logs' positions, MAC'd with a key this process holds
//! only in memory, so a client cannot point the reader at an offset of its
//! choosing. A token from another process, or altered, decodes as nothing and
//! the reader restarts from the newest line.

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::reader::Cursor;

/// This process's token key. A restart makes every earlier token unreadable,
/// which reads as a reset, never as an error.
static KEY: LazyLock<[u8; 32]> = LazyLock::new(rand::random);

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    /// What the token is bound to (the key-server lookup binds its safe
    /// filter, never the email); `None` for Activity's own tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind: Option<String>,
    #[serde(flatten)]
    cursor: Cursor,
}

pub(super) fn encode(cursor: &Cursor) -> String {
    encode_with(&*KEY, cursor, None)
}

pub(super) fn decode(token: &str) -> Option<Cursor> {
    decode_with(&*KEY, token)
        .filter(|(_, bind)| bind.is_none())
        .map(|(c, _)| c)
}

/// A token for `cursor` bound to `bind`: it decodes only for the same bind.
pub(super) fn encode_bound(cursor: &Cursor, bind: &str) -> String {
    encode_with(&*KEY, cursor, Some(bind))
}

/// The cursor of `token` when it is bound to exactly `bind`.
pub(super) fn decode_bound(token: &str, bind: &str) -> Option<Cursor> {
    decode_with(&*KEY, token).and_then(|(c, b)| (b.as_deref() == Some(bind)).then_some(c))
}

fn mac(key: &[u8]) -> Hmac<Sha256> {
    // invariant: HMAC-SHA256 takes a key of any length.
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length")
}

fn encode_with(key: &[u8], cursor: &Cursor, bind: Option<&str>) -> String {
    let body = serde_json::to_vec(&Wire {
        v: 1,
        bind: bind.map(str::to_owned),
        cursor: cursor.clone(),
    })
    // invariant: a cursor is two optional pairs of integers and an optional string; serialising it cannot fail.
    .expect("a cursor serialises");
    let mut m = mac(key);
    m.update(&body);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&body),
        URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
    )
}

fn decode_with(key: &[u8], token: &str) -> Option<(Cursor, Option<String>)> {
    let (body, tag) = token.split_once('.')?;
    let body = URL_SAFE_NO_PAD.decode(body).ok()?;
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    let mut m = mac(key);
    m.update(&body);
    m.verify_slice(&tag).ok()?;
    let wire: Wire = serde_json::from_slice(&body).ok()?;
    (wire.v == 1).then_some((wire.cursor, wire.bind))
}

#[cfg(test)]
mod tests {
    use super::super::reader::LogPos;
    use super::*;

    fn cursor() -> Cursor {
        Cursor {
            inv: Some(LogPos {
                segment: 3,
                offset: 1234,
            }),
            gov: None,
            gov_bound: Some("2026-10-26T10:00:00+00:00".into()),
        }
    }

    #[test]
    fn a_token_round_trips_under_its_key() {
        let key = [7u8; 32];
        assert_eq!(
            decode_with(&key, &encode_with(&key, &cursor(), None)),
            Some((cursor(), None))
        );
    }

    #[test]
    fn a_flipped_byte_or_another_key_decodes_as_nothing() {
        let key = [7u8; 32];
        let token = encode_with(&key, &cursor(), None);
        assert_eq!(
            decode_with(&[8u8; 32], &token),
            None,
            "another process's key"
        );
        for i in 0..token.len() {
            let mut bytes = token.clone().into_bytes();
            bytes[i] = if bytes[i] == b'Q' { b'R' } else { b'Q' };
            let flipped = String::from_utf8(bytes).unwrap();
            if flipped != token {
                assert_eq!(decode_with(&key, &flipped), None, "byte {i} flipped");
            }
        }
    }

    #[test]
    fn a_token_naming_a_chosen_offset_without_the_key_is_refused() {
        let body = URL_SAFE_NO_PAD.encode(br#"{"v":1,"inv":{"segment":0,"offset":5},"gov":null}"#);
        let forged = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert_eq!(decode(&format!("{body}.{forged}")), None);
    }
}
