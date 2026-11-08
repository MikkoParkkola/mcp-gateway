// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The installation key's text rule, key id and HMAC. Expected values were
//! computed independently with Python's `hmac` and `hashlib` over the bytes
//! 0x00..0x1f (and 0x01..0x20 for the second key).

use super::{EmailHashKey, KeyTextError};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KEY2_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
/// sha256(bytes 0x00..0x1f)
const KEY_ID: &str = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
/// sha256 of the 64-character hex TEXT: what the key id must not be.
const TEXT_HASH: &str = "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b";
/// The domain part of every fixture address.
const DOMAIN: &str = concat!("@", "example", ".com");
/// HMAC-SHA256(bytes 0x00..0x1f, "email-v1\0" + normalized) for each input,
/// with the normalized bytes in hex (Python `unicodedata` NFC, `str.lower`).
const VECTORS: [(&str, &str, &str); 6] = [
    (
        "Ada.Lovelace+Audit",
        "6164612e6c6f76656c6163652b6175646974406578616d706c652e636f6d",
        "bdc47c656456fb58d5f738d9d88f65073047549d99d59b88ca5501724ffa07db",
    ),
    (
        "Ren\u{e9}",
        "72656ec3a9406578616d706c652e636f6d",
        "947d9c1f37360d756ca7db3fd41316df7b239c660dd08d3db8834bf40ba22325",
    ),
    (
        "Rene\u{301}",
        "72656ec3a9406578616d706c652e636f6d",
        "947d9c1f37360d756ca7db3fd41316df7b239c660dd08d3db8834bf40ba22325",
    ),
    (
        "\u{130}nci",
        "69cc876e6369406578616d706c652e636f6d",
        "e320cba8b6a9255fa7ddd70f8aa619e4b2d2ae7014fa87f0b62c576abbf2c7a6",
    ),
    (
        "\u{fb01}le",
        "efac816c65406578616d706c652e636f6d",
        "01b605be3b696d78baa295d7787784b5cad4565e9aca89f1f1f793de5fd290b3",
    ),
    (
        "file",
        "66696c65406578616d706c652e636f6d",
        "ed954cc5a5e2070b6513e643395a76a5d1f89791109f9db17f26056dd7e4cf14",
    ),
];

fn key(text: &str) -> EmailHashKey {
    EmailHashKey::from_hex(text).expect("a valid key")
}

#[test]
fn each_vector_normalizes_and_hashes_to_its_known_value() {
    let k = key(KEY_HEX);
    for (local, normalized_hex, hash) in VECTORS {
        let email = format!("{local}{DOMAIN}");
        assert_eq!(
            hex::encode(super::normalize(&email)),
            normalized_hex,
            "{email:?}"
        );
        assert_eq!(k.hash(&email), hash, "{email:?}");
    }
}

/// Canonically equivalent spellings meet; a compatibility form does not.
#[test]
fn equivalent_spellings_meet_and_a_ligature_stays_distinct() {
    let k = key(KEY_HEX);
    let h = |local: &str| k.hash(&format!("{local}{DOMAIN}"));
    assert_eq!(
        h("Ren\u{e9}"),
        h("Rene\u{301}"),
        "NFC joins é and e + accent"
    );
    assert_eq!(
        h("Ada.Lovelace+Audit"),
        h("ada.lovelace+audit"),
        "case folds"
    );
    assert_ne!(
        h("\u{fb01}le"),
        h("file"),
        "NFC keeps the ligature: no NFKC"
    );
}

/// Normalizing twice changes nothing, including after U+0130 lowercases to
/// a decomposed sequence.
#[test]
fn normalization_is_idempotent() {
    for (local, _, _) in VECTORS {
        let once = super::normalize(&format!("{local}{DOMAIN}"));
        assert_eq!(super::normalize(&once), once, "{local:?}");
    }
}

#[test]
fn another_key_gives_another_hash() {
    let email = format!("Ada.Lovelace+Audit{DOMAIN}");
    assert_ne!(key(KEY_HEX).hash(&email), key(KEY2_HEX).hash(&email));
}

#[test]
fn the_key_id_hashes_the_decoded_bytes_not_the_text() {
    let id = key(KEY_HEX).key_id();
    assert_eq!(id, KEY_ID);
    assert_ne!(id, TEXT_HASH);
}

#[test]
fn one_trailing_newline_is_allowed() {
    assert_eq!(key(&format!("{KEY_HEX}\n")).key_id(), KEY_ID);
}

#[test]
fn every_other_text_is_refused_without_echoing_it() {
    let upper = KEY_HEX.to_uppercase();
    let cases: [(String, KeyTextError); 6] = [
        (KEY_HEX[..63].to_owned(), KeyTextError::Length(63)),
        (format!("{KEY_HEX}0"), KeyTextError::Length(65)),
        (upper, KeyTextError::NotLowercaseHex),
        (format!("{KEY_HEX} "), KeyTextError::Length(65)),
        (
            format!("{}\n{}", &KEY_HEX[..32], &KEY_HEX[32..]),
            KeyTextError::Length(65),
        ),
        (
            "correct horse battery staple, a passphrase".to_owned(),
            KeyTextError::Length(42),
        ),
    ];
    for (text, want) in cases {
        let err = EmailHashKey::from_hex(&text).expect_err("refused");
        assert_eq!(err, want, "{text:?}");
        assert!(
            !err.to_string().contains(&text),
            "the error echoes the text"
        );
    }
}

#[test]
fn the_key_debug_shows_no_bytes() {
    let shown = format!("{:?}", key(KEY_HEX));
    assert!(
        !shown.contains("0102") && !shown.contains(KEY_HEX),
        "{shown}"
    );
}
