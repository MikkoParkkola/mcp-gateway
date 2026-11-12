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
const VECTORS: [(&str, &str, &str); 8] = [
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
    // Lowercasing makes t + U+0308, which the final NFC composes to U+1E97.
    (
        "T\u{308}om",
        "e1ba976f6d406578616d706c652e636f6d",
        "5d6b150ffd8a1170cace0ea8ee8cd597166fc98dcecc424cb3564b12d40ad43d",
    ),
    // U+0130 lowercases to i + U+0307 ahead of U+0316, which the final NFC
    // reorders by combining class.
    (
        "\u{130}\u{316}nci",
        "69cc96cc876e6369406578616d706c652e636f6d",
        "b9d01598097fcdfe2d0b600f14fa663a2d5fb2291c9b49068f854205ca2e4fc9",
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

/// The final NFC pass matters: without it these two give other bytes.
#[test]
fn the_final_nfc_pass_composes_and_reorders() {
    let one = super::normalize(&format!("T\u{308}om{DOMAIN}"));
    assert!(one.starts_with('\u{1e97}'), "{one:?}");
    let two = super::normalize(&format!("\u{130}\u{316}nci{DOMAIN}"));
    assert!(two.starts_with("i\u{316}\u{307}"), "{two:?}");
}

/// Normalization v1's tables are pinned: lowercase from the standard
/// library at Unicode 17.0.0, NFC from `icu_normalizer_data`
/// 2.3.0 (built from ICU 78). A toolchain or lock-file change that moves
/// either fails here, and moving them means a new normalization version.
#[test]
fn normalization_v1_tables_are_pinned() {
    assert_eq!(
        char::UNICODE_VERSION,
        (17, 0, 0),
        "the toolchain's lowercase tables moved off Unicode 17.0.0"
    );
    let lock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )
    .expect("Cargo.lock")
    .replace('\r', "");
    assert!(
        lock.contains("name = \"icu_normalizer_data\"\nversion = \"2.3.0\"\n"),
        "icu_normalizer_data moved off 2.3.0 (normalization v1's NFC data)"
    );
}

/// Regenerates `email_hash/case_v1.rs` from the standard library. Run it only
/// on the Unicode 17.0.0 toolchain, by hand:
/// `cargo test --lib generate_case_v1_table -- --ignored --nocapture`, and
/// paste what it prints between the markers over the file. It refuses any
/// other Unicode version.
///
/// Three tables. The per-code-point lowercase is `char::to_lowercase`. The two
/// range tables are what `str::to_lowercase`'s final-sigma rule depends on,
/// read back from the standard library itself: lowercasing `c` + capital
/// Sigma ends in final sigma exactly when `c` is cased and not case-ignorable
/// (`CASED_TERMINAL`); lowercasing `A` + `c` + capital Sigma ends in final sigma
/// when `c` is case-ignorable or cased, so case-ignorable alone is the second
/// minus the first (`CASE_IGNORABLE`).
#[test]
#[ignore = "a generator, run by hand on the Unicode 17.0.0 toolchain"]
fn generate_case_v1_table() {
    assert_eq!(
        char::UNICODE_VERSION,
        (17, 0, 0),
        "not the Unicode 17 toolchain"
    );
    let all = || (0..=0x10_FFFF_u32).filter_map(char::from_u32);
    let mut lower: Vec<(u32, [u32; 3])> = Vec::new();
    let mut ignorable: Vec<u32> = Vec::new();
    let mut terminal: Vec<u32> = Vec::new();
    for c in all() {
        let mapped: Vec<u32> = c.to_lowercase().map(u32::from).collect();
        if mapped != [u32::from(c)] {
            assert!(
                (1..=3).contains(&mapped.len()),
                "{c:?} maps to {} scalars",
                mapped.len()
            );
            assert!(mapped.iter().all(|&v| v != 0), "{c:?} maps to U+0000");
            let mut out = [0_u32; 3];
            out[..mapped.len()].copy_from_slice(&mapped);
            lower.push((u32::from(c), out));
        }
        let final_after = |text: String| text.to_lowercase().ends_with('\u{3c2}');
        let f1 = final_after(format!("{c}\u{3a3}"));
        let f2 = final_after(format!("A{c}\u{3a3}"));
        if f1 {
            terminal.push(u32::from(c));
        }
        if f2 && !f1 {
            ignorable.push(u32::from(c));
        }
    }
    let ranges = |points: &[u32]| -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        for &p in points {
            match out.last_mut() {
                Some(last) if last.1 + 1 == p => last.1 = p,
                _ => out.push((p, p)),
            }
        }
        out
    };
    let mut text = String::from(
        "// SPDX-FileCopyrightText: 2026 Mikko Parkkola\n\
         // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0\n\
         //! Normalization v1's lowercase, frozen at Unicode 17.0.0: the per-code-point\n\
         //! lowercase, and the two range tables behind the final-sigma rule. Generated by\n\
         //! `generate_case_v1_table` (src/key_server/email_hash_tests.rs) from the\n\
         //! standard library on the Unicode 17.0.0 toolchain. Never edit by hand: the\n\
         //! digest row in the tests pins these entries, and changing one needs a new\n\
         //! normalization version.\n\n",
    );
    text.push_str(&format!(
        "pub(super) static LOWER_V1: [(u32, [u32; 3]); {}] = [\n",
        lower.len()
    ));
    for (key, out) in &lower {
        text.push_str(&format!(
            "    ({key:#x}, [{:#x}, {:#x}, {:#x}]),\n",
            out[0], out[1], out[2]
        ));
    }
    text.push_str("];\n\n");
    for (name, points) in [
        ("CASE_IGNORABLE", &ignorable),
        ("CASED_TERMINAL", &terminal),
    ] {
        let r = ranges(points);
        text.push_str(&format!(
            "pub(super) static {name}: [(u32, u32); {}] = [\n",
            r.len()
        ));
        for (lo, hi) in &r {
            text.push_str(&format!("    ({lo:#x}, {hi:#x}),\n"));
        }
        text.push_str("];\n\n");
    }
    text.push_str(include_str!("email_hash/case_v1_helpers.txt"));
    println!("BEGIN-TABLE\n{text}END-TABLE");
}
