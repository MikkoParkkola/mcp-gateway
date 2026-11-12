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

use super::case_v1::{CASE_IGNORABLE, CASED_TERMINAL, LOWER_V1};
use super::{lower_v1, normalize};

fn all_scalars() -> impl Iterator<Item = char> {
    (0..=0x10_FFFF_u32).filter_map(char::from_u32)
}

/// The frozen tables reproduce the standard library only where it is Unicode
/// 17.0.0, the version they were taken at; on a later toolchain the checked-in
/// tables, not std, decide, and the rows that compare against std stand down.
fn std_is_unicode_17() -> bool {
    char::UNICODE_VERSION == (17, 0, 0)
}

/// NORM.1: for every scalar value, alone, `lower_v1` is exactly the standard
/// library's lowercase at Unicode 17.0.0.
/// Mutant: drop, swap or alter one table entry, or call something else.
#[test]
fn lower_v1_is_std_for_every_code_point_at_unicode_17() {
    if !std_is_unicode_17() {
        return;
    }
    for c in all_scalars() {
        let one = c.to_string();
        assert_eq!(lower_v1(&one), one.to_lowercase(), "U+{:04X}", u32::from(c));
    }
}

/// NORM.1: the final-sigma rule, over every character as a neighbour. For each
/// scalar value `c`, five strings that put `c` before, after or between
/// capital Sigmas lowercase exactly as `str::to_lowercase` does, with no
/// expected differences. This is what freezes Cased and Case_Ignorable.
/// Mutant: drop or add a range in either table.
#[test]
fn final_sigma_matches_std_with_every_character_as_a_neighbour() {
    if !std_is_unicode_17() {
        return;
    }
    for c in all_scalars() {
        for text in [
            format!("{c}\u{3a3}"),
            format!("A{c}\u{3a3}"),
            format!("\u{3a3}{c}"),
            format!("\u{3a3}{c}A"),
            format!("A{c}\u{3a3}{c}A"),
        ] {
            assert_eq!(
                lower_v1(&text),
                text.to_lowercase(),
                "U+{:04X} in {text:?}",
                u32::from(c)
            );
        }
    }
}

/// NORM.1: whole strings over an adversarial alphabet (capital, small and final
/// sigma, case-ignorable punctuation and marks, a cased modifier letter, the
/// dotted capital I, titlecase and Cherokee letters) match std, every
/// combination up to four characters, Sigma in every position.
/// Mutant: any change to the Sigma rule or to a table.
#[test]
fn whole_strings_over_an_adversarial_alphabet_match_std() {
    if !std_is_unicode_17() {
        return;
    }
    let alphabet = [
        "A",
        "a",
        "\u{3a3}",
        "\u{3c3}",
        "\u{3c2}",
        ".",
        "'",
        "-",
        "_",
        " ",
        "1",
        "\u{ad}",
        "\u{345}",
        "\u{301}",
        "\u{2b0}",
        "\u{130}",
        "\u{1c5}",
        "\u{13a0}",
        "\u{1c90}",
        "\u{1e9e}",
        "\u{ff21}",
        "\u{e0001}",
    ];
    let n = alphabet.len();
    let mut check = |text: String| {
        assert_eq!(lower_v1(&text), text.to_lowercase(), "{text:?}");
    };
    for a in 0..n {
        check(alphabet[a].to_owned());
        for b in 0..n {
            check(format!("{}{}", alphabet[a], alphabet[b]));
            for c in 0..n {
                check(format!("{}{}{}", alphabet[a], alphabet[b], alphabet[c]));
                for d in 0..n {
                    check(format!(
                        "{}{}{}{}",
                        alphabet[a], alphabet[b], alphabet[c], alphabet[d]
                    ));
                }
            }
        }
    }
}

/// NORM.1: answers computed independently (Python `unicodedata`, per code
/// point, and the Final_Sigma rule by hand), on any toolchain.
/// Mutant: any table entry or the Sigma rule.
#[test]
fn lower_v1_golden_vectors() {
    for (input, expected) in [
        ("\u{130}", "i\u{307}"),
        ("\u{1e9e}", "\u{df}"),
        ("\u{391}\u{3a3}", "\u{3b1}\u{3c2}"),
        (
            "\u{391}\u{3a3}.\u{392}\u{3a3}",
            "\u{3b1}\u{3c3}.\u{3b2}\u{3c2}",
        ),
        ("\u{3a3}", "\u{3c3}"),
        ("\u{391}\u{3a3}\u{391}", "\u{3b1}\u{3c3}\u{3b1}"),
        ("\u{13a0}", "\u{ab70}"),
        ("\u{1c90}", "\u{10d0}"),
        ("\u{1c5}", "\u{1c6}"),
        ("I", "i"),
        ("Ab\u{c7}", "ab\u{e7}"),
    ] {
        assert_eq!(lower_v1(input), expected, "{input:?}");
    }
}

/// NORM.1: the tables are well formed: sorted, unique, one to three scalars
/// padded with zeros, no identity entry; ranges sorted, disjoint and merged;
/// the two sigma tables disjoint; none empty.
/// Mutant: any malformed entry, or an empty table.
#[test]
fn the_tables_are_well_formed_and_not_empty() {
    assert!(
        LOWER_V1.len() > 1000,
        "the lowercase table is empty or truncated"
    );
    let mut last = None;
    for (key, out) in &LOWER_V1 {
        assert!(
            last.is_none_or(|l| l < *key),
            "unsorted or duplicate U+{key:04X}"
        );
        last = Some(*key);
        let c = char::from_u32(*key).expect("a scalar value");
        let n = out.iter().take_while(|&&v| v != 0).count();
        assert!((1..=3).contains(&n), "U+{key:04X} maps to {n} scalars");
        assert!(
            out[n..].iter().all(|&v| v == 0),
            "padding before a scalar at U+{key:04X}"
        );
        assert!(out[..n].iter().all(|&v| char::from_u32(v).is_some()));
        assert!(
            !(n == 1 && out[0] == u32::from(c)),
            "identity entry U+{key:04X}"
        );
    }
    for (name, table) in [
        ("CASE_IGNORABLE", &CASE_IGNORABLE[..]),
        ("CASED_TERMINAL", &CASED_TERMINAL[..]),
    ] {
        assert!(table.len() > 50, "{name} is empty or truncated");
        let mut prev_hi = None;
        for &(lo, hi) in table {
            assert!(lo <= hi, "{name} {lo:#x}..{hi:#x}");
            assert!(
                prev_hi.is_none_or(|p: u32| p + 1 < lo),
                "{name} overlaps or abuts at {lo:#x}"
            );
            prev_hi = Some(hi);
        }
    }
    for &(lo, hi) in &CASE_IGNORABLE {
        assert!(
            !CASED_TERMINAL.iter().any(|&(l, h)| l <= hi && lo <= h),
            "the sigma tables overlap near {lo:#x}"
        );
    }
}

/// The frozen tables' digest: SHA-256 over every entry as little-endian
/// `u32`s (the lowercase entries as key and three values, each range table as
/// pairs, a tag byte between tables), so a changed entry, a reordering or a
/// reformatted file that keeps the same data are told apart correctly: only a
/// data change moves it. Moving it needs a new normalization version.
const TABLE_DIGEST: &str = "59f754112df4660288906f7fa620ed450e41a370381be2b157a55860c1dd6561";

fn table_digest() -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for (key, out) in &LOWER_V1 {
        bytes.extend(key.to_le_bytes());
        for v in out {
            bytes.extend(v.to_le_bytes());
        }
    }
    for (tag, table) in [(1_u8, &CASE_IGNORABLE[..]), (2, &CASED_TERMINAL[..])] {
        bytes.push(tag);
        for (lo, hi) in table {
            bytes.extend(lo.to_le_bytes());
            bytes.extend(hi.to_le_bytes());
        }
    }
    crate::hashing::sha256_hex(&bytes)
}

/// NORM.1: the frozen data is pinned to a literal digest, on any toolchain.
/// Mutant: change, drop or reorder any entry.
#[test]
fn the_frozen_tables_match_their_pinned_digest() {
    assert_eq!(
        table_digest(),
        TABLE_DIGEST,
        "a case table changed: that needs a new normalization version"
    );
}

/// The text of the lines of `Cargo.toml` that name `krate` as a dependency.
fn dependency_lines(krate: &str) -> Vec<String> {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("Cargo.toml")
    .replace('\r', "");
    manifest
        .lines()
        .filter(|l| {
            l.starts_with(&format!("{krate} = ")) || l.starts_with(&format!("{krate}={krate}"))
        })
        .map(str::to_owned)
        .collect()
}

/// NORM.2: the NFC crate and its data crate are pinned to an exact version in
/// `Cargo.toml`, where `cargo install` honours it (it ignores Cargo.lock), and
/// neither may become a caret range again.
/// Mutant: loosen either to a plain or caret version, or drop the data crate.
#[test]
fn the_nfc_crates_are_pinned_exactly_in_cargo_toml() {
    for krate in ["icu_normalizer", "icu_normalizer_data"] {
        let lines = dependency_lines(krate);
        assert_eq!(
            lines.len(),
            1,
            "{krate} must be a direct dependency, once: {lines:?}"
        );
        assert!(
            lines[0].contains("version = \"=") || lines[0].contains(" = \"="),
            "{krate} must be pinned with an exact `=` version: {}",
            lines[0]
        );
    }
}

/// NORM.2: the data pin cannot be cleaned away as an unused dependency: the
/// code names the crate, with a comment saying why. And the Cargo.lock copy of
/// the same pin (the old guard) still holds.
/// Mutant: remove the anchor line.
#[test]
fn the_data_crate_pin_is_anchored_in_code() {
    let source = include_str!("email_hash.rs");
    assert!(
        source.contains("use icu_normalizer_data as _;"),
        "the data crate is not named in code"
    );
    let lock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )
    .expect("Cargo.lock")
    .replace('\r', "");
    assert!(
        lock.contains("name = \"icu_normalizer_data\"\nversion = \"2.3.0\"\n"),
        "icu_normalizer_data moved off 2.3.0"
    );
}

/// NORM.1: the hash's normalization never calls the standard library's
/// lowercase: no line of the production code of `email_hash.rs` (comments
/// removed) names `to_lowercase`. The differential rows above are the real
/// check; this keeps a refactor from putting std back.
/// Mutant: call `to_lowercase` in `normalize` or `lower_v1`.
#[test]
fn the_normalization_does_not_call_std_lowercase() {
    let source = include_str!("email_hash.rs");
    let production = source.split("#[cfg(test)]").next().expect("source");
    for line in production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
    {
        assert!(
            !line.contains("to_lowercase"),
            "std lowercase in production code: {line}"
        );
    }
}

/// NORM.3: the startup self-check passes on the real normalization, and fails,
/// naming the normalization, for a normalizer that differs: none at all, plain
/// std lowercase without NFC, and the real one with the final-sigma rule
/// dropped. A build that fails it must not start the key server.
/// Mutant: let any of them pass, or drop a known answer.
#[test]
fn the_self_check_passes_the_real_normalization_and_fails_a_different_one() {
    super::self_check().expect("the real normalization passes its own known answers");
    for (name, wrong) in [
        ("identity", (|s: &str| s.to_owned()) as fn(&str) -> String),
        ("std lowercase, no NFC", |s| s.to_lowercase()),
        ("final sigma dropped", |s| {
            normalize(s).replace('\u{3c2}', "\u{3c3}")
        }),
    ] {
        let error = super::self_check_with(&wrong).expect_err(name);
        assert!(error.contains("normalization"), "{name}: {error}");
    }
}

/// NORM.3: the server's start runs the self-check before it reads or creates
/// any key, so a build that normalizes differently never writes a key id or a
/// row.
/// Mutant: remove the call or move it after the key is resolved.
#[test]
fn the_key_server_start_runs_the_self_check_before_any_key() {
    let source = include_str!("../gateway/server/run_steps.rs");
    let check = source
        .find("email_hash::self_check()")
        .expect("the start runs the self-check");
    let resolve = source
        .find("email_hmac_store::resolve(")
        .expect("the start resolves the key");
    assert!(
        check < resolve,
        "the self-check must come before the key is resolved"
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
