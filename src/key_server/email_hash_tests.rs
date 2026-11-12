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

use super::case_v1::{CASE_IGNORABLE, CASED_TERMINAL, LOWER_V1, WHITE_SPACE};
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
/// expected differences. This is what freezes Cased and `Case_Ignorable`.
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
    let check = |text: String| {
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
/// point, and the `Final_Sigma` rule by hand), on any toolchain.
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
    let points: u32 = WHITE_SPACE.iter().map(|&(lo, hi)| hi - lo + 1).sum();
    assert_eq!(points, 25, "Unicode 17.0.0 has 25 White_Space code points");
    assert!(
        WHITE_SPACE.windows(2).all(|w| w[0].1 + 1 < w[1].0),
        "White_Space ranges overlap or abut"
    );
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
const TABLE_DIGEST: &str = "1245512ca27c831d06de520af6dd0f8c3206637a9bdada02610ec5ab9ec8d639";

fn table_digest() -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for (key, out) in &LOWER_V1 {
        bytes.extend(key.to_le_bytes());
        for v in out {
            bytes.extend(v.to_le_bytes());
        }
    }
    for (tag, table) in [
        (1_u8, &CASE_IGNORABLE[..]),
        (2, &CASED_TERMINAL[..]),
        (3, &WHITE_SPACE[..]),
    ] {
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
    for krate in [
        "icu_normalizer",
        "icu_normalizer_data",
        "icu_properties",
        "icu_properties_data",
    ] {
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
    for anchor in [
        "icu_normalizer_data",
        "icu_properties",
        "icu_properties_data",
    ] {
        assert!(
            source.contains(&format!("use {anchor} as _;")),
            "{anchor} is not named in code"
        );
    }
    let lock = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
    )
    .expect("Cargo.lock")
    .replace('\r', "");
    for krate in [
        "icu_normalizer",
        "icu_normalizer_data",
        "icu_properties",
        "icu_properties_data",
    ] {
        assert!(
            lock.contains(&format!("name = \"{krate}\"\nversion = \"2.3.0\"\n")),
            "{krate} moved off 2.3.0"
        );
    }
}

/// Every non-test `.rs` file under `dir`, with each file's production code
/// (test-only items, comments and string literals blanked).
fn production_sources(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir)
        .expect("a readable source directory")
        .flatten()
    {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned();
        if path.is_dir() {
            if name != "tests" {
                production_sources(&path, out);
            }
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
            && !name.ends_with("_tests.rs")
        {
            let source = std::fs::read_to_string(&path).expect("a readable source file");
            // Test-only items blanked, then comments and string literals blanked: what
            // is left is the code that ships.
            let code = crate::test_source_text::sanitize(
                &crate::test_source_text::production_text(&source),
            );
            out.push((path.display().to_string(), code));
        }
    }
}

/// NORM.1: nothing under `src/key_server/` calls the standard library's
/// lowercase: no production line (comments removed) names `to_lowercase`. The
/// differential rows are the check that the frozen table is right; this keeps a
/// refactor from putting std back anywhere the email can pass, and on a
/// Unicode 17 toolchain it is the only row that could notice (std then gives
/// the same answer).
/// Mutant: call `to_lowercase` in `normalize`, `lower_v1` or any key-server module.
#[test]
fn nothing_in_the_key_server_calls_std_lowercase() {
    let mut files = Vec::new();
    production_sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/key_server"),
        &mut files,
    );
    assert!(files.len() > 5, "the scan found only {} files", files.len());
    for (path, text) in &files {
        for line in text.lines() {
            assert!(
                !line.contains("to_lowercase"),
                "std lowercase in {path}: {line}"
            );
        }
    }
}

/// NORM.3: building a key runs the normalization check, once per process: every
/// construction path goes through `from_hex`, so no caller can hash on a build
/// that was never checked. The counter moves only inside the once-per-process
/// initializer, so a `from_hex` that skips the check leaves it at zero.
/// Mutant: drop the check from `from_hex`, or run it on every key.
#[test]
fn building_a_key_runs_the_normalization_check_once_per_process() {
    EmailHashKey::from_hex(KEY_HEX).expect("a valid key");
    assert!(
        super::check_runs() >= 1,
        "from_hex did not run the normalization check"
    );
    let after_first = super::check_runs();
    EmailHashKey::from_hex(KEY2_HEX).expect("a second valid key");
    assert_eq!(
        super::check_runs(),
        after_first,
        "the check must run once per process"
    );
}

/// NORM.3: a failing check fails the key: the construction path refuses with the
/// check's own words, and a passing check builds the key.
/// Mutant: ignore the check's result.
#[test]
fn a_failed_normalization_check_fails_the_key() {
    let refused =
        EmailHashKey::from_hex_checked(KEY_HEX, &|| Err("known answer #3 differs".into()));
    match refused {
        Err(KeyTextError::Normalization(why)) => assert!(why.contains("known answer #3"), "{why}"),
        other => panic!("a failed check must fail the key, got {other:?}"),
    }
    assert!(EmailHashKey::from_hex_checked(KEY_HEX, &|| Ok(())).is_ok());
    // A malformed key text is refused as before, whatever the check says.
    assert!(matches!(
        EmailHashKey::from_hex_checked("short", &|| Ok(())),
        Err(KeyTextError::Length(5))
    ));
}

/// NORM.5: a subject is hashed under its own domain tag and exactly as given:
/// a subject that equals an email address does not collide with that email's
/// hash, and subjects that differ only by case stay distinct (a subject is an
/// identifier, not an address). Expected values computed independently with
/// Python `hmac` over the bytes 0x00..0x1f and `subject-v1\0`.
/// Mutant: hash a subject as an email, or normalize it.
#[test]
fn a_subject_hashes_under_its_own_domain_and_exactly() {
    let key = EmailHashKey::for_test();
    assert_eq!(
        key.hash_subject("sub-1"),
        "bc5b9e87054661a36c97eec2c50abe5cafceb99555aa7339cceaf6e57f4b6b27"
    );
    assert_eq!(
        key.hash_subject("ABC"),
        "c8d7ded996a19f3e9496f10b497083b777a11c6e9038b53b0c29d6a0b1b4f2cb"
    );
    assert_ne!(
        key.hash_subject("ABC"),
        key.hash_subject("abc"),
        "case is part of a subject"
    );
    assert_eq!(
        key.hash_subject("ada@corp.invalid"),
        "f8c9c2079823e7d4875d39a802c2a3d782fe8fd931159c4258d49cf19fb8610c"
    );
    assert_eq!(
        key.hash("ada@corp.invalid"),
        "46c905f0e197d1e66afa8a546bae0b9fe12c9f0a2309ff2238e101ab59367336",
        "the email hash is unchanged"
    );
    assert_ne!(
        key.hash_subject("ada@corp.invalid"),
        key.hash("ada@corp.invalid")
    );
}

/// NORM.1: the email reaches the hash exactly as the token carried it: the
/// record builder hashes `identity.email()` and the log field hashes
/// `identity.subject()`, each unchanged: no trim, case change, NFC or split in
/// between. The callers of `EmailHashKey::hash` outside tests are these two
/// (and the admin lookup route, which trims what the admin typed).
/// Mutant: pass a transformed value at either site.
#[test]
fn the_email_reaches_the_hash_untouched() {
    let audit = include_str!("audit.rs");
    assert!(
        audit.contains("let email = identity.email();") && audit.contains("key.hash(email)"),
        "the record builder must hash identity.email() unchanged"
    );
    let server = include_str!("mod.rs");
    assert!(
        server.contains("self.email_key.hash_subject(identity.subject())"),
        "the log field must hash identity.subject() unchanged"
    );
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
        assert!(
            error.contains("known answer #"),
            "{name} must name the answer: {error}"
        );
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

/// NORM.4: surrounding Unicode `White_Space` never changes the hash, so the email
/// an `IdP` sends and the address an admin pastes meet however they are padded:
/// ASCII, no-break space (U+00A0), ideographic space (U+3000), next line
/// (U+0085) and the rest of the Unicode 17 `White_Space` set. Whitespace inside
/// the address, and characters that merely look blank (zero-width space,
/// byte-order mark), are part of the address and do change it.
/// Mutant: no trim, one end only, an ASCII-only trim, an inner trim.
#[test]
fn padding_does_not_change_the_hash_and_inner_or_blank_looking_characters_do() {
    let key = EmailHashKey::for_test();
    let bare = key.hash("Ada.Lovelace@corp.invalid");
    for pad in [
        "",
        " ",
        "\t",
        "\r\n",
        " \n\t ",
        "\u{b}\u{c}",
        "\u{a0}",
        "\u{3000}",
        "\u{2003}",
        "\u{85}",
        "\u{2028}\u{2029}",
        "\u{1680}",
        "\u{202f}",
        "\u{205f}",
        "\u{200a}",
    ] {
        assert_eq!(
            key.hash(&format!("{pad}Ada.Lovelace@corp.invalid{pad}")),
            bare,
            "{pad:?}"
        );
        assert_eq!(
            key.hash(&format!("{pad}Ada.Lovelace@corp.invalid")),
            bare,
            "leading {pad:?}"
        );
        assert_eq!(
            key.hash(&format!("Ada.Lovelace@corp.invalid{pad}")),
            bare,
            "trailing {pad:?}"
        );
    }
    assert_ne!(
        key.hash("Ada. Lovelace@corp.invalid"),
        bare,
        "inner whitespace is kept"
    );
    assert_ne!(
        key.hash("Ada.\u{a0}Lovelace@corp.invalid"),
        bare,
        "an inner no-break space is kept"
    );
    for blank in ["\u{200b}", "\u{feff}", "\u{2060}", "\u{180e}"] {
        assert_ne!(
            key.hash(&format!("{blank}Ada.Lovelace@corp.invalid")),
            bare,
            "{blank:?} is not White_Space and must not be trimmed"
        );
    }
}

/// NORM.4: the frozen trim is exactly the standard library's trim at Unicode
/// 17.0.0, for every scalar value as padding on either side; on a later
/// toolchain the frozen list decides and this stands down.
/// Mutant: drop or add a code point in the `White_Space` table.
#[test]
fn trim_v1_is_std_trim_for_every_code_point_at_unicode_17() {
    if !std_is_unicode_17() {
        return;
    }
    for c in all_scalars() {
        for text in [
            format!("{c}x{c}"),
            format!("{c}{c}x"),
            format!("x{c}{c}"),
            c.to_string(),
        ] {
            assert_eq!(
                super::trim_v1(&text),
                text.trim(),
                "U+{:04X} in {text:?}",
                u32::from(c)
            );
        }
    }
}

/// NORM.4: the record builder (token issuance) hashes a padded email claim to
/// the same value as the clean one, which is what the admin lookup computes.
/// Mutant: trim at the lookup only, not in `hash`.
#[test]
fn issuance_hashes_a_padded_claim_like_a_clean_one() {
    use crate::key_server::audit::SafeIdentity;
    use crate::key_server::oidc::VerifiedIdentity;
    let key = EmailHashKey::for_test();
    let record = |email: &str| {
        SafeIdentity::of(
            &VerifiedIdentity::for_test("sub-1", email, None, Vec::new(), "https://issuer.invalid"),
            &key,
        )
        .email_hash
    };
    assert_eq!(record(" Ada@corp.invalid \n"), record("Ada@corp.invalid"));
    assert!(record("Ada@corp.invalid").is_some());
    // A whitespace-only claim goes through the same trim and hashes as the empty
    // string: the record still carries a hash, as it did for any non-empty claim.
    assert_eq!(record("  \t "), Some(key.hash("")));
    assert_eq!(
        record(""),
        None,
        "an empty claim carries no email hash, as before"
    );
}
