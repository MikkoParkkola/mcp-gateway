// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The installation key behind `email_hash`: 32 bytes, written as exactly 64
//! lowercase hex digits wherever it is stored or configured. The HMAC and the
//! key id are computed over the decoded bytes, never over the hex text.

use crate::wiped_bytes::WipedBytes;

// Names the NFC data crate so a dependency cleanup cannot drop its exact pin in
// Cargo.toml: `cargo install` honours that pin, and ignores Cargo.lock.
use icu_normalizer_data as _;
use icu_properties as _;
use icu_properties_data as _;

/// The key's length in bytes, and so its hex text's length in digits / 2.
const KEY_BYTES: usize = 32;

/// The normalization and hash version records carry as `email_hash_version`.
pub(crate) const VERSION: u32 = 1;

/// Domain separation for version 1: a later version hashes under another
/// prefix, so its hashes cannot collide with these.
const DOMAIN: &[u8] = b"email-v1\0";

/// The subject hash's own domain: a subject is not an address.
const SUBJECT_DOMAIN: &[u8] = b"subject-v1\0";

/// Normalization v1: trim Unicode `White_Space`, NFC, Unicode lowercase, NFC again. The second NFC is
/// needed because lowercasing can emit a decomposed sequence (U+0130 becomes
/// `i` and a combining dot), so one pass alone is not stable under a second.
/// Canonically equivalent spellings meet; compatibility forms (a ligature,
/// fullwidth letters) stay distinct, and the domain is not IDNA-converted.
///
/// The hash must be the same on every build, so no table here is the
/// compiler's: lowercase is the crate's own frozen Unicode 17.0.0 tables
/// (`case_v1`), reproducing the standard library's `str::to_lowercase` at that
/// version exactly, final-sigma rule included; NFC is `icu_normalizer` and its data
/// crate `icu_normalizer_data`, both pinned to an exact version in
/// `Cargo.toml` (`cargo install` ignores Cargo.lock). A change that alters
/// either table needs a new version, and `self_check` refuses to start a
/// build that normalizes differently.
pub(crate) fn normalize(email: &str) -> String {
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc();
    nfc.normalize(&lower_v1(&nfc.normalize(trim_v1(email))))
        .into_owned()
}

/// Version 1's lowercase: the standard library's `str::to_lowercase` at
/// Unicode 17.0.0, over the crate's frozen tables. Each code point goes
/// through the per-code-point table (ASCII by the locale-free ASCII rule);
/// capital Sigma (U+03A3) follows Unicode's `Final_Sigma` rule: it becomes final
/// sigma when a cased letter precedes it and none follows, skipping
/// case-ignorable characters on both sides. That is the only context-sensitive
/// rule in the default lowercase mapping (SpecialCasing.txt).
/// Version 1's trim: Unicode `White_Space` at both ends, from the crate's frozen
/// Unicode 17.0.0 list (not `str::trim`, which follows the toolchain). Inner
/// whitespace stays, and so do characters that only look blank (zero-width
/// space, byte-order mark), which are not `White_Space`.
pub(crate) fn trim_v1(text: &str) -> &str {
    text.trim_matches(case_v1::is_white_space)
}

pub(crate) fn lower_v1(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (at, c) in text.char_indices() {
        if c == '\u{3a3}' {
            let word_final = case_v1::case_ignorable_then_cased(text[..at].chars().rev())
                && !case_v1::case_ignorable_then_cased(text[at + c.len_utf8()..].chars());
            out.push(if word_final { '\u{3c2}' } else { '\u{3c3}' });
        } else if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else if let Some(mapped) = case_v1::lower(c) {
            out.extend(mapped);
        } else {
            out.push(c);
        }
    }
    out
}

/// Known answers every build must reproduce, checked when the key server
/// starts: a build whose Unicode data differs from the one that wrote the
/// retained rows would otherwise hash the same address differently and make
/// lookups miss silently. `cargo install` never runs the tests, so the check
/// is part of the program.
const KNOWN_ANSWERS: &[(&str, &str)] = &[
    ("Ada.Lovelace", "ada.lovelacx"),
    ("  \u{a0}Ada.Lovelace\u{3000}\t", "ada.lovelace"),
    ("\u{130}x", "i\u{307}x"),
    ("\u{1e9e}", "\u{df}"),
    ("\u{391}\u{3a3}", "\u{3b1}\u{3c2}"),
    (
        "\u{391}\u{3a3}.\u{392}\u{3a3}",
        "\u{3b1}\u{3c3}.\u{3b2}\u{3c2}",
    ),
    ("\u{3a3}", "\u{3c3}"),
    ("\u{13a0}", "\u{ab70}"),
    ("\u{1c90}", "\u{10d0}"),
    ("\u{212b}", "\u{e5}"),
    ("A\u{30a}", "\u{e5}"),
    ("\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
    ("a\u{307}\u{323}", "\u{1ea1}\u{307}"),
    ("\u{fb01}", "\u{fb01}"),
    ("\u{ff21}", "\u{ff41}"),
    // Trim: blank-looking characters that are not White_Space stay; inner whitespace stays;
    // next line and line separator pad like any other white space.
    ("\u{200b}Ada\u{200b}", "\u{200b}ada\u{200b}"),
    ("\u{feff}Ada", "\u{feff}ada"),
    ("Ada\u{a0}Lovelace", "ada\u{a0}lovelace"),
    ("\u{85}Ada\u{2028}", "ada"),
    // Final sigma looks back over case-ignorable characters too.
    ("\u{391}.\u{3a3}", "\u{3b1}.\u{3c2}"),
    ("\u{391}\u{ad}\u{3a3}", "\u{3b1}\u{ad}\u{3c2}"),
];

/// Run [`KNOWN_ANSWERS`] through `normalizer`; the first miss is the error.
pub(crate) fn self_check_with(normalizer: &dyn Fn(&str) -> String) -> Result<(), String> {
    for (index, (input, expected)) in KNOWN_ANSWERS.iter().enumerate() {
        let got = normalizer(input);
        if got != *expected {
            return Err(format!(
                "this build's email normalization differs from the one the retained audit rows were \
                 hashed with (known answer #{index}, input U+{:04X}... gave {} code points, \
                 expected {}): rebuild with the pinned dependencies",
                input.chars().next().map_or(0, u32::from),
                got.chars().count(),
                expected.chars().count()
            ));
        }
    }
    Ok(())
}

/// Whether the real check has passed in this process, and how many times it ran.
/// One lock covers both, so the check runs exactly once until it passes: two
/// threads building their first keys cannot both run it, and the count is final
/// as soon as any key has been built.
static CHECK_STATE: std::sync::Mutex<(bool, usize)> = std::sync::Mutex::new((false, 0));

/// The check every key's construction goes through: the real [`self_check`], run
/// until it passes once in this process.
fn process_check() -> Result<(), String> {
    check_once(&CHECK_STATE, &self_check)
}

/// Run `check` unless `state` already records a pass, and count the run. Only a
/// success is remembered: a failure is not cached, so it is judged again at the
/// next key, and it can never be stuck in a process-wide cell. The state is a
/// parameter so a row can give it its own, independent of every other test.
///
/// The check runs while the state's lock is held, which is what makes it run
/// exactly once. It must therefore never build a key or call `process_check`
/// again (that would wait on its own lock): `self_check` does neither.
fn check_once(
    state: &std::sync::Mutex<(bool, usize)>,
    check: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    // A poisoned lock still holds a valid (passed, runs) pair.
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.0 {
        return Ok(());
    }
    state.1 += 1;
    check()?;
    state.0 = true;
    Ok(())
}

/// How many times the real check has run in this process (rows read it).
#[cfg(test)]
pub(crate) fn check_runs() -> usize {
    CHECK_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .1
}

/// [`self_check_with`] on the real normalization.
pub(crate) fn self_check() -> Result<(), String> {
    self_check_with(&normalize)
}

mod case_v1;

/// The installation key. `Debug` shows only the length; the bytes are wiped
/// on drop.
#[derive(Debug)]
pub(crate) struct EmailHashKey(WipedBytes);

/// Why a key's text was refused. Never carries the text itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyTextError {
    /// Not 64 characters after the one optional trailing newline.
    Length(usize),
    /// This build's email normalization differs from its known answers.
    Normalization(String),
    /// A character other than `0-9` or `a-f`.
    NotLowercaseHex,
}

impl std::fmt::Display for KeyTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length(n) => write!(
                f,
                "it must hold exactly 64 lowercase hex digits, not {n} characters"
            ),
            Self::Normalization(why) => f.write_str(why),
            Self::NotLowercaseHex => {
                f.write_str("it must hold only lowercase hex digits (0-9, a-f)")
            }
        }
    }
}

impl EmailHashKey {
    /// Parse the stored or configured text: exactly 64 lowercase hex digits,
    /// with one trailing newline allowed (the record key file's rule).
    pub(crate) fn from_hex(text: &str) -> Result<Self, KeyTextError> {
        Self::from_hex_checked(text, &process_check)
    }

    /// [`Self::from_hex`] with the normalization check passed in, so a row can
    /// give it a failing one. Private to this module (its test children reach
    /// it): no other code in the crate can build a key with a check of its own
    /// choosing, and `from_hex` itself runs through this body, so the rows
    /// judge the production path. The text is judged first; then the check
    /// runs, and a failure fails the key, with the check's own words.
    fn from_hex_checked(
        text: &str,
        check: &dyn Fn() -> Result<(), String>,
    ) -> Result<Self, KeyTextError> {
        let key = Self::parse_hex(text)?;
        check().map_err(KeyTextError::Normalization)?;
        Ok(key)
    }

    fn parse_hex(text: &str) -> Result<Self, KeyTextError> {
        let digits = text.strip_suffix('\n').unwrap_or(text);
        if digits.len() != 2 * KEY_BYTES {
            return Err(KeyTextError::Length(digits.chars().count()));
        }
        if !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(KeyTextError::NotLowercaseHex);
        }
        // invariant: 64 checked hex digits always decode to 32 bytes.
        let bytes = hex::decode(digits).expect("64 checked hex digits decode");
        Ok(Self(WipedBytes::new(bytes)))
    }

    /// The hash of an OIDC `subject` for a log field: HMAC-SHA256 under this key
    /// of its own domain tag (`subject-v1`) and the identifier's exact bytes. A
    /// subject is an opaque, case-sensitive identifier, not an address, so it
    /// does not go through [`normalize`]: no trim, no case folding, and a subject
    /// that equals an email address does not collide with that email's hash.
    pub(crate) fn hash_subject(&self, subject: &str) -> String {
        let mut message = Vec::with_capacity(SUBJECT_DOMAIN.len() + subject.len());
        message.extend_from_slice(SUBJECT_DOMAIN);
        message.extend_from_slice(subject.as_bytes());
        crate::hashing::hmac_sha256_hex(self.0.as_bytes(), &message)
    }

    /// The key id: lowercase hex SHA-256 of the decoded bytes. Names the key
    /// without being it.
    pub(crate) fn key_id(&self) -> String {
        crate::hashing::sha256_hex(self.0.as_bytes())
    }

    /// The `email_hash` of `email`: HMAC-SHA256 under this key of the
    /// version's domain-separation prefix and the normalized address, as 64
    /// lowercase hex digits.
    pub(crate) fn hash(&self, email: &str) -> String {
        let normalized = normalize(email);
        let mut message = Vec::with_capacity(DOMAIN.len() + normalized.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(normalized.as_bytes());
        crate::hashing::hmac_sha256_hex(self.0.as_bytes(), &message)
    }
}

#[cfg(test)]
impl EmailHashKey {
    /// A fixed key (bytes 0x00..0x1f) for rows that need a key server.
    pub(crate) fn for_test() -> std::sync::Arc<Self> {
        std::sync::Arc::new(
            Self::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("a valid fixed key"),
        )
    }

    /// A second fixed key, so a row can show another key id never matches.
    #[cfg(feature = "webui")]
    pub(crate) fn for_test_other() -> std::sync::Arc<Self> {
        std::sync::Arc::new(
            Self::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
                .expect("a valid fixed key"),
        )
    }
}

#[cfg(test)]
#[path = "email_hash_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "email_hash_gen_tests.rs"]
mod gen_tests;
