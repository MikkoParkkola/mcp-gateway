// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The key's construction check and the subject hash: rows that need the key.

use super::super::check_runs;
use super::{EmailHashKey, KEY_HEX, KEY2_HEX, KeyTextError};

/// NORM.3: building a key runs the normalization check, once per process: every
/// construction path goes through `from_hex`, so no caller can hash on a build
/// that was never checked. The counter moves only inside the once-per-process
/// lock, so a `from_hex` that skips the check leaves it at zero, and once any
/// key has been built the count is final: no later or parallel build moves it.
/// Mutant: drop the check from `from_hex`, or run it on every key.
#[test]
fn building_a_key_runs_the_normalization_check_once_per_process() {
    EmailHashKey::from_hex(KEY_HEX).expect("a valid key");
    assert!(
        check_runs() >= 1,
        "from_hex did not run the normalization check"
    );
    let after_first = check_runs();
    EmailHashKey::from_hex(KEY2_HEX).expect("a second valid key");
    assert_eq!(
        check_runs(),
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

/// NORM.3: nothing a test injects can leave a failure stuck in the process: an
/// injected check runs on every call (it is never cached), a failing one does
/// not stop the next key from building with a passing one, and the real check's
/// result is only cached once it has passed.
/// Mutant: cache the injected result, or cache a failure.
#[test]
fn an_injected_check_runs_every_time_and_a_failure_is_never_cached() {
    let runs = std::cell::Cell::new(0_u32);
    let fail = || {
        runs.set(runs.get() + 1);
        Err::<(), String>("boom".into())
    };
    assert!(EmailHashKey::from_hex_checked(KEY_HEX, &fail).is_err());
    assert!(EmailHashKey::from_hex_checked(KEY_HEX, &fail).is_err());
    assert_eq!(runs.get(), 2, "an injected check must run on every call");
    assert!(
        EmailHashKey::from_hex_checked(KEY_HEX, &|| Ok(())).is_ok(),
        "a failure injected before must not stick"
    );
    assert!(
        EmailHashKey::from_hex(KEY_HEX).is_ok(),
        "the real path is untouched by the injections"
    );
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
    // Exact bytes: padding and a decomposed accent are part of a subject.
    assert_ne!(
        key.hash_subject(" sub-1 "),
        key.hash_subject("sub-1"),
        "a subject is not trimmed"
    );
    assert_ne!(
        key.hash_subject("e\u{301}"),
        key.hash_subject("\u{e9}"),
        "a subject is not NFC-normalized"
    );
}
