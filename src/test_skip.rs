// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one rule for a test that cannot run on this host. This file imports nothing from the crate, so both kinds of
//! test compile the same two functions: lib tests through `crate::test_wait`, which includes and re-exports it, and
//! integration tests through `#[path = "../src/test_skip.rs"] mod test_skip;`. Include it only in a test file that
//! calls `skip_or_fail`: `required_mode` is used only through it, so an include with no call is dead code under
//! `-D warnings`.

/// Whether a test that cannot run on this host must fail instead of skipping, from `TESTS_REQUIRE_ALL`: unset or
/// `0` skips (`0` is the local opt-out), `1` requires, and any other value is an error naming it, so a typo cannot
/// silently turn required mode off. CI sets `1` in every test shard (`scripts/ci/shard_tests.py`); the packaged-crate
/// suite does not, and still skips what its crate lacks. The Python rule is `scripts/ci/required_mode.py`.
pub(crate) fn required_mode(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!(
            "TESTS_REQUIRE_ALL must be 0 or 1 when set, got {other:?}"
        )),
    }
}

/// The one way a test skips because this host lacks something it needs (a user right, a loopback family, the
/// repository files): prints `skipped: <requirement>`, or panics where required mode is on, so a feature's only check
/// cannot pass by not running. The caller returns right after it (`scripts/ci/check_rust_skips.py` checks that).
///
/// # Panics
///
/// In required mode, and on a `TESTS_REQUIRE_ALL` value that is not `0` or `1`.
pub(crate) fn skip_or_fail(requirement: &str) {
    let value = match std::env::var("TESTS_REQUIRE_ALL") {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("TESTS_REQUIRE_ALL is not valid unicode"),
    };
    match required_mode(value.as_deref()) {
        Ok(true) => panic!("required here but unavailable on this host: {requirement}"),
        Ok(false) => eprintln!("skipped: {requirement}"),
        Err(message) => panic!("{message}"),
    }
}
