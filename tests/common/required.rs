// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Required mode for integration tests: the same rule as the library's
//! `test_wait::skip_or_fail`, which integration test crates cannot reach.

/// Skips by printing `skipped: <requirement>`, or panics where `TESTS_REQUIRE_ALL`
/// is `1` (CI sets it in every test shard) so a test that cannot run there fails
/// instead of passing by not running. Unset or `0` skips; any other value panics
/// naming it. The caller returns right after this call.
///
/// # Panics
///
/// In required mode, and on a `TESTS_REQUIRE_ALL` value that is not `0` or `1`.
pub fn skip_or_fail(requirement: &str) {
    match std::env::var("TESTS_REQUIRE_ALL").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => eprintln!("skipped: {requirement}"),
        Ok("1") => panic!("required here but unavailable on this host: {requirement}"),
        Ok(other) => panic!("TESTS_REQUIRE_ALL must be 0 or 1 when set, got {other:?}"),
        Err(std::env::VarError::NotUnicode(_)) => panic!("TESTS_REQUIRE_ALL is not valid unicode"),
    }
}
