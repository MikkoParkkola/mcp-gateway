// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A function no test calls, compiled only for the coverage grade.
//!
//! The grade merges profiles and instrumented binaries from several runners.
//! A merge that lost a part's binaries, or a report built from profiles alone,
//! would drop every function no test reached, and coverage would read higher
//! than it is. This function must appear in the merged report at a count of
//! zero; the merge job fails when it is missing or reached.

/// Never called. Its zero count in the merged report is the check.
pub(crate) fn coverage_canary() -> u8 {
    1
}

/// Asks the compiler to keep the canary in the object file: referenced here,
/// never called, so its count stays zero. The linker may still drop it; that
/// the merged report does hold it is what the merge job's canary check proves.
#[used]
static COVERAGE_CANARY: fn() -> u8 = coverage_canary;
