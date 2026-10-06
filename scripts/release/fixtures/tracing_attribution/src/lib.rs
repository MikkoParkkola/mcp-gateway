// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7731: three tracing shapes, logged with no subscriber, for the coverage
//! grader's attribution rules. Line numbers are part of the fixture: the test
//! in scripts/release/test_critical_function_coverage.py names them.

fn label(x: u8) -> u8 {
    x.wrapping_add(1)
}

/// Reached; a multi-line macro whose argument lines are plain fields.
// Kept multi-line on purpose: the argument lines are what is graded.
#[rustfmt::skip]
pub fn plain_fields(x: u8) -> bool {
    let doubled = x.wrapping_mul(2);
    tracing::debug!(
        value = doubled,
        "plain fields"
    );
    doubled > 0
}

/// Reached; a call on the macro's head line.
pub fn head_call(x: u8) -> bool {
    tracing::debug!(value = label(x), "call on the head line");
    x > 0
}

/// Never reached.
// Kept multi-line on purpose: the argument lines are what is graded.
#[rustfmt::skip]
pub fn unreached(x: u8) -> bool {
    tracing::debug!(
        value = x,
        "never logged"
    );
    x > 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn reaches_two_of_three() {
        assert!(super::plain_fields(3));
        assert!(super::head_call(3));
    }
}
