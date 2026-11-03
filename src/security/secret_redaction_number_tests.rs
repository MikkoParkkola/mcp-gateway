// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A JSON number is redacted exactly when it equals a value by the number
//! rules, however the scrub finds the match. The oracle below is the
//! per-value comparison the scrub ran before it matched numbers by lookup,
//! kept verbatim: every row compares the scrub's answer with it.

use serde_json::{Number, Value};

use super::{Compiled, exact_integer, redact_value_with};

/// Whether `number` equals `needle` by the number rules: the comparison the
/// scrub made per value, one value at a time.
fn oracle(needle: &str, number: &Number) -> bool {
    let n = number;
    let digits = n.to_string();
    let float = n.as_f64().filter(|_| n.is_f64()).map(f64::abs);
    let value_f64 = n.as_f64().map(f64::abs);
    let value_int = n
        .as_u64()
        .map(u128::from)
        .or_else(|| n.as_i64().map(|v| u128::from(v.unsigned_abs())));
    let needle = needle.trim_ascii();
    let needle = needle.strip_prefix(['+', '-']).unwrap_or(needle);
    let coefficient = needle.split(['e', 'E']).next().unwrap_or_default();
    if !coefficient.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    if !needle.bytes().all(|b| b.is_ascii_digit()) {
        let trimmed = needle.trim_start_matches('0');
        let normalized: std::borrow::Cow<'_, str> =
            if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
                trimmed.into()
            } else {
                format!("0{trimmed}").into()
            };
        let Ok(parsed) = serde_json::from_str::<Number>(&normalized) else {
            return false;
        };
        if let Some(v) = value_int {
            return exact_integer(&normalized).is_some_and(|e| e == v.to_string());
        }
        return parsed
            .as_f64()
            .zip(value_f64)
            .is_some_and(|(p, v)| p.abs().to_bits() == v.to_bits());
    }
    let value = needle.trim_start_matches('0');
    let value = if value.is_empty() { "0" } else { value };
    if let Some(f) = float {
        return serde_json::from_str::<f64>(value).is_ok_and(|p| p.to_bits() == f.to_bits());
    }
    digits.trim_start_matches('-') == value
}

/// The scrub's verdict on the JSON `scalar` against `needles`, and the
/// oracle's: a literal (exact JSON scalar equality, as `Value` compares) first,
/// as the scrub checks it, then, for a number, any value equal by the number
/// rules.
fn verdicts(needles: &[&str], scalar: &str) -> (bool, bool) {
    let parsed: Value = serde_json::from_str(scalar).expect("a JSON scalar");
    let literal = needles
        .iter()
        .filter_map(|needle| serde_json::from_str::<Value>(needle).ok())
        .filter(|v| !matches!(v, Value::String(_) | Value::Array(_) | Value::Object(_)))
        .any(|literal| literal == parsed);
    let by_number = match &parsed {
        Value::Number(n) => needles.iter().any(|needle| oracle(needle, n)),
        _ => false,
    };
    let expected = literal || by_number;
    let owned: Vec<String> = needles.iter().map(|s| (*s).to_owned()).collect();
    let mut scrubbed = parsed.clone();
    let actual = redact_value_with(&mut scrubbed, &Compiled::new(&owned));
    (actual, expected)
}

/// Value forms: digits with and without leading zeros and signs, decimals,
/// exponents, past f64 precision, past u64, past u128, and forms that name
/// no number.
const NEEDLES: &[&str] = &[
    "0",
    "000",
    "007",
    "012345",
    "+012345",
    "-012345",
    " 12345.0\n",
    "12.5",
    "0012.5",
    "1.5e10",
    "1.2345e4",
    "12345.0",
    "1e400",
    "0e99",
    "e123",
    "+",
    "abc",
    "12_345",
    "0x1F",
    "18446744073709551616",
    "340282366920938463463374607431768211456",
    "9007199254740993",
    "123456789012345678901234567890",
    "99999999999999991611392",
    "1e23",
    "0.0",
    "-0.0",
    "true",
    "false",
    "null",
    "-0012.5",
    "+1.2345e4",
    ".5",
    "5.",
    "100.",
    "1e+",
    "1e-400",
    "--5",
    "+-5",
];

/// Number forms: zero in each sign and form, small and large integers in
/// each sign, floats, exponents, the edges of u64, i64 and f64 precision,
/// and a float that rounds to the same f64 as an integer-form value.
const NUMBERS: &[&str] = &[
    "0",
    "-0",
    "0.0",
    "-0.0",
    "7",
    "1771",
    "12345",
    "-12345",
    "12345.0",
    "-12345.0",
    "1.5e10",
    "15000000000",
    "12.5",
    "-12.5",
    "18446744073709551615",
    "-9223372036854775808",
    "9007199254740992",
    "9007199254740993",
    "1e23",
    "99999999999999991611392",
    "1e300",
    "0.5",
    "-0.5",
    "7.0",
];

/// Every value alone against every number form.
#[test]
fn each_value_alone_matches_numbers_as_the_oracle_does() {
    let mut wrong = Vec::new();
    for needle in NEEDLES {
        for number in NUMBERS {
            let (actual, expected) = verdicts(&[needle], number);
            if actual != expected {
                wrong.push(format!(
                    "{needle:?} vs {number}: scrub {actual}, oracle {expected}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Mixed sets: a match by any one value is a match, and a set none of whose
/// values matches redacts nothing.
#[test]
fn mixed_value_sets_match_numbers_as_the_oracle_does() {
    let sets: &[&[&str]] = &[
        &["007", "12.5", "abc"],
        &["e123", "+", "0x1F", "12_345"],
        &["9007199254740993", "1.5e10", "-012345"],
        &[
            "0",
            "99999999999999991611392",
            "340282366920938463463374607431768211456",
        ],
        NEEDLES,
    ];
    let mut wrong = Vec::new();
    for set in sets {
        for number in NUMBERS {
            let (actual, expected) = verdicts(set, number);
            if actual != expected {
                wrong.push(format!(
                    "{set:?} vs {number}: scrub {actual}, oracle {expected}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Scalars that are not numbers match a literal needle by exact JSON
/// equality only, as before.
#[test]
fn other_scalars_match_literals_as_the_oracle_does() {
    let mut wrong = Vec::new();
    for needle in NEEDLES {
        for scalar in ["true", "false", "null"] {
            let (actual, expected) = verdicts(&[needle], scalar);
            if actual != expected {
                wrong.push(format!(
                    "{needle:?} vs {scalar}: scrub {actual}, oracle {expected}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert_eq!(
        verdicts(&["true"], "true"),
        (true, true),
        "premise: a match"
    );
}

/// A value that reads as a JSON number is matched by the number rules alone,
/// with no literal check: a result equal to it by exact JSON equality is
/// still redacted, in each form, past u64, below `i64::MIN` and underflowing
/// to zero included.
#[test]
fn a_literal_number_value_is_redacted_by_the_number_rules() {
    for (needle, scalar) in [
        ("5", "5"),
        ("-5", "-5"),
        ("5.0", "5.0"),
        ("-0.0", "-0.0"),
        ("-0", "-0"),
        ("18446744073709551616", "18446744073709551616"),
        // Below i64::MIN: both sides read it as a float.
        ("-9223372036854775809", "-9223372036854775809"),
        // Underflows to 0.0 on both sides.
        ("1e-400", "1e-400"),
        ("1e2", "1e2"),
        ("-18446744073709551616", "-18446744073709551616"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("18446744073709551615", "18446744073709551615"),
        (" 5\n", "5"),
    ] {
        assert_eq!(
            verdicts(&[needle], scalar),
            (true, true),
            "{needle:?} vs {scalar}"
        );
    }
    // Across forms the scrub agrees with the oracle, whatever it answers.
    for (needle, scalar) in [("-0", "0"), ("1e-400", "0.0"), ("1e-400", "-0.0")] {
        let (actual, expected) = verdicts(&[needle], scalar);
        assert_eq!(actual, expected, "{needle:?} vs {scalar}");
    }
}

/// The lookup keys a number that is not a float by its exact integer
/// magnitude, which holds only while `serde_json` reads every integer past
/// u64 as a float (no `arbitrary_precision`): pinned here.
#[test]
fn an_integer_past_u64_reads_as_a_float() {
    let past_u64: Value = serde_json::from_str("18446744073709551616").expect("a number");
    let Value::Number(n) = past_u64 else {
        panic!("premise: a number");
    };
    assert!(n.is_f64(), "serde_json now keeps big integers exact: {n}");
}

/// The grid's premise: it holds matches as well as misses, including the
/// cases the lookup must get right (zero in each sign, the rounding pair).
#[test]
fn the_grid_holds_matches_and_misses() {
    for (needle, number, expected) in [
        ("0", "-0.0", true),
        ("0", "0.0", true),
        ("007", "7", true),
        ("007", "1771", false),
        ("99999999999999991611392", "1e23", true),
        ("9007199254740993", "9007199254740992", false),
        ("1.5e10", "15000000000", true),
        ("-0.0", "0.0", true),
        ("0.0", "-0.0", true),
    ] {
        let (actual, oracle) = verdicts(&[needle], number);
        assert_eq!(
            oracle, expected,
            "premise: the oracle on {needle:?} vs {number}"
        );
        assert_eq!(actual, expected, "{needle:?} vs {number}");
    }
}

/// NUMCOST.3, measured by hand in a release build: a 16 MiB number-heavy
/// answer against 1,024 and 2,048 values, directly through [`Compiled`]
/// (the ingress set stops at 1,024 values, past which it refuses rather than
/// matches). The set is built once (cold) and then reused for every scrub, as
/// a backend's cached set is; both times are printed. Values are mostly text
/// or all numbers, and the answer's numbers either match one value or none.
#[test]
#[ignore = "measurement: run by hand and report"]
fn cost_of_number_matching_against_the_value_count() {
    let size = 16 * 1024 * 1024;
    for count in [1024_usize, 2048] {
        for (values_kind, values) in [
            (
                "text",
                (0..count)
                    .map(|i| {
                        if i == 0 {
                            "012345".to_owned()
                        } else {
                            format!("needle-{i:05}-secret")
                        }
                    })
                    .collect::<Vec<String>>(),
            ),
            (
                "numeric",
                (0..count)
                    .map(|i| format!("{}", 7_000_000 + i))
                    .collect::<Vec<String>>(),
            ),
        ] {
            let started = std::time::Instant::now();
            let compiled = Compiled::new(&values);
            let build = started.elapsed();
            for (answer_kind, number) in [
                ("matching", values[0].trim_start_matches('0')),
                ("missing", "12346"),
            ] {
                let answer: Value = serde_json::from_str(&format!(
                    "{{\"n\":[{}]}}",
                    vec![number; size / (number.len() + 1)].join(",")
                ))
                .expect("a number-heavy answer");
                let mut scrubbed = answer.clone();
                let started = std::time::Instant::now();
                let changed = redact_value_with(&mut scrubbed, &compiled);
                let scrub = started.elapsed();
                assert_eq!(
                    changed,
                    answer_kind == "matching",
                    "{values_kind} {answer_kind}"
                );
                println!(
                    "NUMCOST.3 values={count} values_kind={values_kind} answer={answer_kind} build={build:?} scrub={scrub:?}"
                );
            }
        }
    }
}
