// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! With no automaton for the needles, a value is replaced whole by the
//! marker chosen for them, and text is dropped whole: nothing of either
//! survives.

use serde_json::{Value, json};

use super::{Compiled, FAIL_MATCHER_BUILD, matcher, redact_untruncated, redact_value_with};

/// `secrets` compiled with every automaton build on this thread failing.
fn compiled_without_automaton(secrets: &[&str]) -> Compiled {
    let owned: Vec<String> = secrets.iter().map(|s| (*s).to_owned()).collect();
    FAIL_MATCHER_BUILD.with(|fail| fail.set(true));
    let compiled = Compiled::new(&owned);
    FAIL_MATCHER_BUILD.with(|fail| fail.set(false));
    assert!(
        compiled.matcher.is_none(),
        "premise: the automaton build failed"
    );
    compiled
}

#[test]
fn a_value_is_replaced_whole_when_no_automaton_exists() {
    let compiled = compiled_without_automaton(&["s3cret-value-1"]);
    let mut value = json!({"text": "no secret here", "n": 5});
    assert!(redact_value_with(&mut value, &compiled));
    assert_eq!(value, Value::String("[redacted]".to_owned()));
}

/// The marker is the one chosen for the needles: a needle that is the first
/// marker's own text moves it to the next.
#[test]
fn the_whole_value_marker_contains_no_needle() {
    let compiled = compiled_without_automaton(&["[redacted]", "s3cret-value-1"]);
    let mut value = json!("anything");
    assert!(redact_value_with(&mut value, &compiled));
    assert_eq!(value, Value::String("<removed>".to_owned()));
}

/// Text with no automaton for its needles is dropped whole: none of it is
/// returned, the credential included.
#[test]
fn text_is_dropped_whole_when_no_automaton_exists() {
    let secrets = vec!["s3cret-value-1".to_owned()];
    let text = "before s3cret-value-1 after";
    let with_automaton = redact_untruncated(text, &secrets, &[]);
    assert!(
        with_automaton.starts_with("before ") && !with_automaton.contains("s3cret-value-1"),
        "premise: with an automaton the text is redacted, not dropped: {with_automaton:?}"
    );
    FAIL_MATCHER_BUILD.with(|fail| fail.set(true));
    let built = matcher(&["s3cret-value-1"]).is_some();
    let redacted = redact_untruncated(text, &secrets, &[]);
    FAIL_MATCHER_BUILD.with(|fail| fail.set(false));
    assert!(!built, "premise: the automaton build failed");
    assert_eq!(redacted, "");
}
