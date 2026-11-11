// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 receipt rows R6, R10, R11, R11b, R20, R33: what the receipt's
//! `answer` block says, line by line.

use serde_json::Value;

use super::access::Access;
use super::answer_fixture::{Dl, Fixture, SECRET};
use super::reader::{Line, Which};
use super::receipt::{parse_id, receipt};
use super::rows::{Check, row_id};

/// The receipt for the call carrying `trace`, with the fixture's secret.
pub(super) fn rcpt(fx: &Fixture, trace: &str) -> Value {
    rcpt_with(fx, trace, fx.secret.map(str::as_bytes))
}

pub(super) fn rcpt_with(fx: &Fixture, trace: &str, secret: Option<&[u8]>) -> Value {
    let lines = fx.every_line();
    let e = lines
        .iter()
        .find(|l| l["trace_id"] == trace && l.get("request_hash").is_some())
        .unwrap();
    let line = Line {
        log: Which::Invocation,
        entry: e.clone(),
        segment: 0,
        span: None,
    };
    let id = parse_id(&row_id(&line).unwrap()).unwrap();
    receipt(
        &fx.path,
        &id,
        &Access::All,
        &Check::new(secret, &fx.path, None),
    )
    .unwrap()
    .unwrap()
}

pub(super) fn line_of(receipt: &Value) -> String {
    receipt["answer"]["line"].as_str().unwrap().to_string()
}

#[test]
fn r10_receipt_says_the_effect_is_not_known() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::omitted());
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert!(line_of(&r).starts_with("effect not known: the record states none"));
}

#[test]
fn r11_receipt_for_an_unvouched_refusal_says_no_findings_are_recorded() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    let mut d = Dl::effect("refused");
    d.findings = None;
    fx.delivery("gw-t", &d);
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "refused");
    let line = line_of(&r);
    assert!(line.contains("did not vouch for this answer"), "{line}");
    assert!(!line.contains("did not produce"));
}

#[test]
fn r11b_receipt_for_an_echo_rewrite_makes_no_claim_about_the_producer() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    let mut d = Dl::effect("rewritten");
    d.findings = None;
    fx.delivery("gw-t", &d);
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "rewritten");
    let line = line_of(&r);
    assert!(line.starts_with("effect: rewritten (the gateway removed an injected value"));
    assert!(!line.contains("did not produce"));
}

#[test]
fn r6_receipt_lists_both_records_of_a_duplicate() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    fx.delivery("gw-t", &Dl::effect("refused"));
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer"]["records"].as_array().unwrap().len(), 2);
    assert!(line_of(&r).contains("more than one delivery record for this trace"));
}

#[test]
fn r20_receipt_caps_a_duplicate_list_at_two() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    for _ in 0..5 {
        fx.delivery("gw-t", &Dl::effect("delivered"));
    }
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer"]["records"].as_array().unwrap().len(), 2);
    assert_eq!(r["answer"]["more"], 3);
}

#[test]
fn r33_receipt_says_this_gateway_cannot_vouch_without_a_secret() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let r = rcpt_with(&fx, "gw-t", None);
    assert_eq!(r["answer_integrity"], "unverifiable");
    assert!(line_of(&r).contains(
        "this gateway cannot verify the delivery record's signature, so it cannot vouch"
    ));
}
